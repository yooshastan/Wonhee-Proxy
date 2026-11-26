package dualwg

import (
 "encoding/binary"
 "io"
 "net"
 "net/netip"
 "sync"
 "sync/atomic"
 "time"

 "golang.zx2c4.com/wireguard/tun"
 "golang.zx2c4.com/wireguard/tun/netstack"
)

// Private in-memory TCP endpoint. No OS listener, no upstream network socket,
// no forwarding route: only authorized IPv4 TCP packets to virtual DNS:53.
type DnsTCPStack struct{
 device tun.Device
 listener net.Listener
 done chan struct{}
 once sync.Once
 packets chan []byte
 queries chan []byte
 slots chan struct{}
 mu sync.Mutex
 feedMu sync.Mutex
 clients map[net.Conn]struct{}
 pending map[uint64]chan []byte
 serial atomic.Uint64
 wg sync.WaitGroup
}
func NewDnsTCPStack()(*DnsTCPStack,error){
 device,network,err:=netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("1.1.1.1")},nil,1280)
 if err!=nil{return nil,err}
 listener,err:=network.ListenTCP(&net.TCPAddr{IP:net.IP{1,1,1,1},Port:53})
 if err!=nil{device.Close();return nil,err}
 s:=&DnsTCPStack{device:device,listener:listener,done:make(chan struct{}),packets:make(chan []byte,128),queries:make(chan []byte,32),slots:make(chan struct{},16),clients:map[net.Conn]struct{}{},pending:map[uint64]chan []byte{}}
 s.wg.Add(2);go s.readPackets();go s.accept();return s,nil
}
func tcpDNSPacket(p []byte,reply bool)bool{
 if len(p)<40||len(p)>1280||p[0]!=0x45||p[9]!=6||int(binary.BigEndian.Uint16(p[2:]))!=len(p)||binary.BigEndian.Uint16(p[6:])&0xbfff!=0{return false}
 header:=int(p[32]>>4)*4
 if header<20||20+header>len(p){return false}
 src,dst:=binary.BigEndian.Uint32(p[12:]),binary.BigEndian.Uint32(p[16:])
 sp,dp:=binary.BigEndian.Uint16(p[20:]),binary.BigEndian.Uint16(p[22:])
 if reply{src,dst=dst,src;sp,dp=dp,sp}
 return src==0x0afd0001&&dst==0x01010101&&sp!=0&&dp==53
}
func (s *DnsTCPStack) Feed(p []byte)bool{
 if !tcpDNSPacket(p,false){return false}
 s.feedMu.Lock();defer s.feedMu.Unlock()
 select{case <-s.done:return false;default:}
 n,err:=s.device.Write([][]byte{p},0);return err==nil&&n==1
}
func (s *DnsTCPStack) readPackets(){
 defer s.wg.Done()
 b:=make([]byte,1280);sizes:=make([]int,1)
 for{
  n,err:=s.device.Read([][]byte{b},sizes,0)
  if err!=nil{return}
  if n!=1||sizes[0]<40||sizes[0]>len(b)||!tcpDNSPacket(b[:sizes[0]],true){continue}
  packet:=append([]byte(nil),b[:sizes[0]]...)
  // Keep draining the netstack until device.Close unblocks Read.
  // A stopped reader could deadlock a concurrent netstack close notification.
  select{case <-s.done:continue;default:}
  select{case s.packets<-packet:default:} // bounded; TCP retransmits
 }
}
func (s *DnsTCPStack) accept(){
 defer s.wg.Done()
 for{
  c,err:=s.listener.Accept();if err!=nil{return}
  select{case <-s.done:c.Close();return;case s.slots<-struct{}{}:default:c.Close();continue}
  s.mu.Lock()
  select{case <-s.done:s.mu.Unlock();c.Close();<-s.slots;return;default:}
  s.clients[c]=struct{}{};s.mu.Unlock()
  s.wg.Add(1);go s.serve(c)
 }
}
func (s *DnsTCPStack) serve(c net.Conn){
 defer s.wg.Done()
 defer func(){c.Close();s.mu.Lock();delete(s.clients,c);s.mu.Unlock();<-s.slots}()
 for i:=0;i<16;i++{
  _ = c.SetDeadline(time.Now().Add(20*time.Second))
  var prefix [2]byte
  if _,err:=io.ReadFull(c,prefix[:]);err!=nil{return}
  size:=int(binary.BigEndian.Uint16(prefix[:]))
  if size<17||size>MaxDnsQuery{return}
  q:=make([]byte,size);if _,err:=io.ReadFull(c,q);err!=nil{return}
  a:=s.resolve(q);if len(a)<12||len(a)>MaxDnsReply{return}
  frame:=make([]byte,2+len(a));binary.BigEndian.PutUint16(frame,uint16(len(a)));copy(frame[2:],a)
  if n,err:=c.Write(frame);err!=nil||n!=len(frame){return}
 }
}
func (s *DnsTCPStack) resolve(q []byte)[]byte{
 token:=s.serial.Add(1);ch:=make(chan []byte,1)
 s.mu.Lock();s.pending[token]=ch;s.mu.Unlock()
 defer func(){s.mu.Lock();delete(s.pending,token);s.mu.Unlock()}()
 msg:=make([]byte,8+len(q));binary.BigEndian.PutUint64(msg,token);copy(msg[8:],q)
 select{case <-s.done:return nil;case s.queries<-msg:default:return nil}
 timer:=time.NewTimer(15*time.Second);defer timer.Stop()
 select{case <-s.done:return nil;case <-timer.C:return nil;case a:=<-ch:return a}
}
func (s *DnsTCPStack) PollPacket()[]byte{select{case b:=<-s.packets:return b;default:return nil}}
func (s *DnsTCPStack) PollQuery()[]byte{select{case b:=<-s.queries:return b;default:return nil}}
func (s *DnsTCPStack) Answer(token uint64,a []byte)bool{
 s.mu.Lock();defer s.mu.Unlock()
 ch:=s.pending[token];if ch==nil||len(a)<12||len(a)>MaxDnsReply{return false}
 select{case ch<-a:return true;default:return false}
}
func (s *DnsTCPStack) Close(){
 s.once.Do(func(){
  close(s.done);s.listener.Close()
  s.mu.Lock();for c:=range s.clients{c.Close()};s.mu.Unlock()
  s.feedMu.Lock();s.device.Close();s.feedMu.Unlock();s.wg.Wait()
 })
}
