package main

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"time"
)

// A strictly local forwarder, never exposed to Wi-Fi, cellular, a VPN subnet or
// the Internet. Only root-owned firewall rules can redirect Android DNS here.
// The listener remains up if the selected tunnel fails, but returns NO DNS
// reply (fail closed). It does not try the host's resolver or another route.
const localDnsPort = "53535"

func serveDNS(c config) error {
	if _,err := net.InterfaceByName(c.interfaceName); err!=nil {return err}
	udp,err:=net.ListenPacket("udp4","127.0.0.1:"+localDnsPort)
	if err!=nil{return err}
	defer udp.Close()
	tcp,err:=net.Listen("tcp4","127.0.0.1:"+localDnsPort)
	if err!=nil{return err}
	defer tcp.Close()
	go serveTcpDNS(tcp,c)
	// Bounded parallel DNS forwarding; overload refuses instead of leaking.
	slots:=make(chan struct{},8)
	for {
		buf:=make([]byte,4097)
		n,remote,err:=udp.ReadFrom(buf)
		if err!=nil{return err}
		if n==0 || n>4096{continue}
		query:=buf[:n]
		select {
		case slots<-struct{}{}:
			go func(){
				defer func(){<-slots}()
				ctx,cancel:=context.WithTimeout(context.Background(),9*time.Second)
				defer cancel()
				reply,err:=forwardWire(ctx,c,query)
				if err==nil{udp.WriteTo(reply,remote)}
			}()
		default: // reject overload without any alternate transport
		}
	}
}

func serveTcpDNS(listener net.Listener,c config){
	slots:=make(chan struct{},8)
	for {
		conn,err:=listener.Accept()
		if err!=nil{return}
		select {
		case slots<-struct{}{}:
			go func(){defer func(){<-slots;conn.Close()}();handleTcpDNS(conn,c)}()
		default:conn.Close()
		}
	}
}

func handleTcpDNS(conn net.Conn,c config){
	conn.SetDeadline(time.Now().Add(9*time.Second))
	var prefix [2]byte
	if _,err:=io.ReadFull(conn,prefix[:]);err!=nil{return}
	length:=int(binary.BigEndian.Uint16(prefix[:]))
	if length<17||length>4096{return}
	query:=make([]byte,length)
	if _,err:=io.ReadFull(conn,query);err!=nil{return}
	ctx,cancel:=context.WithTimeout(context.Background(),8*time.Second)
	defer cancel()
	reply,err:=forwardWire(ctx,c,query)
	if err!=nil{return}
	if len(reply)>65535{return}
	binary.BigEndian.PutUint16(prefix[:],uint16(len(reply)))
	if n,err:=conn.Write(prefix[:]);err!=nil||n!=2{return}
	if n,err:=conn.Write(reply);err!=nil||n!=len(reply){return}
}
