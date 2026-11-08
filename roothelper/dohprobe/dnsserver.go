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

func serveDNS(c config, filter *trackerPolicy, stats *dnsCounters) error {
	if _,err := net.InterfaceByName(c.interfaceName); err!=nil {return err}
	udp,err:=net.ListenPacket("udp4","127.0.0.1:"+localDnsPort)
	if err!=nil{return err}
	defer udp.Close()
	tcp,err:=net.Listen("tcp4","127.0.0.1:"+localDnsPort)
	if err!=nil{return err}
	defer tcp.Close()
	if err := stats.startSnapshots(); err != nil { return err }
	go serveTcpDNS(tcp,c,filter,stats)
	// Bounded parallel DNS forwarding; overload refuses instead of leaking.
	slots:=make(chan struct{},8)
	for {
		buf:=make([]byte,4097)
		n,remote,err:=udp.ReadFrom(buf)
		if err!=nil{return err}
		if n==0 || n>4096{if stats!=nil{stats.failed.Add(1)};continue}
		if stats!=nil{stats.received.Add(1)}
		query:=buf[:n]
		select {
		case slots<-struct{}{}:
			go func(){
				defer func(){<-slots}()
				if answer,blocked:=trackerReply(query,filter);blocked {
					if _,err:=udp.WriteTo(answer,remote);err==nil {if stats!=nil{stats.blocked.Add(1)}} else if stats!=nil{stats.failed.Add(1)}
					return
				}
				ctx,cancel:=context.WithTimeout(context.Background(),9*time.Second)
				defer cancel()
				reply,err:=forwardWire(ctx,c,query)
				if err!=nil {if stats!=nil{stats.failed.Add(1)};return}
				if _,err=udp.WriteTo(reply,remote);err!=nil {if stats!=nil{stats.failed.Add(1)}} else if stats!=nil{stats.forwarded.Add(1)}
			}()
		default: // reject overload without any alternate transport
			if stats!=nil{stats.failed.Add(1)}
		}
	}
}

func serveTcpDNS(listener net.Listener,c config,filter *trackerPolicy, stats *dnsCounters){
	slots:=make(chan struct{},8)
	for {
		conn,err:=listener.Accept()
		if err!=nil{return}
		select {
		case slots<-struct{}{}:
			go func(){defer func(){<-slots;conn.Close()}();handleTcpDNS(conn,c,filter,stats)}()
		default:if stats!=nil{stats.failed.Add(1)};conn.Close()
		}
	}
}

func handleTcpDNS(conn net.Conn,c config,filter *trackerPolicy, stats *dnsCounters){
	conn.SetDeadline(time.Now().Add(9*time.Second))
	var prefix [2]byte
	if _,err:=io.ReadFull(conn,prefix[:]);err!=nil{if stats!=nil{stats.failed.Add(1)};return}
	length:=int(binary.BigEndian.Uint16(prefix[:]))
	if length<17||length>4096{if stats!=nil{stats.failed.Add(1)};return}
	query:=make([]byte,length)
	if _,err:=io.ReadFull(conn,query);err!=nil{if stats!=nil{stats.failed.Add(1)};return}
	if stats!=nil{stats.received.Add(1)}
	ctx,cancel:=context.WithTimeout(context.Background(),8*time.Second)
	defer cancel()
	reply,blocked:=trackerReply(query,filter)
	if !blocked {
		var err error
		reply,err=forwardWire(ctx,c,query)
		if err!=nil{if stats!=nil{stats.failed.Add(1)};return}
	}
	if len(reply)>65535{if stats!=nil{stats.failed.Add(1)};return}
	binary.BigEndian.PutUint16(prefix[:],uint16(len(reply)))
	if n,err:=conn.Write(prefix[:]);err!=nil||n!=2{if stats!=nil{stats.failed.Add(1)};return}
	if n,err:=conn.Write(reply);err!=nil||n!=len(reply){if stats!=nil{stats.failed.Add(1)};return}
	if stats!=nil {if blocked {stats.blocked.Add(1)} else {stats.forwarded.Add(1)}}
}
