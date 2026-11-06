package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// questionEnd refuses compression pointers and malformed input rather than
// forwarding arbitrary UDP payloads through a privileged tunnel.
func questionEnd(q []byte) (int, error) {
	if len(q) < 17 || len(q) > 4096 || q[2]&0xf8 != 0 ||
		binary.BigEndian.Uint16(q[4:6]) != 1 || q[3]&0x0f != 0 {
		return 0, errors.New("invalid query header")
	}
	offset := 12
	for labels := 0; labels < 128; labels++ {
		if offset >= len(q) { return 0, errors.New("short name") }
		length := int(q[offset])
		if length&0xc0 != 0 || length > 63 || offset+1+length > len(q) {
			return 0, errors.New("invalid name")
		}
		offset++
		if length == 0 {
			if offset+4 > len(q) { return 0, errors.New("short question") }
			return offset+4, nil
		}
		offset += length
	}
	return 0, errors.New("too many labels")
}

func verifyWireReply(q, reply []byte) error {
	end, err := questionEnd(q)
	if err != nil || len(reply) < end || len(reply) > 4096 ||
		!bytes.Equal(reply[:2], q[:2]) || reply[2]&0x80 == 0 ||
		reply[2]&0x78 != q[2]&0x78 || reply[2]&0x02 != 0 ||
		binary.BigEndian.Uint16(reply[4:6]) != 1 ||
		!bytes.Equal(reply[12:end], q[12:end]) {
		return errors.New("unverified DNS response")
	}
	return nil
}

// forwardWire never uses system DNS, redirects, proxy environment variables or
// an alternate interface. A failure returns no response to the local client.
func forwardWire(ctx context.Context, c config, query []byte) ([]byte, error) {
	if _, err := questionEnd(query); err != nil { return nil, err }
	if _, err := net.InterfaceByName(c.interfaceName); err != nil { return nil, err }
	upstreamQuery := bytes.Clone(query)
	if c.protocol == "doq" { upstreamQuery[0], upstreamQuery[1] = 0, 0 }
	var reply []byte
	var err error
	switch c.protocol {
	case "doh": reply, err = forwardDoH(ctx, c, upstreamQuery)
	case "doq": reply, err = forwardDoQ(ctx, c, upstreamQuery)
	case "doh3": reply, err = forwardDoH3(ctx, c, upstreamQuery)
	default: return nil, errors.New("unsupported protocol")
	}
	if err != nil { return nil, err }
	if err = verifyWireReply(upstreamQuery, reply); err != nil { return nil, err }
	if c.protocol == "doq" { copy(reply[:2], query[:2]) }
	return reply, nil
}

func doHResponse(ctx context.Context, c config, query []byte, transport http.RoundTripper) ([]byte, error) {
	client := &http.Client{Transport: transport, Timeout: 9*time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpointURL, bytes.NewReader(query))
	if err != nil { return nil, err }
	request.Header.Set("Content-Type", "application/dns-message")
	request.Header.Set("Accept", "application/dns-message")
	request.Header.Set("Cache-Control", "no-store")
	response, err := client.Do(request)
	if err != nil { return nil, err }
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK ||
		strings.ToLower(strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0])) != "application/dns-message" {
		return nil, errors.New("upstream HTTP response invalid")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || len(body) > 4096 { return nil, errors.New("upstream body invalid") }
	return body, nil
}

func forwardDoH(ctx context.Context, c config, query []byte) ([]byte, error) {
	dialer := &net.Dialer{Timeout: 6*time.Second, Control: func(network, address string, fd syscall.RawConn) error {
		var bindErr error
		err := fd.Control(func(n uintptr) { bindErr = syscall.SetsockoptString(int(n), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, c.interfaceName) })
		if err != nil { return err }; return bindErr
	}}
	family := "tcp4"
	if strings.Contains(c.bootstrapIP, ":") { family = "tcp6" }
	transport := &http.Transport{Proxy:nil, DisableCompression:true, DisableKeepAlives:true,
		TLSClientConfig:&tls.Config{ServerName:c.hostname, MinVersion:tls.VersionTLS12},
		DialContext:func(ctx context.Context, network, address string) (net.Conn,error) {
			if address != net.JoinHostPort(c.hostname, c.port) { return nil, errors.New("unexpected endpoint") }
			return dialer.DialContext(ctx, family, net.JoinHostPort(c.bootstrapIP, c.port))
		}}
	defer transport.CloseIdleConnections()
	return doHResponse(ctx,c,query,transport)
}

func forwardDoQ(ctx context.Context, c config, query []byte) ([]byte,error) {
	socket, err := bindUDP(ctx,c)
	if err != nil { return nil, err }
	defer socket.Close()
	conn, err := quic.Dial(ctx,socket,quicRemote(c),&tls.Config{ServerName:c.hostname,
		MinVersion:tls.VersionTLS13,NextProtos:[]string{"doq"}},&quic.Config{HandshakeIdleTimeout:5*time.Second,MaxIdleTimeout:8*time.Second})
	if err != nil { return nil, err }
	defer conn.CloseWithError(0,"")
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil { return nil, err }
	frame := make([]byte,len(query)+2)
	binary.BigEndian.PutUint16(frame[:2],uint16(len(query)))
	copy(frame[2:],query)
	n, err := stream.Write(frame)
	if err != nil || n != len(frame) { return nil, errors.New("short DoQ write") }
	if err = stream.Close(); err != nil { return nil, err }
	var prefix [2]byte
	if _,err = io.ReadFull(stream,prefix[:]); err != nil { return nil,err }
	length := int(binary.BigEndian.Uint16(prefix[:]))
	if length < 17 || length > 4096 { return nil, errors.New("invalid DoQ frame") }
	reply := make([]byte,length)
	if _,err = io.ReadFull(stream,reply); err != nil { return nil,err }
	var extra [1]byte
	if n,err := stream.Read(extra[:]); n!=0 || err!=io.EOF { return nil, errors.New("extra DoQ payload") }
	return reply,nil
}

func forwardDoH3(ctx context.Context, c config, query []byte) ([]byte,error) {
	var socket net.PacketConn
	transport := &http3.Transport{TLSClientConfig:&tls.Config{ServerName:c.hostname,MinVersion:tls.VersionTLS13,
		NextProtos:[]string{http3.NextProtoH3}},DisableCompression:true,
		Dial:func(ctx context.Context, address string, tlsConf *tls.Config, quicConf *quic.Config)(quic.EarlyConnection,error){
			if address!=net.JoinHostPort(c.hostname,c.port) { return nil,errors.New("unexpected endpoint") }
			var err error
			socket,err=bindUDP(ctx,c)
			if err!=nil{return nil,err}
			conn,err:=quic.DialEarly(ctx,socket,quicRemote(c),tlsConf,quicConf)
			if err!=nil{socket.Close()}
			return conn,err
		}}
	defer func(){transport.Close();if socket!=nil{socket.Close()}}()
	return doHResponse(ctx,c,query,transport)
}
