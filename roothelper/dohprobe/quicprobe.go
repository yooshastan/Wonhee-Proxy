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
	"strconv"
	"strings"
	"syscall"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// bindUDP creates the only transport socket for a QUIC probe. Binding occurs
// BEFORE the socket can send traffic. A bind failure refuses the transaction;
// no alternate device, resolver, proxy or plaintext protocol is attempted.
func bindUDP(ctx context.Context, c config) (net.PacketConn, error) {
	family := "udp4"
	if strings.Contains(c.bootstrapIP, ":") { family = "udp6" }
	listener := net.ListenConfig{Control: func(network, address string, conn syscall.RawConn) error {
		var binding error
		err := conn.Control(func(fd uintptr) {
			binding = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET,
				syscall.SO_BINDTODEVICE, c.interfaceName)
		})
		if err != nil { return err }
		return binding
	}}
	return listener.ListenPacket(ctx, family, ":0")
}

func quicRemote(c config) *net.UDPAddr {
	port, _ := strconv.Atoi(c.port) // Already validated by parseConfigForProtocol.
	return &net.UDPAddr{IP: net.ParseIP(c.bootstrapIP), Port: port}
}

func runQuicProbe(c config) (int, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	question, err := dnsQuestion()
	if err != nil { return 0, "QUERY_UNAVAILABLE" }
	if c.protocol == "doq" {
		// RFC 9250 section 4.2.1: DoQ DNS Message ID MUST be 0.
		question[0], question[1] = 0, 0
		return runDoQ(ctx, c, question)
	}
	return runDoH3(ctx, c, question)
}

func runDoQ(ctx context.Context, c config, question []byte) (int, string) {
	socket, err := bindUDP(ctx, c)
	if err != nil { return 0, "BIND_FAILED" }
	defer socket.Close()
	connection, err := quic.Dial(ctx, socket, quicRemote(c),
		&tls.Config{ServerName: c.hostname, MinVersion: tls.VersionTLS13,
			NextProtos: []string{"doq"}},
		&quic.Config{HandshakeIdleTimeout: 5*time.Second, MaxIdleTimeout: 10*time.Second})
	if err != nil { return 0, "TLS_OR_CONNECT_FAILED" }
	defer connection.CloseWithError(0, "")
	stream, err := connection.OpenStreamSync(ctx)
	if err != nil { return 0, "STREAM_FAILED" }
	frame := make([]byte, len(question)+2)
	binary.BigEndian.PutUint16(frame[:2], uint16(len(question)))
	copy(frame[2:], question)
	n, err := stream.Write(frame)
	if err != nil || n != len(frame) { return 0, "STREAM_FAILED" }
	if err = stream.Close(); err != nil { return 0, "STREAM_FAILED" }
	var prefix [2]byte
	if _, err = io.ReadFull(stream, prefix[:]); err != nil { return 0, "DNS_REPLY_INVALID" }
	length := int(binary.BigEndian.Uint16(prefix[:]))
	if length < len(question)+12 || length > 4096 { return 0, "DNS_REPLY_INVALID" }
	reply := make([]byte, length)
	if _, err = io.ReadFull(stream, reply); err != nil { return 0, "DNS_REPLY_INVALID" }
	// A single query consumes one stream and one framed response. Extra data
	// is refused; the helper does not process unsolicited additional answers.
	var trailing [1]byte
	if n, err := stream.Read(trailing[:]); n != 0 || err != io.EOF {
		return 0, "DNS_REPLY_INVALID"
	}
	answers, err := verifiedAAnswers(question, reply)
	if err != nil { return 0, "DNS_REPLY_INVALID" }
	return answers, "OK"
}

func runDoH3(ctx context.Context, c config, question []byte) (int, string) {
	var socket net.PacketConn
	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{ServerName:c.hostname, MinVersion:tls.VersionTLS13,
			NextProtos: []string{http3.NextProtoH3}},
		DisableCompression: true,
		Dial: func(ctx context.Context, addr string, tlsConf *tls.Config,
			quicConf *quic.Config) (quic.EarlyConnection, error) {
			if addr != net.JoinHostPort(c.hostname, c.port) {
				return nil, errors.New("unexpected destination")
			}
			var err error
			socket, err = bindUDP(ctx, c)
			if err != nil { return nil, err }
			connection, err := quic.DialEarly(ctx, socket, quicRemote(c), tlsConf, quicConf)
			if err != nil { socket.Close() }
			return connection, err
		},
	}
	defer func() {
		transport.Close()
		if socket != nil { socket.Close() }
	}()
	client := &http.Client{Transport:transport, Timeout:12*time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpointURL,
		bytes.NewReader(question))
	if err != nil { return 0, "REQUEST_UNAVAILABLE" }
	request.Header.Set("Content-Type", "application/dns-message")
	request.Header.Set("Accept", "application/dns-message")
	request.Header.Set("Cache-Control", "no-store")
	response, err := client.Do(request)
	if err != nil { return 0, "TLS_OR_CONNECT_FAILED" }
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK { return 0, "HTTP_NOT_200" }
	if strings.ToLower(strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0]))
		!= "application/dns-message" { return 0, "WRONG_CONTENT_TYPE" }
	body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || len(body) > 4096 { return 0, "DNS_REPLY_TOO_LARGE" }
	answers, err := verifiedAAnswers(question, body)
	if err != nil { return 0, "DNS_REPLY_INVALID" }
	return answers, "OK"
}
