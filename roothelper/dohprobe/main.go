// Wonhee strictly bound encrypted DNS helper: a one-shot probe or an opt-in
// localhost-only DNS forwarder. The helper NEVER installs firewall rules.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type config struct {
	protocol      string
	interfaceName string
	endpointURL   string
	bootstrapIP   string
	hostname      string
	port          string
	path          string
}

func parseConfig(device, endpoint, bootstrap string) (config, error) {
	return parseConfigForProtocol("doh", device, endpoint, bootstrap)
}

func parseConfigForProtocol(protocol, device, endpoint, bootstrap string) (config, error) {
	var c config
	if protocol != "doh" && protocol != "doq" && protocol != "doh3" {
		return c, errors.New("protocol")
	}
	if !strings.HasPrefix(device, "wnm") || len(device) != 15 {
		return c, errors.New("interface")
	}
	for _, char := range device[3:] {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return c, errors.New("interface")
		}
	}
	if len(endpoint) > 2048 || len(endpoint) < 10 || strings.ContainsAny(endpoint, "\r\n") {
		return c, errors.New("endpoint")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Host == "" {
		return c, errors.New("endpoint")
	}
	if protocol == "doq" && (u.Scheme != "quic" || u.EscapedPath() != "") {
		return c, errors.New("endpoint")
	}
	if protocol != "doq" && u.Scheme != "https" {
		return c, errors.New("endpoint")
	}
	host := strings.ToLower(u.Hostname())
	if !validHost(host) {
		return c, errors.New("endpoint")
	}
	if protocol != "doq" && (u.EscapedPath() == "" || len(u.EscapedPath()) > 1024 || u.EscapedPath()[0] != '/') {
		return c, errors.New("endpoint")
	}
	port := u.Port()
	if port == "" {
		if protocol == "doq" { port = "853" } else { port = "443" }
	}
	value, err := strconv.Atoi(port)
	if err != nil || value < 1 || value > 65535 {
		return c, errors.New("port")
	}
	if ip := net.ParseIP(bootstrap); ip == nil || strings.Contains(bootstrap, "%") {
		return c, errors.New("bootstrap")
	}
	c = config{protocol, device, u.String(), bootstrap, host, port, u.EscapedPath()}
	return c, nil
}

func validHost(host string) bool {
	if len(host) > 253 || !strings.Contains(host, ".") {
		return false
	}
	for _, part := range strings.Split(host, ".") {
		if len(part) < 1 || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
			return false
		}
		for _, char := range part {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return false
			}
		}
	}
	return true
}

func dnsQuestion() ([]byte, error) {
	id := make([]byte, 2)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	query := []byte{id[0], id[1], 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, part := range strings.Split("example.com", ".") {
		query = append(query, byte(len(part)))
		query = append(query, part...)
	}
	return append(query, 0, 0, 1, 0, 1), nil
}

func skipName(data []byte, offset int) (int, error) {
	for labels := 0; labels < 128; labels++ {
		if offset >= len(data) {
			return 0, errors.New("truncated name")
		}
		length := int(data[offset])
		if length&0xc0 == 0xc0 {
			if offset+1 >= len(data) || int(data[offset]&0x3f)<<8|int(data[offset+1]) >= offset {
				return 0, errors.New("invalid name pointer")
			}
			return offset + 2, nil
		}
		if length&0xc0 != 0 || offset+1+length > len(data) {
			return 0, errors.New("invalid label")
		}
		offset++
		if length == 0 {
			return offset, nil
		}
		offset += length
	}
	return 0, errors.New("name too long")
}

func verifiedAAnswers(query, reply []byte) (int, error) {
	if len(reply) < len(query)+12 || len(reply) > 4096 || !bytes.Equal(reply[:2], query[:2]) ||
		reply[2]&0x80 == 0 || reply[2]&0x7a != 0 || reply[3]&0x0f != 0 ||
		binary.BigEndian.Uint16(reply[4:6]) != 1 || !bytes.Equal(reply[12:len(query)], query[12:]) {
		return 0, errors.New("DNS response mismatch")
	}
	answers := int(binary.BigEndian.Uint16(reply[6:8]))
	if answers < 1 || answers > 64 {
		return 0, errors.New("DNS answer count")
	}
	position := len(query)
	valid := 0
	for i := 0; i < answers; i++ {
		var err error
		position, err = skipName(reply, position)
		if err != nil || position+10 > len(reply) {
			return 0, errors.New("DNS record truncated")
		}
		rrType := binary.BigEndian.Uint16(reply[position : position+2])
		rrClass := binary.BigEndian.Uint16(reply[position+2 : position+4])
		length := int(binary.BigEndian.Uint16(reply[position+8 : position+10]))
		position += 10
		if position+length > len(reply) {
			return 0, errors.New("DNS answer truncated")
		}
		if rrType == 1 && rrClass == 1 && length == 4 {
			valid++
		}
		position += length
	}
	if valid == 0 {
		return 0, errors.New("no A answer")
	}
	return valid, nil
}

func run(c config) (int, string) {
	if _, err := net.InterfaceByName(c.interfaceName); err != nil {
		return 0, "INTERFACE_UNAVAILABLE"
	}
	if c.protocol == "doq" || c.protocol == "doh3" {
		return runQuicProbe(c)
	}
	question, err := dnsQuestion()
	if err != nil {
		return 0, "QUERY_UNAVAILABLE"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	var bindFailure bool
	dialer := &net.Dialer{Timeout: 6 * time.Second, Control: func(network, address string, connection syscall.RawConn) error {
		var bindErr error
		err := connection.Control(func(fd uintptr) {
			bindErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET,
				syscall.SO_BINDTODEVICE, c.interfaceName)
		})
		if err != nil || bindErr != nil {
			bindFailure = true
			if err != nil {
				return err
			}
			return bindErr
		}
		return nil
	}}
	upstream := net.JoinHostPort(c.bootstrapIP, c.port)
	transport := &http.Transport{
		Proxy: nil, // Ignore environment proxy settings; NEVER send to a proxy.
		DisableCompression: true,
		DisableKeepAlives: true,
		ForceAttemptHTTP2: false,
		TLSClientConfig: &tls.Config{ServerName: c.hostname, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != net.JoinHostPort(c.hostname, c.port) {
				return nil, errors.New("unexpected destination")
			}
			family := "tcp4"
			if strings.Contains(c.bootstrapIP, ":") {
				family = "tcp6"
			}
			return dialer.DialContext(ctx, family, upstream)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 12 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpointURL, bytes.NewReader(question))
	if err != nil {
		return 0, "REQUEST_UNAVAILABLE"
	}
	request.Header.Set("Content-Type", "application/dns-message")
	request.Header.Set("Accept", "application/dns-message")
	request.Header.Set("Cache-Control", "no-store")
	response, err := client.Do(request)
	if err != nil {
		if bindFailure {
			return 0, "BIND_FAILED"
		}
		return 0, "TLS_OR_CONNECT_FAILED"
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return 0, "HTTP_NOT_200"
	}
	if strings.ToLower(strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0])) != "application/dns-message" {
		return 0, "WRONG_CONTENT_TYPE"
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || len(body) > 4096 {
		return 0, "DNS_REPLY_TOO_LARGE"
	}
	answers, err := verifiedAAnswers(question, body)
	if err != nil {
		return 0, "DNS_REPLY_INVALID"
	}
	return answers, "OK"
}

func main() {
	serve := flag.Bool("serve", false, "run localhost-only encrypted DNS forwarding")
	protocol := flag.String("protocol", "doh", "one of doh, doq, doh3")
	device := flag.String("interface", "", "exact kernel WireGuard interface")
	endpoint := flag.String("url", "", "DoH HTTPS URL")
	bootstrap := flag.String("bootstrap", "", "numeric upstream IP")
	trackerFile := flag.String("tracker-file", "", "optional local Batch E tracker policy")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Println("REFUSED CONFIG")
		os.Exit(2)
	}
	c, err := parseConfigForProtocol(*protocol, *device, *endpoint, *bootstrap)
	if err != nil {
		fmt.Println("REFUSED CONFIG")
		os.Exit(2)
	}
	if *serve {
		filter, filterErr := loadTrackerPolicy(*trackerFile)
		if filterErr != nil {
			fmt.Println("REFUSED TRACKER_POLICY")
			os.Exit(1)
		}
		if err := serveDNS(c,filter); err != nil {
			fmt.Println("REFUSED RELAY_UNAVAILABLE")
			os.Exit(1)
		}
		return
	}
	if *trackerFile != "" {fmt.Println("REFUSED CONFIG");os.Exit(2)}
	answers, status := run(c)
	if status != "OK" {
		fmt.Println("REFUSED " + status)
		os.Exit(1)
	}
	fmt.Printf("VERIFIED A_COUNT=%d\n", answers)
}
