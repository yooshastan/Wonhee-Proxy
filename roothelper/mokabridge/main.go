// A deliberately restricted, root-owned loopback bridge for one approved
// private Navidrome endpoint. This is a transport component, not a general
// HTTP proxy. The Android-side pairing, consent and lifecycle are separate.
package main

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const tokenHeader = "X-Wonhee-Bridge-Token"

var interfacePattern = regexp.MustCompile(`^wnm[0-9a-f]{12}$`)

type bridgeConfig struct {
	interfaceName string
	upstreamIP    netip.Addr
	upstreamPort  uint16
	token         []byte
}

func privateAddress(address netip.Addr) bool {
	if !address.IsValid() || address.Is4In6() || address.Zone() != "" {
		return false
	}
	if address.Is6() {
		return address.As16()[0]&0xfe == 0xfc // ULA fc00::/7 only.
	}
	v := address.As4()
	return v[0] == 10 ||
		(v[0] == 172 && v[1] >= 16 && v[1] <= 31) ||
		(v[0] == 192 && v[1] == 168) ||
		(v[0] == 100 && v[1] >= 64 && v[1] <= 127)
}

func validateConfig(c bridgeConfig) error {
	if !interfacePattern.MatchString(c.interfaceName) {
		return errors.New("unverified interface name")
	}
	if !privateAddress(c.upstreamIP) || c.upstreamPort == 0 {
		return errors.New("unapproved private destination")
	}
	if len(c.token) != 32 {
		return errors.New("invalid pairing secret")
	}
	return nil
}

func readToken(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("private pairing secret is missing or accessible to other users")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("cannot read private pairing secret")
	}
	token, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(token) != 32 {
		return nil, errors.New("private pairing secret must be 32 random bytes")
	}
	return token, nil
}

// The privileged helper binds EVERY outgoing TCP socket to the Home WireGuard
// device. When that device disappears, a request fails instead of using Wi-Fi,
// cellular or the Internet VPN. No proxy environment variables are consulted.
func boundDialer(device string) func(context.Context, string, string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout: 8 * time.Second,
		Control: func(_, _ string, raw syscall.RawConn) error {
			var bindErr error
			if err := raw.Control(func(fd uintptr) {
				bindErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET,
					syscall.SO_BINDTODEVICE, device)
			}); err != nil {
				return err
			}
			return bindErr
		},
	}
	return dialer.DialContext
}

func bridgeHandler(c bridgeConfig,
	dial func(context.Context, string, string) (net.Conn, error)) (http.Handler, error) {
	if err := validateConfig(c); err != nil {
		return nil, err
	}
	upstream := net.JoinHostPort(c.upstreamIP.String(), strconv.Itoa(int(c.upstreamPort)))
	family := "tcp4"
	if c.upstreamIP.Is6() {
		family = "tcp6"
	}
	transport := &http.Transport{
		Proxy:             nil,
		DisableKeepAlives: true,
		DisableCompression: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != upstream {
				return nil, errors.New("destination mismatch")
			}
			return dial(ctx, family, upstream)
		},
	}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	semaphore := make(chan struct{}, 8)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Token failure and unapproved requests must never contact the upstream.
		received, err := hex.DecodeString(r.Header.Get(tokenHeader))
		if err != nil || subtle.ConstantTimeCompare(received, c.token) != 1 {
			http.Error(w, "not authorized", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method refused", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.IsAbs() || r.URL.Host != "" || !strings.HasPrefix(r.URL.Path, "/rest/") ||
			strings.Contains(r.URL.Path, "..") || len(r.URL.RequestURI()) > 4096 || r.ContentLength > 0 {
			http.Error(w, "destination refused", http.StatusBadRequest)
			return
		}
		select {
		case semaphore <- struct{}{}:
			defer func() { <-semaphore }()
		default:
			http.Error(w, "bridge busy", http.StatusServiceUnavailable)
			return
		}
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		target := "http://" + upstream + r.URL.RequestURI()
		out, err := http.NewRequestWithContext(ctx, r.Method, target, nil)
		if err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		for _, name := range []string{"Accept", "Range", "User-Agent"} {
			if value := r.Header.Get(name); value != "" {
				out.Header.Set(name, value)
			}
		}
		out.Header.Set("Cache-Control", "no-store")
		response, err := client.Do(out)
		if err != nil {
			http.Error(w, "protected Home connection unavailable", http.StatusBadGateway)
			return
		}
		defer response.Body.Close()
		if response.StatusCode >= 300 && response.StatusCode < 400 {
			http.Error(w, "upstream redirect refused", http.StatusBadGateway)
			return
		}
		for _, name := range []string{"Content-Type", "Content-Length", "Content-Range", "Accept-Ranges", "ETag"} {
			if value := response.Header.Get(name); value != "" {
				w.Header().Set(name, value)
			}
		}
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(response.StatusCode)
		if r.Method != http.MethodHead {
			_, _ = io.Copy(w, response.Body)
		}
	}), nil
}

func main() {
	device := flag.String("interface", "", "verified Home WireGuard interface")
	address := flag.String("upstream-ip", "", "approved numeric Navidrome address")
	port := flag.Int("upstream-port", 0, "approved Navidrome port")
	secretPath := flag.String("token-file", "", "private 0600 pairing secret file")
	flag.Parse()
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "REFUSED ROOT_REQUIRED")
		os.Exit(2)
	}
	ip, err := netip.ParseAddr(*address)
	if err != nil || *port < 1 || *port > 65535 {
		fmt.Fprintln(os.Stderr, "REFUSED DESTINATION")
		os.Exit(2)
	}
	token, err := readToken(*secretPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "REFUSED PAIRING")
		os.Exit(2)
	}
	c := bridgeConfig{*device, ip, uint16(*port), token}
	handler, err := bridgeHandler(c, boundDialer(c.interfaceName))
	if err != nil {
		fmt.Fprintln(os.Stderr, "REFUSED CONFIGURATION")
		os.Exit(2)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintln(os.Stderr, "REFUSED LISTENER")
		os.Exit(2)
	}
	defer listener.Close()
	// This is just the ephemeral loopback port; the secret never reaches logs.
	fmt.Printf("READY PORT=%d\n", listener.Addr().(*net.TCPAddr).Port)
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout: 15 * time.Second, MaxHeaderBytes: 8192}
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, "REFUSED SERVER")
		os.Exit(2)
	}
}
