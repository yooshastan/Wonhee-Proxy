package main

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func testConfig() bridgeConfig {
	return bridgeConfig{
		interfaceName: "wnma292ddb4b6da",
		upstreamIP:    netip.MustParseAddr("10.0.0.169"),
		upstreamPort:  4533,
		token:         []byte("0123456789abcdef0123456789abcdef"),
	}
}

func TestOnlyApprovedPrivateAddresses(t *testing.T) {
	for _, address := range []string{"10.0.0.169", "172.20.0.1", "192.168.50.1", "100.90.3.7", "fd00::4"} {
		if !privateAddress(netip.MustParseAddr(address)) {
			t.Fatalf("should allow private numeric destination %s", address)
		}
	}
	for _, address := range []string{"127.0.0.1", "169.254.1.1", "8.8.8.8", "172.32.0.1", "::1", "2001:db8::1", "::ffff:10.0.0.169"} {
		if privateAddress(netip.MustParseAddr(address)) {
			t.Fatalf("must refuse %s", address)
		}
	}
}

func TestConfigRejectsUnexpectedInterfaces(t *testing.T) {
	for _, device := range []string{"wlan0", "rmnet16", "wnm000000000000;sh", "wg0", "wnm123", "wnma292ddb4b6dg"} {
		c := testConfig()
		c.interfaceName = device
		if err := validateConfig(c); err == nil {
			t.Fatalf("must refuse interface %q", device)
		}
	}
}

func testHandler(t *testing.T, server *httptest.Server) http.Handler {
	t.Helper()
	calls := func(_ context.Context, _, _ string) (net.Conn, error) {
		return net.Dial("tcp", server.Listener.Addr().String())
	}
	handler, err := bridgeHandler(testConfig(), calls)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func bridgeRequest(method, path string, authorized bool) *http.Request {
	// Incoming HTTP servers receive origin-form request targets, not absolute
	// URLs. Test the same shape the real loopback listener will see.
	req := httptest.NewRequest(method, path, nil)
	if authorized {
		req.Header.Set(tokenHeader, hex.EncodeToString(testConfig().token))
	}
	return req
}

func TestTokenRequiredAndRestPathRestricted(t *testing.T) {
	var forwarded atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()
	handler := testHandler(t, server)
	for _, tc := range []struct {
		method, path string
		authorized   bool
		status       int
	}{
		{"GET", "/rest/ping.view?u=test", false, 403},
		{"GET", "/admin", true, 400},
		{"GET", "/rest/../admin", true, 400},
		{"POST", "/rest/ping.view", true, 405},
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, bridgeRequest(tc.method, tc.path, tc.authorized))
		if response.Code != tc.status {
			t.Fatalf("%s %s expected %d, got %d", tc.method, tc.path, tc.status, response.Code)
		}
	}
	if forwarded.Load() != 0 {
		t.Fatal("rejected requests must not contact Navidrome")
	}
}

func TestAuthorizedRequestForwardsRangeButNotBridgeToken(t *testing.T) {
	var receivedPath, receivedToken, receivedRange string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.RequestURI()
		receivedToken = r.Header.Get(tokenHeader)
		receivedRange = r.Header.Get("Range")
		w.Header().Set("Content-Type", "audio/flac")
		w.Header().Set("Content-Range", "bytes 0-3/100")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = io.WriteString(w, "fLaC")
	}))
	defer server.Close()
	handler := testHandler(t, server)
	req := bridgeRequest("GET", "/rest/stream.view?u=test&t=hashed&s=salted", true)
	req.Header.Set("Range", "bytes=0-3")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusPartialContent || rec.Body.String() != "fLaC" ||
		rec.Header().Get("Content-Range") != "bytes 0-3/100" {
		t.Fatalf("streaming response was not preserved: %d", rec.Code)
	}
	if receivedPath != "/rest/stream.view?u=test&t=hashed&s=salted" ||
		receivedRange != "bytes=0-3" || receivedToken != "" {
		t.Fatal("proxy forwarded an unexpected path/header or leaked its pairing token")
	}
}

func TestInterfaceFailureNeverRetriesAnotherNetwork(t *testing.T) {
	var attempts atomic.Int32
	handler, err := bridgeHandler(testConfig(), func(context.Context, string, string) (net.Conn, error) {
		attempts.Add(1)
		return nil, errors.New("Home WireGuard disappeared")
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, bridgeRequest("GET", "/rest/ping.view", true))
	if rec.Code != http.StatusBadGateway || attempts.Load() != 1 {
		t.Fatalf("expected one failed protected dial, got HTTP %d / %d attempts", rec.Code, attempts.Load())
	}
}

func TestRedirectDoesNotEscapeApprovedEndpoint(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Redirect(w, r, "https://example.org/", http.StatusFound)
	}))
	defer server.Close()
	handler := testHandler(t, server)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, bridgeRequest("GET", "/rest/ping.view", true))
	if rec.Code != http.StatusBadGateway || calls.Load() != 1 || rec.Header().Get("Location") != "" {
		t.Fatal("redirect must be refused without requesting its target")
	}
}

func TestPairingSecretMustBePrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bridge-token")
	if err := os.WriteFile(path, []byte(strings.Repeat("01", 32)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readToken(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readToken(path); err == nil {
		t.Fatal("world-readable pairing secret must be refused")
	}
}
