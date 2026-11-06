package main

import (
	"encoding/binary"
	"testing"
)

func TestStrictConfigurations(t *testing.T) {
	good := []struct{ endpoint, ip string }{
		{"https://cloudflare-dns.com/dns-query", "1.1.1.1"},
		{"https://custom.example:8443/query", "2606:4700:4700::1111"},
	}
	for _, item := range good {
		c, err := parseConfig("wnm68fe81200daa", item.endpoint, item.ip)
		if err != nil || c.interfaceName != "wnm68fe81200daa" || c.bootstrapIP != item.ip {
			t.Fatalf("valid endpoint refused: %v", err)
		}
	}
	bad := []struct{ endpoint, ip string }{
		{"http://cloudflare-dns.com/dns-query", "1.1.1.1"},
		{"https://name:password@cloudflare-dns.com/dns-query", "1.1.1.1"},
		{"https://cloudflare-dns.com/dns-query?token=secret", "1.1.1.1"},
		{"https://cloudflare-dns.com/dns-query#section", "1.1.1.1"},
		{"https://cloudflare-dns.com", "1.1.1.1"},
		{"https://cloudflare-dns.com/dns-query", "dns.google"},
		{"https://cloudflare-dns.com/dns-query", "fe80::1%eth0"},
		{"https://cloudflare-dns.com/dns-query", "256.1.1.1"},
	}
	for _, item := range bad {
		if _, err := parseConfig("wnm68fe81200daa", item.endpoint, item.ip); err == nil {
			t.Fatalf("unsafe DoH accepted: %s", item.endpoint)
		}
	}
	if _, err := parseConfig("wlan0", good[0].endpoint, good[0].ip); err == nil {
		t.Fatal("unknown interface accepted")
	}
	if _, err := parseConfig("wnm68fe81200daa;reboot", good[0].endpoint, good[0].ip); err == nil {
		t.Fatal("malicious interface accepted")
	}
}

func TestWireformatVerification(t *testing.T) {
	query, err := dnsQuestion()
	if err != nil {
		t.Fatal(err)
	}
	answer := []byte{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1}
	reply := append(append([]byte{}, query...), answer...)
	reply[2] = 0x81
	reply[3] = 0x80
	binary.BigEndian.PutUint16(reply[6:8], 1)
	if count, err := verifiedAAnswers(query, reply); err != nil || count != 1 {
		t.Fatalf("valid DoH reply refused: count=%d err=%v", count, err)
	}
	checks := []func([]byte){
		func(b []byte) { b[0] ^= 1 },
		func(b []byte) { b[3] = 0x83 },
		func(b []byte) { b[12] ^= 1 },
		func(b []byte) { b[len(query)+1] = 0x7f },
		func(b []byte) { b[len(query)+3] = 28 },
	}
	for _, mutate := range checks {
		bad := append([]byte{}, reply...)
		mutate(bad)
		if _, err := verifiedAAnswers(query, bad); err == nil {
			t.Fatal("bad DNS response was accepted")
		}
	}
	if _, err := verifiedAAnswers(query, reply[:len(query)+9]); err == nil {
		t.Fatal("truncated answer accepted")
	}
}
