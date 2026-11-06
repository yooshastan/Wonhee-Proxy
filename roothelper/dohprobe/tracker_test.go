package main

import (
	"bytes"
	"testing"
)

func TestTrackerLocalFilter(t *testing.T) {
	p,err:=parseTrackerPolicy("block app-measurement.com\nblock telemetry.example.net\nallow safe.telemetry.example.net\n")
	if err!=nil{t.Fatal(err)}
	for _,name:=range []string{"app-measurement.com","x.app-measurement.com","other.telemetry.example.net"}{
		if !p.shouldBlock(name){t.Fatalf("did not block %s",name)}
	}
	for _,name:=range []string{"notapp-measurement.com","safe.telemetry.example.net","x.safe.telemetry.example.net","example.com"}{
		if p.shouldBlock(name){t.Fatalf("blocked allowed %s",name)}
	}
	for _,raw:=range []string{"block *.example.com\n", "allow google.com\n", "block 10.0.0.1\n",
		"block https://example.com\n", "block company.local domain\n"}{
		if _,err:=parseTrackerPolicy(raw);err==nil{t.Fatalf("accepted invalid policy %q",raw)}
	}
	q,err:=dnsQuestion()
	if err!=nil{t.Fatal(err)}
	// Rewrite the test name to a blocked hostname using a fixed deterministic
	// label encoding, preserving the original 12-byte header and question type.
	q=append(append([]byte{},q[:12]...), []byte{15,'a','p','p','-','m','e','a','s','u','r','e','m','e','n','t',3,'c','o','m',0,0,1,0,1}...)
	reply,blocked:=trackerReply(q,p)
	if !blocked||len(reply)!=len(q)||reply[3]&15!=3||reply[2]&0x80==0{t.Fatal("no local NXDOMAIN")}
	if !bytes.Equal(reply[:2],q[:2])||reply[6]!=0||reply[7]!=0{t.Fatal("unexpected DNS reply")}
	if _,blocked:=trackerReply(q,nil);blocked{t.Fatal("off mode blocked")}
}
