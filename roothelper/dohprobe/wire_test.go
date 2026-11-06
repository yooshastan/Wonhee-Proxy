package main

import (
	"encoding/binary"
	"testing"
)

func TestStrictForwarderWire(t *testing.T) {
	query,err:=dnsQuestion()
	if err!=nil{t.Fatal(err)}
	if _,err=questionEnd(query);err!=nil{t.Fatal(err)}
	answer:=[]byte{0xc0,0x0c,0,1,0,1,0,0,0,60,0,4,192,0,2,1}
	reply:=append(append([]byte{},query...),answer...)
	reply[2]=0x81
	reply[3]=0x80
	binary.BigEndian.PutUint16(reply[6:8],1)
	if err:=verifyWireReply(query,reply);err!=nil{t.Fatal(err)}
	for _,change:=range []func([]byte){
		func(q []byte){q[0]^=1},
		func(q []byte){q[2]=0},
		func(q []byte){q[12]=0xc0},
		func(q []byte){q[17]^=1},
	} {
		bad:=append([]byte{},reply...)
		change(bad)
		if verifyWireReply(query,bad)==nil{t.Fatal("accepted mismatched DNS response")}
	}
	bad:=append([]byte{},query...)
	bad[12]=0xc0
	if _,err:=questionEnd(bad);err==nil{t.Fatal("accepted compressed query name")}
	bad=append([]byte{},query...)
	bad[4]=0
	bad[5]=2
	if _,err:=questionEnd(bad);err==nil{t.Fatal("accepted multiple questions")}
}
