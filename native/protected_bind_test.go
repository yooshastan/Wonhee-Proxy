package dualwg

import (
	"errors"
	"net"
	"reflect"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
)

type fakeProtectedBind struct {
	opened, single, badFD bool
	sends, closes, marks, opens int
}
func (f *fakeProtectedBind) Open(uint16) ([]conn.ReceiveFunc,uint16,error) {
	f.opens++
	f.opened=true
	fn := func([][]byte, []int, []conn.Endpoint)(int,error){return 0,net.ErrClosed}
	if f.single {return []conn.ReceiveFunc{fn},51820,nil}
	return []conn.ReceiveFunc{fn,fn},51820,nil
}
func(f *fakeProtectedBind) Close() error { f.opened=false;f.closes++;return nil }
func(f *fakeProtectedBind) SetMark(uint32) error { f.marks++;return nil }
func(f *fakeProtectedBind) Send([][]byte,conn.Endpoint) error {
	if !f.opened {return net.ErrClosed}
	f.sends++;return nil
}
func(f *fakeProtectedBind) ParseEndpoint(string)(conn.Endpoint,error){return nil,nil}
func(f *fakeProtectedBind) BatchSize() int{return 1}
func(f *fakeProtectedBind) PeekLookAtSocketFd4()(int,error){return 10,nil}
func(f *fakeProtectedBind) PeekLookAtSocketFd6()(int,error){
	if f.badFD {return -1,errors.New("missing socket")}
	return 11,nil
}
type fakeProtector struct { seen []int; reject int }
func(p *fakeProtector) Protect(fd int) bool {p.seen=append(p.seen,fd);return fd!=p.reject}

func TestProtectedBindProtectsBeforeSendAndReopen(t *testing.T){
	f:=&fakeProtectedBind{};p:=&fakeProtector{};b:=newProtectedBind(f,p)
	if err:=b.Send(nil,nil);!errors.Is(err,net.ErrClosed)||f.sends!=0 {t.Fatal("early send")}
	fns,port,err:=b.Open(0)
	if err!=nil||len(fns)!=2||port!=51820||!reflect.DeepEqual(p.seen,[]int{10,11}) {t.Fatal("protection missing")}
	if _,_,err=b.Open(0);err==nil||f.opens!=1||!f.opened {t.Fatal("duplicate open disturbed active bind")}
	if err=b.Send(nil,nil);err!=nil||f.sends!=1 {t.Fatal("protected send unavailable")}
	if err=b.SetMark(0);err!=nil||f.marks!=0 {t.Fatal("cleared platform mark")}
	if err=b.SetMark(23);!errors.Is(err,errExternalMark)||f.marks!=0 {t.Fatal("external mark passed")}
	if err=b.Close();err!=nil {t.Fatal(err)}
	if err=b.Send(nil,nil);!errors.Is(err,net.ErrClosed)||f.sends!=1 {t.Fatal("post-close send")}
	if _,_,err=b.Open(0);err!=nil||!reflect.DeepEqual(p.seen,[]int{10,11,10,11}) {t.Fatal("reopen skipped protection")}
	_ = b.Close()
}

func TestProtectedBindRejectsIncompleteProtection(t *testing.T){
	for _,c:=range []struct{single,badFD bool; reject int}{
		{true,false,0},{false,true,0},{false,false,10},{false,false,11},
	}{
		f:=&fakeProtectedBind{single:c.single,badFD:c.badFD}
		b:=newProtectedBind(f,&fakeProtector{reject:c.reject})
		fns,port,err:=b.Open(0)
		if !errors.Is(err,errProtection)||len(fns)!=0||port!=0||f.opened||f.closes!=1 {t.Fatalf("unsafe open: %+v",c)}
		if err=b.Send(nil,nil);!errors.Is(err,net.ErrClosed)||f.sends!=0 {t.Fatal("unprotected send")}
	}
	f:=&fakeProtectedBind{}
	b:=newProtectedBind(f,nil)
	if _,_,err:=b.Open(0);!errors.Is(err,errProtection)||f.opens!=0 {t.Fatal("opened without protector")}
}
