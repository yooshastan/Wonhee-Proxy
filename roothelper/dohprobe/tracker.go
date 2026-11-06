package main

import (
	"encoding/binary"
	"errors"
	"os"
	"strings"
)

// Tracker filtering is entirely local. The signed APK supplies a bounded,
// user-reviewable policy; neither list downloads nor telemetry occur in root.
type trackerPolicy struct {
	blocked map[string]bool
	allowed map[string]bool
}

func validTrackerDomain(name string) bool {
	if len(name) < 4 || len(name) > 253 || !strings.Contains(name, ".") || strings.HasSuffix(name, ".") { return false }
	if strings.ContainsAny(name, ":/* \\@") { return false }
	labels:=strings.Split(name,".")
	if len(labels)==4 {
		ipv4:=true
		for _,l:=range labels { if l=="" { ipv4=false }; for _,c:=range l { if c<'0'||c>'9'{ipv4=false} } }
		if ipv4 { return false }
	}
	for _,l:=range labels {
		if len(l)==0||len(l)>63||l[0]=='-'||l[len(l)-1]=='-' { return false }
		for _,c:=range l {if !(c>='a'&&c<='z')&&!(c>='0'&&c<='9')&&c!='-'{return false}}
	}
	return true
}

func parseTrackerPolicy(data string) (*trackerPolicy,error) {
	if len(data)>24000 {return nil,errors.New("oversize tracker policy")}
	p:=&trackerPolicy{blocked:make(map[string]bool),allowed:make(map[string]bool)}
	for _,raw:=range strings.Split(data,"\n") {
		line:=strings.TrimSpace(raw)
		if line==""{continue}
		parts:=strings.Fields(line)
		if len(parts)!=2{return nil,errors.New("invalid tracker policy line")}
		domain:=strings.ToLower(parts[1])
		if !validTrackerDomain(domain) {return nil,errors.New("invalid tracker domain")}
		if len(p.blocked)+len(p.allowed)>=400 {return nil,errors.New("too many tracker entries")}
		switch parts[0] {
		case "block":p.blocked[domain]=true
		case "allow":p.allowed[domain]=true
		default:return nil,errors.New("invalid tracker action")
		}
	}
	if len(p.blocked)==0{return nil,errors.New("empty tracker blocklist")}
	return p,nil
}

func loadTrackerPolicy(path string)(*trackerPolicy,error){
	if path==""{return nil,nil}
	// The file path is supplied by Wonhee's own private application directory.
	// The helper reads it once before binding a listener, never follows updates.
	data,err:=os.ReadFile(path)
	if err!=nil{return nil,err}
	return parseTrackerPolicy(string(data))
}

func trackerMatch(name string,domains map[string]bool) bool {
	if domains[name] {return true}
	for idx:=strings.IndexByte(name,'.');idx>=0;{
		name=name[idx+1:]
		if domains[name]{return true}
		idx=strings.IndexByte(name,'.')
	}
	return false
}

func (p *trackerPolicy) shouldBlock(name string) bool {
	if p==nil {return false}
	name=strings.ToLower(name)
	return !trackerMatch(name,p.allowed)&&trackerMatch(name,p.blocked)
}

func trackerReply(query []byte,p *trackerPolicy)([]byte,bool){
	if p==nil{return nil,false}
	end,err:=questionEnd(query)
	if err!=nil{return nil,false}
	var name strings.Builder
	for pos:=12;pos<end-4;{
		length:=int(query[pos]);pos++
		if length==0{break}
		if name.Len()>0{name.WriteByte('.')}
		name.Write(query[pos:pos+length]);pos+=length
	}
	if binary.BigEndian.Uint16(query[end-2:end])!=1 || !p.shouldBlock(name.String()){
		return nil,false
	}
	reply:=make([]byte,end)
	copy(reply,query[:end])
	// QR + RD-preserving + RA + NXDOMAIN. No forged DNSSEC AD bit or
	// upstream claims; the answer section is intentionally empty.
	reply[2]=0x80 | (query[2]&0x01)
	reply[3]=0x83
	for i:=6;i<12;i++{reply[i]=0}
	return reply,true
}
