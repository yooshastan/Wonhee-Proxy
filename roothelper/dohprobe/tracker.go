package main

import (
    "bufio"
        "encoding/binary"
    "errors"
    "io"
    "os"
    "strings"
)

// Batch E.1: the signed app commits a bounded, reviewed, offline list. Root
// reads it once before the DNS listener starts. No downloads, network access,
// DNS history, automatic policy changes or background subscriptions occur.
const maxTrackerPolicyBytes = 24 * 1024 * 1024
const maxTrackerPolicyEntries = 250512
const maxTrackerAllowEntries = 256

type trackerPolicy struct {
    blocked map[string]bool
    allowed map[string]bool
}

func validTrackerDomain(name string) bool {
    if len(name) < 4 || len(name) > 253 || !strings.Contains(name, ".") || strings.HasSuffix(name, ".") {
        return false
    }
    if strings.ContainsAny(name, ":/* \\@") || name != strings.ToLower(name) {
        return false
    }
    if strings.HasSuffix(name, ".local") || strings.HasSuffix(name, ".internal") || strings.HasSuffix(name, ".arpa") {
        return false
    }
    labels := strings.Split(name, ".")
    if len(labels) == 4 {
        ipv4 := true
        for _, label := range labels {
            if label == "" { ipv4 = false }
            for _, ch := range label {
                if ch < '0' || ch > '9' { ipv4 = false }
            }
        }
        if ipv4 { return false }
    }
    for _, label := range labels {
        if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
            return false
        }
        for _, ch := range label {
            if !(ch >= 'a' && ch <= 'z') && !(ch >= '0' && ch <= '9') && ch != '-' {
                return false
            }
        }
    }
    return true
}

func parseTrackerReader(reader io.Reader) (*trackerPolicy, error) {
    p := &trackerPolicy{
        blocked: make(map[string]bool),
        allowed: make(map[string]bool),
    }
    scanner := bufio.NewScanner(reader)
    scanner.Buffer(make([]byte, 4096), 4096)
    for scanner.Scan() {
        parts := strings.Fields(scanner.Text())
        if len(parts) == 0 { continue }
        if len(parts) != 2 { return nil, errors.New("invalid tracker policy line") }
        name := parts[1]
        if !validTrackerDomain(name) { return nil, errors.New("invalid tracker domain") }
        switch parts[0] {
        case "block":
            p.blocked[name] = true
        case "allow":
            p.allowed[name] = true
            if len(p.allowed) > maxTrackerAllowEntries {
                return nil, errors.New("too many allowlist entries")
            }
        default:
            return nil, errors.New("invalid tracker action")
        }
        if len(p.blocked)+len(p.allowed) > maxTrackerPolicyEntries {
            return nil, errors.New("too many tracker entries")
        }
    }
    if err := scanner.Err(); err != nil { return nil, err }
    if len(p.blocked) == 0 { return nil, errors.New("empty tracker blocklist") }
    return p, nil
}

func parseTrackerPolicy(data string) (*trackerPolicy, error) {
    if len(data) > maxTrackerPolicyBytes { return nil, errors.New("oversize tracker policy") }
    return parseTrackerReader(strings.NewReader(data))
}

func loadTrackerPolicy(path string) (*trackerPolicy, error) {
    if path == "" { return nil, nil }
    file, err := os.Open(path)
    if err != nil { return nil, err }
    defer file.Close()
    stat, err := file.Stat()
    if err != nil { return nil, err }
    if stat.Size() > maxTrackerPolicyBytes { return nil, errors.New("oversize tracker policy") }
    return parseTrackerReader(io.LimitReader(file, maxTrackerPolicyBytes+1))
}

func trackerMatch(name string, domains map[string]bool) bool {
    if domains[name] { return true }
    for pos := strings.IndexByte(name, '.'); pos >= 0; {
        name = name[pos+1:]
        if domains[name] { return true }
        pos = strings.IndexByte(name, '.')
    }
    return false
}

func (p *trackerPolicy) shouldBlock(name string) bool {
    if p == nil { return false }
    name = strings.ToLower(name)
    return !trackerMatch(name, p.allowed) && trackerMatch(name, p.blocked)
}

func trackerReply(query []byte, p *trackerPolicy) ([]byte, bool) {
    if p == nil { return nil, false }
    end, err := questionEnd(query)
    if err != nil { return nil, false }
    var name strings.Builder
    for pos := 12; pos < end-4; {
        length := int(query[pos])
        pos++
        if length == 0 { break }
        if name.Len() > 0 { name.WriteByte('.') }
        name.Write(query[pos:pos+length])
        pos += length
    }
    // Match only class IN. Block A and AAAA consistently.
    if binary.BigEndian.Uint16(query[end-2:end]) != 1 || !p.shouldBlock(name.String()) {
        return nil, false
    }
    reply := make([]byte, end)
    copy(reply, query[:end])
    reply[2] = 0x80 | (query[2] & 0x01)
    reply[3] = 0x83
    for i := 6; i < 12; i++ { reply[i] = 0 }
    return reply, true
}

