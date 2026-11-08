package main

import (
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "sync/atomic"
    "time"
)

// Statistics contain only aggregate counts, never queried domains, IPs,
// resolver replies, peer information or per-app identifiers.
const statsFileName = "wonhee-dns-stats-v1.txt"
const statsVersion = "WN_DNS_STATS_V1"

type dnsCounters struct {
    received atomic.Uint64
    blocked atomic.Uint64
    forwarded atomic.Uint64
    failed atomic.Uint64
    path string
}

func newDNSCounters(path string) (*dnsCounters, error) {
    if !filepath.IsAbs(path) || filepath.Base(path) != statsFileName ||
        filepath.Base(filepath.Dir(path)) != "files" {
        return nil, errors.New("stats path must be the private app files directory")
    }
    dir := filepath.Dir(path)
    info, err := os.Stat(dir)
    if err != nil || !info.IsDir() { return nil, errors.New("stats directory unavailable") }
    return &dnsCounters{path: path}, nil
}

func (c *dnsCounters) snapshot() string {
    return fmt.Sprintf("%s pid=%d received=%d blocked=%d forwarded=%d failed=%d\n",
        statsVersion, os.Getpid(), c.received.Load(), c.blocked.Load(),
        c.forwarded.Load(), c.failed.Load())
}

func (c *dnsCounters) flush() error {
    if c == nil { return nil }
    tmp := c.path + fmt.Sprintf(".tmp-%d", os.Getpid())
    // The native helper only receives a path constructed inside the app's
    // private storage. Never follow a preexisting tempfile symlink.
    if fi, err := os.Lstat(tmp); err == nil && (fi.Mode()&os.ModeSymlink) != 0 {
        return errors.New("stats staging symlink refused")
    } else if err != nil && !os.IsNotExist(err) { return err }
    f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
    if err != nil { return err }
    _, writeErr := f.WriteString(c.snapshot())
    if writeErr == nil { writeErr = f.Sync() }
    closeErr := f.Close()
    if writeErr != nil { return writeErr }
    if closeErr != nil { return closeErr }
    return os.Rename(tmp, c.path)
}

func (c *dnsCounters) startSnapshots() error {
    if c == nil { return nil }
    if err := c.flush(); err != nil { return err }
    go func() {
        ticker := time.NewTicker(2 * time.Second)
        defer ticker.Stop()
        for range ticker.C {
            // Stats failure must never weaken encrypted DNS or enable fallback.
            _ = c.flush()
        }
    }()
    return nil
}
