package main

import (
    "os"
    "path/filepath"
    "strings"
    "testing"
)

func TestDnsStatsSnapshotIsAggregateOnly(t *testing.T) {
    dir := filepath.Join(t.TempDir(), "files")
    if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
    path := filepath.Join(dir, statsFileName)
    stats, err := newDNSCounters(path)
    if err != nil { t.Fatal(err) }
    stats.received.Add(4)
    stats.blocked.Add(2)
    stats.forwarded.Add(1)
    stats.failed.Add(1)
    if err := stats.flush(); err != nil { t.Fatal(err) }
    raw, err := os.ReadFile(path)
    if err != nil { t.Fatal(err) }
    body := string(raw)
    for _, expected := range []string{
        statsVersion, "received=4", "blocked=2", "forwarded=1", "failed=1",
    } {
        if !strings.Contains(body, expected) { t.Fatalf("missing %s in counters", expected) }
    }
    if strings.Contains(body, ".com") || strings.Contains(body, "qname") {
        t.Fatal("stats must not contain client DNS content")
    }
    if _, err := newDNSCounters("/tmp/evil-stats.txt"); err == nil {
        t.Fatal("accepted arbitrary stats path")
    }
}
