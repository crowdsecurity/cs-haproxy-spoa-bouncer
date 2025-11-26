package host

import (
	"fmt"
	"path/filepath"
	"testing"
)

// sliceMatcher represents the old slice-based host matching approach
// for benchmark comparison purposes
type sliceMatcher struct {
	hosts []*Host
}

func newSliceMatcher() *sliceMatcher {
	return &sliceMatcher{
		hosts: make([]*Host, 0),
	}
}

func (s *sliceMatcher) add(host *Host) {
	s.hosts = append(s.hosts, host)
}

// matchFirstHost is the old O(n) matching algorithm using filepath.Match
func (s *sliceMatcher) matchFirstHost(toMatch string) *Host { //nolint:unparam
	for _, host := range s.hosts {
		matched, err := filepath.Match(host.Host, toMatch)
		if matched && err == nil {
			return host
		}
	}
	return nil
}

// trieMatcher wraps the new trie implementation for benchmarking
type trieMatcher struct {
	trie            *domainTrie
	complexPatterns []*Host
}

func newTrieMatcher() *trieMatcher {
	return &trieMatcher{
		trie:            newDomainTrie(),
		complexPatterns: make([]*Host, 0),
	}
}

func (t *trieMatcher) add(host *Host) {
	if isComplexPattern(host.Host) {
		t.complexPatterns = append(t.complexPatterns, host)
	} else {
		t.trie.add(host)
	}
}

func (t *trieMatcher) matchFirstHost(toMatch string) *Host { //nolint:unparam
	return t.trie.match(toMatch, t.complexPatterns)
}

// generateHosts creates n hosts with patterns like:
// - Exact matches: host0.example.com, host1.example.com, ...
// - With some wildcards: *.domain0.com, *.domain1.com, ...
// - One catch-all: *
func generateHosts(n int) []*Host {
	hosts := make([]*Host, 0, n)

	// 70% exact matches
	exactCount := (n * 70) / 100
	for range exactCount {
		hosts = append(hosts, &Host{
			Host: fmt.Sprintf("host%d.example%d.com", len(hosts), len(hosts)%100),
		})
	}

	// 29% wildcard patterns
	wildcardCount := (n * 29) / 100
	for i := range wildcardCount {
		hosts = append(hosts, &Host{
			Host: fmt.Sprintf("*.domain%d.com", i),
		})
	}

	// 1% catch-all (at least 1)
	catchAllCount := n - exactCount - wildcardCount
	if catchAllCount < 1 {
		catchAllCount = 1
	}
	for range catchAllCount {
		hosts = append(hosts, &Host{
			Host: "*",
		})
	}

	return hosts
}

// BenchmarkSliceMatcher_Small benchmarks slice matching with 10 hosts
func BenchmarkSliceMatcher_Small(b *testing.B) {
	benchmarkSliceMatcher(b, 10)
}

// BenchmarkTrieMatcher_Small benchmarks trie matching with 10 hosts
func BenchmarkTrieMatcher_Small(b *testing.B) {
	benchmarkTrieMatcher(b, 10)
}

// BenchmarkSliceMatcher_Medium benchmarks slice matching with 100 hosts
func BenchmarkSliceMatcher_Medium(b *testing.B) {
	benchmarkSliceMatcher(b, 100)
}

// BenchmarkTrieMatcher_Medium benchmarks trie matching with 100 hosts
func BenchmarkTrieMatcher_Medium(b *testing.B) {
	benchmarkTrieMatcher(b, 100)
}

// BenchmarkSliceMatcher_Large benchmarks slice matching with 1000 hosts
func BenchmarkSliceMatcher_Large(b *testing.B) {
	benchmarkSliceMatcher(b, 1000)
}

// BenchmarkTrieMatcher_Large benchmarks trie matching with 1000 hosts
func BenchmarkTrieMatcher_Large(b *testing.B) {
	benchmarkTrieMatcher(b, 1000)
}

// BenchmarkSliceMatcher_XLarge benchmarks slice matching with 10000 hosts
func BenchmarkSliceMatcher_XLarge(b *testing.B) {
	benchmarkSliceMatcher(b, 10000)
}

// BenchmarkTrieMatcher_XLarge benchmarks trie matching with 10000 hosts
func BenchmarkTrieMatcher_XLarge(b *testing.B) {
	benchmarkTrieMatcher(b, 10000)
}

func benchmarkSliceMatcher(b *testing.B, hostCount int) {
	hosts := generateHosts(hostCount)
	matcher := newSliceMatcher()
	for _, h := range hosts {
		matcher.add(h)
	}

	// Test domains to match
	testDomains := []string{
		"host0.example0.com",                                                  // First exact match
		fmt.Sprintf("host%d.example%d.com", hostCount/2, (hostCount/2)%100),   // Middle exact match
		"api.domain50.com",                                                    // Wildcard match
		"unknown.random.org",                                                  // Falls through to catch-all
	}

	b.ResetTimer()
	b.ReportAllocs()

	for range b.N {
		for _, domain := range testDomains {
			_ = matcher.matchFirstHost(domain)
		}
	}
}

func benchmarkTrieMatcher(b *testing.B, hostCount int) {
	hosts := generateHosts(hostCount)
	matcher := newTrieMatcher()
	for _, h := range hosts {
		matcher.add(h)
	}

	// Test domains to match
	testDomains := []string{
		"host0.example0.com",                                                  // First exact match
		fmt.Sprintf("host%d.example%d.com", hostCount/2, (hostCount/2)%100),   // Middle exact match
		"api.domain50.com",                                                    // Wildcard match
		"unknown.random.org",                                                  // Falls through to catch-all
	}

	b.ResetTimer()
	b.ReportAllocs()

	for range b.N {
		for _, domain := range testDomains {
			_ = matcher.matchFirstHost(domain)
		}
	}
}

// BenchmarkSliceMatcher_WorstCase benchmarks slice matching when match is at the end
func BenchmarkSliceMatcher_WorstCase(b *testing.B) {
	hosts := generateHosts(1000)
	matcher := newSliceMatcher()
	for _, h := range hosts {
		matcher.add(h)
	}

	// Domain that will only match the catch-all at the end
	domain := "nomatch.unknown.tld"

	b.ResetTimer()
	b.ReportAllocs()

	for range b.N {
		_ = matcher.matchFirstHost(domain)
	}
}

// BenchmarkTrieMatcher_WorstCase benchmarks trie matching when falling through to catch-all
func BenchmarkTrieMatcher_WorstCase(b *testing.B) {
	hosts := generateHosts(1000)
	matcher := newTrieMatcher()
	for _, h := range hosts {
		matcher.add(h)
	}

	// Domain that will only match the catch-all
	domain := "nomatch.unknown.tld"

	b.ResetTimer()
	b.ReportAllocs()

	for range b.N {
		_ = matcher.matchFirstHost(domain)
	}
}

// BenchmarkSliceMatcher_BestCase benchmarks slice matching when match is first
func BenchmarkSliceMatcher_BestCase(b *testing.B) {
	hosts := generateHosts(1000)
	matcher := newSliceMatcher()
	for _, h := range hosts {
		matcher.add(h)
	}

	// Domain that matches the first host
	domain := "host0.example0.com"

	b.ResetTimer()
	b.ReportAllocs()

	for range b.N {
		_ = matcher.matchFirstHost(domain)
	}
}

// BenchmarkTrieMatcher_BestCase benchmarks trie matching with exact match
func BenchmarkTrieMatcher_BestCase(b *testing.B) {
	hosts := generateHosts(1000)
	matcher := newTrieMatcher()
	for _, h := range hosts {
		matcher.add(h)
	}

	// Domain that has an exact match
	domain := "host0.example0.com"

	b.ResetTimer()
	b.ReportAllocs()

	for range b.N {
		_ = matcher.matchFirstHost(domain)
	}
}

// BenchmarkAddHost_Slice benchmarks adding hosts to slice
func BenchmarkAddHost_Slice(b *testing.B) {
	hosts := generateHosts(100)

	b.ResetTimer()
	b.ReportAllocs()

	for range b.N {
		matcher := newSliceMatcher()
		for _, h := range hosts {
			matcher.add(h)
		}
	}
}

// BenchmarkAddHost_Trie benchmarks adding hosts to trie
func BenchmarkAddHost_Trie(b *testing.B) {
	hosts := generateHosts(100)

	b.ResetTimer()
	b.ReportAllocs()

	for range b.N {
		matcher := newTrieMatcher()
		for _, h := range hosts {
			matcher.add(h)
		}
	}
}
