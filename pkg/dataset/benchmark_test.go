package dataset

import (
	"math/rand"
	"net/netip"
	"testing"

	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/go-cs-lib/ptr"
)

// generateTestIPs generates a set of test IP addresses
func generateTestIPs(count int) []netip.Addr {
	ips := make([]netip.Addr, count)
	for i := 0; i < count; i++ {
		// Generate random IPv4 addresses
		ip := netip.AddrFrom4([4]byte{
			byte(rand.Intn(256)),
			byte(rand.Intn(256)),
			byte(rand.Intn(256)),
			byte(rand.Intn(256)),
		})
		ips[i] = ip
	}
	return ips
}

// generateTestPrefixes generates a set of test CIDR prefixes
func generateTestPrefixes(count int) []netip.Prefix {
	prefixes := make([]netip.Prefix, count)
	for i := 0; i < count; i++ {
		// Generate random IPv4 prefixes with various lengths
		ip := netip.AddrFrom4([4]byte{
			byte(rand.Intn(256)),
			byte(rand.Intn(256)),
			byte(rand.Intn(256)),
			byte(rand.Intn(256)),
		})
		// Random prefix length between 8 and 30
		prefixLen := 8 + rand.Intn(23)
		prefixes[i] = netip.PrefixFrom(ip, prefixLen)
	}
	return prefixes
}

// generateTestDecisions generates test decisions for benchmarking
func generateTestDecisions(ipCount, prefixCount int) models.GetDecisionsResponse {
	decisions := make(models.GetDecisionsResponse, 0, ipCount+prefixCount)

	// Add IP decisions
	for i := 0; i < ipCount; i++ {
		ip := generateTestIPs(1)[0]
		decisions = append(decisions, &models.Decision{
			Scope:  ptr.Of("ip"),
			Value:  ptr.Of(ip.String()),
			Type:   ptr.Of("ban"),
			Origin: ptr.Of("test"),
			ID:     int64(i + 1),
		})
	}

	// Add prefix decisions
	for i := 0; i < prefixCount; i++ {
		prefix := generateTestPrefixes(1)[0]
		decisions = append(decisions, &models.Decision{
			Scope:  ptr.Of("range"),
			Value:  ptr.Of(prefix.String()),
			Type:   ptr.Of("ban"),
			Origin: ptr.Of("test"),
			ID:     int64(ipCount + i + 1),
		})
	}

	return decisions
}

// BenchmarkAddRemove tests the performance of adding and removing items
func BenchmarkAddRemove(b *testing.B) {
	dataset := New()
	decisions := generateTestDecisions(1000, 1000)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Add decisions
		dataset.Add(decisions)

		// Remove decisions
		dataset.Remove(decisions)
	}
}

// BenchmarkAddOnly tests the performance of adding items only
func BenchmarkAddOnly(b *testing.B) {
	decisions := generateTestDecisions(1000, 1000)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		dataset := New() // Fresh dataset each iteration
		dataset.Add(decisions)
	}
}

// BenchmarkRemoveOnly tests the performance of removing items only
func BenchmarkRemoveOnly(b *testing.B) {
	dataset := New()
	decisions := generateTestDecisions(1000, 1000)

	// Preload the dataset once
	dataset.Add(decisions)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Create a copy of decisions for each iteration
		decisionsCopy := make(models.GetDecisionsResponse, len(decisions))
		copy(decisionsCopy, decisions)
		dataset.Remove(decisionsCopy)
		// Re-add for next iteration
		dataset.Add(decisionsCopy)
	}
}

// BenchmarkDifferentSizes tests performance with different dataset sizes
func BenchmarkDifferentSizes(b *testing.B) {
	sizes := []struct {
		name        string
		ipCount     int
		prefixCount int
	}{
		{"Small", 100, 100},
		{"Medium", 1000, 1000},
		{"Large", 5000, 5000},
	}

	for _, size := range sizes {
		b.Run(size.name, func(b *testing.B) {
			dataset := New()
			decisions := generateTestDecisions(size.ipCount, size.prefixCount)

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				dataset.Add(decisions)
				dataset.Remove(decisions)
			}
		})
	}
}

// TestCorrectness verifies that the implementation works correctly
func TestCorrectness(t *testing.T) {
	// Generate test data
	decisions := generateTestDecisions(100, 100)
	testIPs := generateTestIPs(50)

	// Create dataset and populate it
	dataset := New()
	dataset.Add(decisions)

	// Test that the implementation works correctly
	for _, testIP := range testIPs {
		result, origin, err := dataset.CheckIP(testIP)

		if err != nil {
			t.Errorf("Error for IP %s: %v", testIP.String(), err)
			continue
		}

		// Basic sanity check - result should be valid
		if result < remediation.Allow {
			t.Errorf("Invalid result for IP %s: %v", testIP.String(), result)
		}

		// Origin should be non-empty if we have a match
		if result > remediation.Allow && origin == "" {
			t.Errorf("Empty origin for IP %s with result %v", testIP.String(), result)
		}
	}
}

// TestLongestPrefixMatch tests that the trie correctly implements longest prefix matching
func TestLongestPrefixMatch(t *testing.T) {
	dataset := New()

	// Add a broader prefix first
	if err := dataset.BartUnifiedIPSet.AddPrefix(netip.MustParsePrefix("192.168.0.0/16"), "test", remediation.Ban, 1); err != nil {
		t.Fatalf("Failed to add prefix: %v", err)
	}

	// Add a more specific prefix
	if err := dataset.BartUnifiedIPSet.AddPrefix(netip.MustParsePrefix("192.168.1.0/24"), "test", remediation.Captcha, 2); err != nil {
		t.Fatalf("Failed to add prefix: %v", err)
	}

	// Add an even more specific IP
	if err := dataset.BartUnifiedIPSet.AddIP(netip.MustParseAddr("192.168.1.1"), "test", remediation.Allow, 3); err != nil {
		t.Fatalf("Failed to add IP: %v", err)
	}

	// Test that we get the most specific match (Allow should win over Ban)
	ip1 := netip.MustParseAddr("192.168.1.1")
	result, _, _ := dataset.CheckIP(ip1)
	if result != remediation.Allow {
		t.Errorf("Expected Allow for 192.168.1.1, got %v", result)
	}

	// Test that we get the next most specific match (Captcha should win over Ban)
	ip2 := netip.MustParseAddr("192.168.1.2")
	result, _, _ = dataset.CheckIP(ip2)
	if result != remediation.Captcha {
		t.Errorf("Expected Captcha for 192.168.1.2, got %v", result)
	}

	// Test that we get the broadest match
	ip3 := netip.MustParseAddr("192.168.2.1")
	result, _, _ = dataset.CheckIP(ip3)
	if result != remediation.Ban {
		t.Errorf("Expected Ban for 192.168.2.1, got %v", result)
	}

	// Test that we get no match
	ip4 := netip.MustParseAddr("10.0.0.1")
	result, _, _ = dataset.CheckIP(ip4)
	if result != remediation.Allow {
		t.Errorf("Expected Allow for 10.0.0.1, got %v", result)
	}
}

// BenchmarkBartLookup benchmarks the bart implementation
func BenchmarkBartLookup(b *testing.B) {
	dataset := New()

	// Add some test data
	decisions := models.GetDecisionsResponse{
		{
			ID:     1,
			Origin: ptr.Of("test"),
			Scope:  ptr.Of("ip"),
			Value:  ptr.Of("192.168.1.1"),
			Type:   ptr.Of("ban"),
		},
		{
			ID:     2,
			Origin: ptr.Of("test"),
			Scope:  ptr.Of("range"),
			Value:  ptr.Of("192.168.0.0/16"),
			Type:   ptr.Of("captcha"),
		},
	}
	dataset.Add(decisions)

	testIP := netip.MustParseAddr("192.168.1.1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = dataset.CheckIP(testIP)
	}
}

// BenchmarkBartAdd benchmarks adding decisions with bart
func BenchmarkBartAdd(b *testing.B) {
	dataset := New()

	decisions := models.GetDecisionsResponse{
		{
			ID:     1,
			Origin: ptr.Of("test"),
			Scope:  ptr.Of("ip"),
			Value:  ptr.Of("192.168.1.1"),
			Type:   ptr.Of("ban"),
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dataset.Add(decisions)
		dataset.Remove(decisions)
	}
}

// BenchmarkBartRemove benchmarks removing decisions with bart
func BenchmarkBartRemove(b *testing.B) {
	dataset := New()

	decisions := models.GetDecisionsResponse{
		{
			ID:     1,
			Origin: ptr.Of("test"),
			Scope:  ptr.Of("ip"),
			Value:  ptr.Of("192.168.1.1"),
			Type:   ptr.Of("ban"),
		},
	}

	// Pre-populate
	dataset.Add(decisions)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dataset.Remove(decisions)
		dataset.Add(decisions)
	}
}
