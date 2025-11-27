package dataset

import (
	"fmt"
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
	for i := range count {
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
	for i := range count {
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
	for i := range ipCount {
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
	for i := range prefixCount {
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

	for range b.N {
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

	for range b.N {
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

	for range b.N {
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

			for range b.N {
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

// TestLongestPrefixMatch tests that the hybrid storage correctly handles individual IPs vs ranges
func TestLongestPrefixMatch(t *testing.T) {
	dataset := New()

	// Add individual IP to IPMap and ranges to RangeSet
	dataset.IPMap.AddBatch([]IPAddOp{
		{IP: netip.MustParseAddr("192.168.1.1"), Origin: "test", R: remediation.Allow, ID: 3, IPType: "ipv4"},
	})
	dataset.RangeSet.AddBatch([]BartAddOp{
		{Prefix: netip.MustParsePrefix("192.168.0.0/16"), Origin: "test", R: remediation.Ban, ID: 1, IPType: "ipv4", Scope: "range"},
		{Prefix: netip.MustParsePrefix("192.168.1.0/24"), Origin: "test", R: remediation.Captcha, ID: 2, IPType: "ipv4", Scope: "range"},
	})

	// Test that individual IP from IPMap wins (checked first before RangeSet)
	ip1 := netip.MustParseAddr("192.168.1.1")
	result, _, _ := dataset.CheckIP(ip1)
	if result != remediation.Allow {
		t.Errorf("Expected Allow for 192.168.1.1 (from IPMap), got %v", result)
	}

	// Test that we get the LPM from RangeSet (Captcha /24 wins over Ban /16)
	ip2 := netip.MustParseAddr("192.168.1.2")
	result, _, _ = dataset.CheckIP(ip2)
	if result != remediation.Captcha {
		t.Errorf("Expected Captcha for 192.168.1.2 (LPM from RangeSet), got %v", result)
	}

	// Test that we get the broadest match from RangeSet
	ip3 := netip.MustParseAddr("192.168.2.1")
	result, _, _ = dataset.CheckIP(ip3)
	if result != remediation.Ban {
		t.Errorf("Expected Ban for 192.168.2.1 (from RangeSet), got %v", result)
	}

	// Test that we get no match
	ip4 := netip.MustParseAddr("10.0.0.1")
	result, _, _ = dataset.CheckIP(ip4)
	if result != remediation.Allow {
		t.Errorf("Expected Allow for 10.0.0.1 (no match), got %v", result)
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
	for range b.N {
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
	for range b.N {
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
	for range b.N {
		dataset.Remove(decisions)
		dataset.Add(decisions)
	}
}

// BenchmarkHybridVsBartOnly compares memory allocation of hybrid vs BART-only storage
func BenchmarkHybridVsBartOnly(b *testing.B) {
	// Generate test IPs (individual addresses, not ranges)
	generateIPDecisions := func(count int) models.GetDecisionsResponse {
		decisions := make(models.GetDecisionsResponse, 0, count)
		for i := range count {
			ip := netip.AddrFrom4([4]byte{
				byte(10 + i/16777216%246),
				byte(i / 65536 % 256),
				byte(i / 256 % 256),
				byte(i % 256),
			})
			decisions = append(decisions, &models.Decision{
				Scope:  ptr.Of("ip"),
				Value:  ptr.Of(ip.String()),
				Type:   ptr.Of("ban"),
				Origin: ptr.Of("test"),
				ID:     int64(i + 1),
			})
		}
		return decisions
	}

	sizes := []int{1000, 10000, 50000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("Hybrid_%d_IPs", size), func(b *testing.B) {
			decisions := generateIPDecisions(size)
			b.ResetTimer()
			b.ReportAllocs()

			for range b.N {
				dataset := New()
				dataset.Add(decisions)
			}
		})

		b.Run(fmt.Sprintf("BartOnly_%d_IPs", size), func(b *testing.B) {
			// Generate the same IPs but convert to prefix batch for BART
			decisions := generateIPDecisions(size)
			ops := make([]BartAddOp, 0, size)
			for _, d := range decisions {
				ip, _ := netip.ParseAddr(*d.Value)
				prefixLen := 32
				if ip.Is6() {
					prefixLen = 128
				}
				ops = append(ops, BartAddOp{
					Prefix: netip.PrefixFrom(ip, prefixLen),
					Origin: *d.Origin,
					R:      remediation.Ban,
					ID:     d.ID,
					IPType: "ipv4",
					Scope:  "ip",
				})
			}

			b.ResetTimer()
			b.ReportAllocs()

			for range b.N {
				bartSet := NewBartUnifiedIPSet("test")
				bartSet.AddBatch(ops)
			}
		})
	}
}

// BenchmarkLookupHybrid benchmarks lookup in the hybrid storage
func BenchmarkLookupHybrid(b *testing.B) {
	dataset := New()

	// Add individual IPs to IPMap
	for i := range 10000 {
		ip := netip.AddrFrom4([4]byte{
			byte(10),
			byte(i / 65536 % 256),
			byte(i / 256 % 256),
			byte(i % 256),
		})
		dataset.IPMap.AddBatch([]IPAddOp{
			{IP: ip, Origin: "test", R: remediation.Ban, ID: int64(i), IPType: "ipv4"},
		})
	}

	// Add some ranges to RangeSet
	dataset.RangeSet.AddBatch([]BartAddOp{
		{Prefix: netip.MustParsePrefix("192.168.0.0/16"), Origin: "test", R: remediation.Ban, ID: 1, IPType: "ipv4", Scope: "range"},
	})

	// Test IPs - some in IPMap, some in RangeSet, some not found
	testIPs := []netip.Addr{
		netip.MustParseAddr("10.0.0.1"),      // In IPMap
		netip.MustParseAddr("10.0.39.15"),    // In IPMap  
		netip.MustParseAddr("192.168.1.100"), // In RangeSet
		netip.MustParseAddr("8.8.8.8"),       // Not found
	}

	b.Run("IPMap_hit", func(b *testing.B) {
		ip := testIPs[0]
		b.ResetTimer()
		for range b.N {
			_, _, _ = dataset.CheckIP(ip)
		}
	})

	b.Run("RangeSet_hit", func(b *testing.B) {
		ip := testIPs[2]
		b.ResetTimer()
		for range b.N {
			_, _, _ = dataset.CheckIP(ip)
		}
	})

	b.Run("No_match", func(b *testing.B) {
		ip := testIPs[3]
		b.ResetTimer()
		for range b.N {
			_, _, _ = dataset.CheckIP(ip)
		}
	})
}
