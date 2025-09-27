package dataset

import (
	"net/netip"

	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
	log "github.com/sirupsen/logrus"
)

// BartUnifiedIPSet provides a unified interface for IP and CIDR operations using bart library
type BartUnifiedIPSet struct {
	trie   *BartTrie
	logger *log.Entry
}

// NewBartUnifiedIPSet creates a new BartUnifiedIPSet
func NewBartUnifiedIPSet(logAlias string) *BartUnifiedIPSet {
	return &BartUnifiedIPSet{
		trie:   NewBartTrie(logAlias),
		logger: log.WithField("alias", logAlias),
	}
}

// AddIP adds an exact IP address to the trie
func (s *BartUnifiedIPSet) AddIP(ip netip.Addr, origin string, r remediation.Remediation, id int64) error {
	// Intelligently detect the appropriate prefix length based on the IP content
	prefixLen := s.detectPrefixLength(ip)
	prefix := netip.PrefixFrom(ip, prefixLen)
	return s.trie.Add(prefix, origin, r, id)
}

// AddPrefix adds a CIDR prefix to the trie
func (s *BartUnifiedIPSet) AddPrefix(prefix netip.Prefix, origin string, r remediation.Remediation, id int64) error {
	return s.trie.Add(prefix, origin, r, id)
}

// RemoveIP removes an exact IP address from the trie
func (s *BartUnifiedIPSet) RemoveIP(ip netip.Addr, r remediation.Remediation, id int64) bool {
	// Use the same intelligent prefix detection for removal
	prefixLen := s.detectPrefixLength(ip)
	prefix := netip.PrefixFrom(ip, prefixLen)
	return s.trie.Remove(prefix, r, id)
}

// RemovePrefix removes a CIDR prefix from the trie
func (s *BartUnifiedIPSet) RemovePrefix(prefix netip.Prefix, r remediation.Remediation, id int64) bool {
	return s.trie.Remove(prefix, r, id)
}

// Contains checks if an IP address matches any prefix in the trie
func (s *BartUnifiedIPSet) Contains(ip netip.Addr) (remediation.Remediation, string) {
	return s.trie.Contains(ip)
}

// detectPrefixLength intelligently determines the appropriate prefix length based on the IP content
func (s *BartUnifiedIPSet) detectPrefixLength(ip netip.Addr) int {
	if ip.Is4() {
		// For IPv4, check if it's a typical subnet boundary
		// Common IPv4 subnets: /8 (255.0.0.0), /16 (255.255.0.0), /24 (255.255.255.0)
		bytes := ip.As4()

		// Check for /8 boundary (last three octets are 0) - broadest first
		if bytes[1] == 0 && bytes[2] == 0 && bytes[3] == 0 {
			return 8
		}
		// Check for /16 boundary (last two octets are 0)
		if bytes[2] == 0 && bytes[3] == 0 {
			return 16
		}
		// Check for /24 boundary (last octet is 0)
		if bytes[3] == 0 {
			return 24
		}
		// Default to /32 for specific IPs
		return 32
	}

	// For IPv6, check for common subnet boundaries by finding first non-zero byte
	bytes := ip.As16()

	// Find the first non-zero byte from the end
	for i := 15; i >= 0; i-- {
		if bytes[i] != 0 {
			// Calculate prefix length based on position of first non-zero byte
			prefixLen := (i + 1) * 8

			// Map to common IPv6 subnet boundaries
			switch {
			case prefixLen <= 16:
				return 16
			case prefixLen <= 32:
				return 32
			case prefixLen <= 48:
				return 48
			case prefixLen <= 56:
				return 56
			case prefixLen <= 60:
				return 60
			case prefixLen <= 64:
				return 64
			case prefixLen <= 80:
				return 80
			case prefixLen <= 96:
				return 96
			default:
				return 128
			}
		}
	}

	// All bytes are zero (::) - this is a /0 (entire IPv6 space)
	return 0
}
