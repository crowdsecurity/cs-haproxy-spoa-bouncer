package dataset

import (
	"net/netip"
	"sync"

	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
	log "github.com/sirupsen/logrus"
)

// CIDRUnifiedIPSet is a trie-based implementation using cidranger that replaces both IPSet and PrefixSet
// It stores both exact IPs (as /32 or /128 prefixes) and CIDR prefixes in a single trie
type CIDRUnifiedIPSet struct {
	sync.RWMutex
	trie   *CIDRTrie
	logger *log.Entry
}

// NewCIDRUnifiedIPSet creates a new unified IP set using cidranger
func NewCIDRUnifiedIPSet(logAlias string) *CIDRUnifiedIPSet {
	return &CIDRUnifiedIPSet{
		trie:   NewCIDRTrie(logAlias),
		logger: log.WithField("alias", logAlias),
	}
}

// AddIP adds an exact IP address to the set (stored as /32 or /128 prefix)
func (s *CIDRUnifiedIPSet) AddIP(ip netip.Addr, origin string, r remediation.Remediation, id int64) error {
	// Convert exact IP to /32 (IPv4) or /128 (IPv6) prefix
	var prefix netip.Prefix
	if ip.Is4() {
		prefix = netip.PrefixFrom(ip, 32)
	} else {
		prefix = netip.PrefixFrom(ip, 128)
	}

	return s.trie.Add(prefix, origin, r, id)
}

// AddPrefix adds a CIDR prefix to the set
func (s *CIDRUnifiedIPSet) AddPrefix(prefix netip.Prefix, origin string, r remediation.Remediation, id int64) error {
	return s.trie.Add(prefix, origin, r, id)
}

// RemoveIP removes an exact IP address from the set
func (s *CIDRUnifiedIPSet) RemoveIP(ip netip.Addr, r remediation.Remediation, id int64) bool {
	// Convert exact IP to /32 (IPv4) or /128 (IPv6) prefix
	var prefix netip.Prefix
	if ip.Is4() {
		prefix = netip.PrefixFrom(ip, 32)
	} else {
		prefix = netip.PrefixFrom(ip, 128)
	}

	return s.trie.Remove(prefix, r, id)
}

// RemovePrefix removes a CIDR prefix from the set
func (s *CIDRUnifiedIPSet) RemovePrefix(prefix netip.Prefix, r remediation.Remediation, id int64) bool {
	return s.trie.Remove(prefix, r, id)
}

// Contains checks if an IP address matches any prefix in the set
// Returns the longest matching prefix's remediation and origin
func (s *CIDRUnifiedIPSet) Contains(ip netip.Addr) (remediation.Remediation, string) {
	return s.trie.Contains(ip)
}
