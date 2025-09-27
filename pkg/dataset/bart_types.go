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
	prefix := netip.PrefixFrom(ip, ip.BitLen())
	return s.trie.Add(prefix, origin, r, id)
}

// AddPrefix adds a CIDR prefix to the trie
func (s *BartUnifiedIPSet) AddPrefix(prefix netip.Prefix, origin string, r remediation.Remediation, id int64) error {
	return s.trie.Add(prefix, origin, r, id)
}

// RemoveIP removes an exact IP address from the trie
func (s *BartUnifiedIPSet) RemoveIP(ip netip.Addr, r remediation.Remediation, id int64) bool {
	prefix := netip.PrefixFrom(ip, ip.BitLen())
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
