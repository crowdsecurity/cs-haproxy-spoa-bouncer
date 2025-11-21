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

// Contains checks if an IP address matches any prefix in the trie
func (s *BartUnifiedIPSet) Contains(ip netip.Addr) (remediation.Remediation, string) {
	return s.trie.Contains(ip)
}

// AddBatch adds multiple prefixes in a single batch operation.
// IPs should be converted to /32 or /128 prefixes before calling this method.
func (s *BartUnifiedIPSet) AddBatch(operations []BartAddOp) error {
	return s.trie.AddBatch(operations)
}

// RemoveBatch removes multiple prefixes in a single batch operation.
// IPs should be converted to /32 or /128 prefixes before calling this method.
// Returns a slice of pointers to successfully removed operations (nil for failures).
func (s *BartUnifiedIPSet) RemoveBatch(operations []BartRemoveOp) []*BartRemoveOp {
	return s.trie.RemoveBatch(operations)
}
