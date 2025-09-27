package dataset

import (
	"net"
	"net/netip"
	"sync"

	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
	log "github.com/sirupsen/logrus"
	"github.com/yl2chen/cidranger"
)

// DecisionEntry represents a decision stored in the trie
type DecisionEntry struct {
	Remediation remediation.Remediation
	Origin      string
	ID          int64
}

// RangerEntry implements cidranger.RangerEntry
type RangerEntry struct {
	IPNet net.IPNet
	Data  *RemediationIdsMap
}

// Network returns the network for this entry
func (r *RangerEntry) Network() net.IPNet {
	return r.IPNet
}

// CIDRTrie is a trie-based implementation using cidranger
type CIDRTrie struct {
	sync.RWMutex
	ranger cidranger.Ranger
	logger *log.Entry
}

// NewCIDRTrie creates a new CIDR trie using cidranger
func NewCIDRTrie(logAlias string) *CIDRTrie {
	return &CIDRTrie{
		ranger: cidranger.NewPCTrieRanger(),
		logger: log.WithField("alias", logAlias),
	}
}

// Add adds an IP address or CIDR prefix to the trie
// For exact IPs, we use /32 (IPv4) or /128 (IPv6) prefixes
func (t *CIDRTrie) Add(prefix netip.Prefix, origin string, r remediation.Remediation, id int64) error {
	t.Lock()
	defer t.Unlock()

	valueLog := t.logger.WithField("prefix", prefix.String()).WithField("remediation", r.String())
	valueLog.Trace("adding to cidranger trie")

	// Convert to canonical form
	prefix = prefix.Masked()

	// Convert netip.Prefix to net.IPNet
	ipNet := &net.IPNet{
		IP:   prefix.Addr().AsSlice(),
		Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()),
	}

	// Check if this prefix already exists
	existing, err := t.ranger.ContainingNetworks(prefix.Addr().AsSlice())
	if err != nil {
		return err
	}

	// Look for exact match
	for _, entry := range existing {
		if rangerEntry, ok := entry.(*RangerEntry); ok {
			if rangerEntry.IPNet.String() == ipNet.String() {
				// Update existing entry
				valueLog.Trace("updating existing entry")
				rangerEntry.Data.AddID(valueLog, r, id, origin)
				return nil
			}
		}
	}

	// Create new entry
	valueLog.Trace("creating new entry")
	newEntry := &RangerEntry{
		IPNet: *ipNet,
		Data:  &RemediationIdsMap{},
	}
	newEntry.Data.AddID(valueLog, r, id, origin)

	return t.ranger.Insert(newEntry)
}

// Remove removes an IP address or CIDR prefix from the trie
func (t *CIDRTrie) Remove(prefix netip.Prefix, r remediation.Remediation, id int64) bool {
	t.Lock()
	defer t.Unlock()

	valueLog := t.logger.WithField("prefix", prefix.String()).WithField("remediation", r.String())
	valueLog.Trace("removing from cidranger trie")

	// Convert to canonical form
	prefix = prefix.Masked()

	// Convert netip.Prefix to net.IPNet
	ipNet := &net.IPNet{
		IP:   prefix.Addr().AsSlice(),
		Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()),
	}

	// Find the exact entry
	existing, err := t.ranger.ContainingNetworks(prefix.Addr().AsSlice())
	if err != nil {
		valueLog.Error(err)
		return false
	}

	// Look for exact match
	for _, entry := range existing {
		if rangerEntry, ok := entry.(*RangerEntry); ok {
			if rangerEntry.IPNet.String() == ipNet.String() {
				// Remove the specific remediation
				if err := rangerEntry.Data.RemoveID(valueLog, r, id); err != nil {
					valueLog.Error(err)
					return false
				}

				// If no more remediations, remove the entire entry
				if len(*rangerEntry.Data) == 0 {
					valueLog.Trace("removing empty entry")
					_, err := t.ranger.Remove(*ipNet)
					return err == nil
				}

				return true
			}
		}
	}

	valueLog.Trace("prefix not found")
	return false
}

// Contains checks if an IP address matches any prefix in the trie
// Returns the longest matching prefix's remediation and origin
func (t *CIDRTrie) Contains(ip netip.Addr) (remediation.Remediation, string) {
	t.RLock()
	defer t.RUnlock()

	valueLog := t.logger.WithField("ip", ip.String())
	valueLog.Trace("checking in cidranger trie")

	// Find all containing networks
	networks, err := t.ranger.ContainingNetworks(ip.AsSlice())
	if err != nil {
		valueLog.Error(err)
		return remediation.Allow, ""
	}

	// Find the longest matching prefix (most specific)
	bestRemediation := remediation.Allow
	bestOrigin := ""
	longestPrefixLen := -1

	for _, entry := range networks {
		if rangerEntry, ok := entry.(*RangerEntry); ok {
			prefixLen, _ := rangerEntry.IPNet.Mask.Size()
			if prefixLen > longestPrefixLen {
				// Always take the longest prefix match, regardless of remediation value
				bestRemediation, bestOrigin = rangerEntry.Data.GetRemediationAndOrigin()
				longestPrefixLen = prefixLen
			}
		}
	}

	valueLog.Tracef("cidranger result: %s", bestRemediation.String())
	return bestRemediation, bestOrigin
}
