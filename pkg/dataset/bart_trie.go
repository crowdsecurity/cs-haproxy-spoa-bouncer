package dataset

import (
	"net/netip"
	"sync"

	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
	"github.com/gaissmai/bart"
	log "github.com/sirupsen/logrus"
)

// BartTrie is a trie-based implementation using bart library
type BartTrie struct {
	sync.RWMutex
	table  *bart.Table[RemediationIdsMap]
	logger *log.Entry
}

// NewBartTrie creates a new bart-based trie
func NewBartTrie(logAlias string) *BartTrie {
	return &BartTrie{
		table:  &bart.Table[RemediationIdsMap]{},
		logger: log.WithField("alias", logAlias),
	}
}

// Add adds a prefix to the bart table
func (t *BartTrie) Add(prefix netip.Prefix, origin string, r remediation.Remediation, id int64) error {
	t.Lock()
	defer t.Unlock()

	valueLog := t.logger.WithField("prefix", prefix.String()).WithField("remediation", r.String())
	valueLog.Trace("adding to bart trie")

	prefix = prefix.Masked()

	// Use Modify to handle both insert and update cases
	t.table.Modify(prefix, func(current RemediationIdsMap, found bool) (RemediationIdsMap, bool) {
		if found {
			valueLog.Trace("updating existing entry")
			current.AddID(valueLog, r, id, origin)
			return current, false // false = update, not delete
		} else {
			valueLog.Trace("creating new entry")
			newData := RemediationIdsMap{}
			newData.AddID(valueLog, r, id, origin)
			return newData, false // false = insert, not delete
		}
	})

	return nil
}

// Remove removes a prefix from the bart table
func (t *BartTrie) Remove(prefix netip.Prefix, r remediation.Remediation, id int64) bool {
	t.Lock()
	defer t.Unlock()

	valueLog := t.logger.WithField("prefix", prefix.String()).WithField("remediation", r.String())
	valueLog.Trace("removing from bart trie")

	prefix = prefix.Masked()

	// Use Modify to handle the removal
	_, deleted := t.table.Modify(prefix, func(current RemediationIdsMap, found bool) (RemediationIdsMap, bool) {
		if !found {
			valueLog.Trace("prefix not found")
			return current, false // no-op
		}

		// Remove the specific ID
		err := current.RemoveID(valueLog, r, id)
		if err != nil {
			valueLog.Trace("ID not found")
			return current, false // no-op
		}

		if current.IsEmpty() {
			valueLog.Trace("removed prefix entirely")
			return current, true // delete the entry
		}

		valueLog.Trace("removed ID from existing prefix")
		return current, false // update with modified data
	})

	return deleted
}

// Contains checks if an IP address matches any prefix in the bart table
// Returns the longest matching prefix's remediation and origin
func (t *BartTrie) Contains(ip netip.Addr) (remediation.Remediation, string) {
	t.RLock()
	defer t.RUnlock()

	valueLog := t.logger.WithField("ip", ip.String())
	valueLog.Trace("checking in bart trie")

	// Use Lookup to get the longest prefix match
	data, found := t.table.Lookup(ip)
	if !found {
		valueLog.Trace("no match found")
		return remediation.Allow, ""
	}

	remediation, origin := data.GetRemediationAndOrigin()
	valueLog.Tracef("bart result: %s (data: %+v)", remediation.String(), data)
	return remediation, origin
}
