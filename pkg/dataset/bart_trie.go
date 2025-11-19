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

	prefix = prefix.Masked()

	// Only build logging fields if trace level is enabled
	var valueLog *log.Entry
	if t.logger.Logger.IsLevelEnabled(log.TraceLevel) {
		valueLog = t.logger.WithField("prefix", prefix.String()).WithField("remediation", r.String())
		valueLog.Trace("adding to bart trie")
	}

	// Use Modify to handle both insert and update cases
	t.table.Modify(prefix, func(current RemediationIdsMap, found bool) (RemediationIdsMap, bool) {
		if found {
			if valueLog != nil {
				valueLog.Trace("updating existing entry")
			}
			current.AddID(valueLog, r, id, origin)
			return current, false // false = update, not delete
		}

		if valueLog != nil {
			valueLog.Trace("creating new entry")
		}
		newData := RemediationIdsMap{}
		newData.AddID(valueLog, r, id, origin)
		return newData, false // false = insert, not delete
	})

	return nil
}

// Remove removes a prefix from the bart table
func (t *BartTrie) Remove(prefix netip.Prefix, r remediation.Remediation, id int64) bool {
	t.Lock()
	defer t.Unlock()

	prefix = prefix.Masked()

	// Only build logging fields if trace level is enabled
	var valueLog *log.Entry
	if t.logger.Logger.IsLevelEnabled(log.TraceLevel) {
		valueLog = t.logger.WithField("prefix", prefix.String()).WithField("remediation", r.String())
		valueLog.Trace("removing from bart trie")
	}

	// Track whether the ID was actually found and removed
	var idRemoved bool

	// Use Modify to handle the removal
	t.table.Modify(prefix, func(current RemediationIdsMap, found bool) (RemediationIdsMap, bool) {
		if !found {
			if valueLog != nil {
				valueLog.Trace("prefix not found")
			}
			return current, false // no-op
		}

		// Remove the specific ID
		err := current.RemoveID(valueLog, r, id)
		if err != nil {
			if valueLog != nil {
				valueLog.Trace("ID not found")
			}
			return current, false // no-op
		}

		// ID was successfully removed
		idRemoved = true

		if current.IsEmpty() {
			if valueLog != nil {
				valueLog.Trace("removed prefix entirely")
			}
			return current, true // delete the entry
		}

		if valueLog != nil {
			valueLog.Trace("removed ID from existing prefix")
		}
		return current, false // update with modified data
	})

	return idRemoved
}

// Contains checks if an IP address matches any prefix in the bart table
// Returns the longest matching prefix's remediation and origin
func (t *BartTrie) Contains(ip netip.Addr) (remediation.Remediation, string) {
	t.RLock()
	defer t.RUnlock()

	// Only build logging fields if trace level is enabled
	var valueLog *log.Entry
	if t.logger.Logger.IsLevelEnabled(log.TraceLevel) {
		valueLog = t.logger.WithField("ip", ip.String())
		valueLog.Trace("checking in bart trie")
	}

	// Use Lookup to get the longest prefix match
	data, found := t.table.Lookup(ip)
	if !found {
		if valueLog != nil {
			valueLog.Trace("no match found")
		}
		return remediation.Allow, ""
	}

	remediationResult, origin := data.GetRemediationAndOrigin()
	if valueLog != nil {
		valueLog.Tracef("bart result: %s (data: %+v)", remediationResult.String(), data)
	}
	return remediationResult, origin
}
