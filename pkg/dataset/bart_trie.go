package dataset

import (
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
	"github.com/gaissmai/bart"
	log "github.com/sirupsen/logrus"
)

// BartAddOp represents a single prefix add operation for batch processing
type BartAddOp struct {
	Prefix netip.Prefix
	Origin string
	R      remediation.Remediation
	ID     int64
	IPType string
	Scope  string
}

// BartRemoveOp represents a single prefix removal operation for batch processing
type BartRemoveOp struct {
	Prefix netip.Prefix
	R      remediation.Remediation
	ID     int64
	Origin string
	IPType string
	Scope  string
}

// BartTrie is a trie-based implementation using bart library.
// Uses atomic pointer for lock-free reads and mutex-protected writes
// following the pattern recommended in bart's documentation.
type BartTrie struct {
	tableAtomicPtr atomic.Pointer[bart.Table[RemediationIdsMap]]
	writeMutex     sync.Mutex // Protects writers only
	logger         *log.Entry
}

// NewBartTrie creates a new bart-based trie
func NewBartTrie(logAlias string) *BartTrie {
	baseTable := &bart.Table[RemediationIdsMap]{}
	trie := &BartTrie{
		logger: log.WithField("alias", logAlias),
	}
	trie.tableAtomicPtr.Store(baseTable)
	return trie
}

// AddBatch adds multiple prefixes to the bart table in a single atomic operation.
// This is much more efficient than calling Add() multiple times, as it only
// swaps the atomic pointer once at the end instead of once per prefix.
func (t *BartTrie) AddBatch(operations []BartAddOp) error {
	if len(operations) == 0 {
		return nil
	}

	t.writeMutex.Lock()
	defer t.writeMutex.Unlock()

	// Get current table atomically
	cur := t.tableAtomicPtr.Load()

	// Process all operations, chaining the table updates
	next := cur
	for _, op := range operations {
		prefix := op.Prefix.Masked()

		// Only build logging fields if trace level is enabled
		var valueLog *log.Entry
		if t.logger.Logger.IsLevelEnabled(log.TraceLevel) {
			valueLog = t.logger.WithField("prefix", prefix.String()).WithField("remediation", op.R.String())
			valueLog.Trace("adding to bart trie")
		}

		// Check if the exact prefix exists by attempting to delete it
		// DeletePersist returns (newTable, value, found) - if found is true, the exact prefix existed
		var existingData RemediationIdsMap
		var exactPrefixExists bool
		next, existingData, exactPrefixExists = next.DeletePersist(prefix)

		var newData RemediationIdsMap
		if exactPrefixExists {
			if valueLog != nil {
				valueLog.Trace("exact prefix exists, merging IDs")
			}
			// Clone existing data and add the new ID
			newData = existingData.Clone()
			newData.AddID(valueLog, op.R, op.ID, op.Origin)
		} else {
			if valueLog != nil {
				valueLog.Trace("creating new entry")
			}
			// Create new data
			newData = RemediationIdsMap{}
			newData.AddID(valueLog, op.R, op.ID, op.Origin)
		}
		// Re-insert with merged/new data (we deleted it to check, now we add it back)
		next = next.InsertPersist(prefix, newData)
	}

	// Atomically swap in the final table (only once for the entire batch)
	t.tableAtomicPtr.Store(next)

	return nil
}

// RemoveBatch removes multiple prefixes from the bart table in a single atomic operation.
// Returns a slice of pointers to successfully removed operations (nil for failures).
// This allows callers to access operation metadata (Origin, IPType, Scope) for metrics.
func (t *BartTrie) RemoveBatch(operations []BartRemoveOp) []*BartRemoveOp {
	if len(operations) == 0 {
		return nil
	}

	t.writeMutex.Lock()
	defer t.writeMutex.Unlock()

	// Get current table atomically
	cur := t.tableAtomicPtr.Load()

	// Process all operations, chaining the table updates
	next := cur
	results := make([]*BartRemoveOp, len(operations))
	for i, op := range operations {
		prefix := op.Prefix.Masked()

		// Only build logging fields if trace level is enabled
		var valueLog *log.Entry
		if t.logger.Logger.IsLevelEnabled(log.TraceLevel) {
			valueLog = t.logger.WithField("prefix", prefix.String()).WithField("remediation", op.R.String())
			valueLog.Trace("removing from bart trie")
		}

		// Check if exact prefix exists using DeletePersist (same pattern as AddBatch)
		// DeletePersist returns (newTable, value, found) - if found is true, the exact prefix existed
		var existingData RemediationIdsMap
		var exactPrefixExists bool
		next, existingData, exactPrefixExists = next.DeletePersist(prefix)
		if !exactPrefixExists {
			if valueLog != nil {
				valueLog.Trace("exact prefix not found")
			}
			results[i] = nil
			continue
		}

		// Clone existing data and remove the ID
		clonedData := existingData.Clone()
		err := clonedData.RemoveID(valueLog, op.R, op.ID)
		if err != nil {
			if valueLog != nil {
				valueLog.Trace("ID not found")
			}
			results[i] = nil
			// Re-insert the prefix since we deleted it to check for existence
			next = next.InsertPersist(prefix, existingData)
			continue
		}

		// ID was successfully removed - return pointer to the operation for metadata access
		// Use index to get pointer to original operation (safe since we don't modify the slice)
		results[i] = &operations[i]

		if clonedData.IsEmpty() {
			if valueLog != nil {
				valueLog.Trace("removed prefix entirely")
			}
			// Prefix is already deleted from DeletePersist above, no need to delete again
		} else {
			if valueLog != nil {
				valueLog.Trace("removed ID from existing prefix")
			}
			// Re-insert with modified data (we deleted it to check, now we add it back with updated data)
			next = next.InsertPersist(prefix, clonedData)
		}
	}

	// Atomically swap in the final table (only once for the entire batch)
	t.tableAtomicPtr.Store(next)

	return results
}

// Contains checks if an IP address matches any prefix in the bart table.
// Returns the longest matching prefix's remediation and origin.
// This method uses lock-free reads via atomic pointer for optimal performance.
func (t *BartTrie) Contains(ip netip.Addr) (remediation.Remediation, string) {
	// Lock-free read: atomically load the current table pointer
	table := t.tableAtomicPtr.Load()

	// Only build logging fields if trace level is enabled
	var valueLog *log.Entry
	if t.logger.Logger.IsLevelEnabled(log.TraceLevel) {
		valueLog = t.logger.WithField("ip", ip.String())
		valueLog.Trace("checking in bart trie")
	}

	// Use Lookup to get the longest prefix match
	data, found := table.Lookup(ip)
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
