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

// BartRangeSet provides a unified interface for IP and CIDR operations using bart library.
// Uses atomic pointer for lock-free reads and mutex-protected writes
// following the pattern recommended in bart's documentation.
type BartRangeSet struct {
	tableAtomicPtr atomic.Pointer[bart.Table[RemediationMap]]
	writeMutex     sync.Mutex // Protects writers only
	logger         *log.Entry
}

// NewBartRangeSet creates a new BartRangeSet
// The table starts as nil and will be created on first use for better memory efficiency
// Initialize with nil; the table will be allocated during the first AddBatch operation.
// This approach enables using Insert for the initial table population, which is more memory efficient than incremental updates.
func NewBartRangeSet(logAlias string) *BartRangeSet {
	return &BartRangeSet{
		logger: log.WithField("alias", logAlias),
	}
}

// AddBatch adds multiple prefixes to the bart table in a single atomic operation.
// This is much more efficient than calling Add() multiple times, as it only
// swaps the atomic pointer once at the end instead of once per prefix.
// For the initial load (when table is nil), uses Insert for better memory efficiency.
// For subsequent updates, uses ModifyPersist for incremental changes.
// All operations always succeed (duplicates are merged, new entries are created).
func (s *BartRangeSet) AddBatch(operations []BartAddOp) {
	if len(operations) == 0 {
		return
	}

	s.writeMutex.Lock()
	defer s.writeMutex.Unlock()

	// Get current table atomically
	cur := s.tableAtomicPtr.Load()

	// Check if this is the initial load (table is nil)
	if cur == nil {
		s.initializeBatch(operations)
		return
	}

	// Table already exists - use ModifyPersist for incremental updates
	s.updateBatch(cur, operations)
}

// initializeBatch creates a new table and initializes it with the given operations using Insert.
// This is more memory efficient than using ModifyPersist for the initial load.
// Handles duplicate prefixes by merging remediations before inserting.
// All operations always succeed.
func (s *BartRangeSet) initializeBatch(operations []BartAddOp) {
	// Create a new table for the initial load
	next := &bart.Table[RemediationMap]{}

	// First, collect all operations by prefix to handle duplicates
	prefixMap := make(map[netip.Prefix]RemediationMap)
	for _, op := range operations {
		prefix := op.Prefix.Masked()

		// Only build logging fields if trace level is enabled
		var valueLog *log.Entry
		if s.logger.Logger.IsLevelEnabled(log.TraceLevel) {
			valueLog = s.logger.WithField("prefix", prefix.String()).WithField("remediation", op.R.String())
			valueLog.Trace("initial load: collecting prefix operations")
		}

		// Get or create the data for this prefix
		data, exists := prefixMap[prefix]
		if !exists {
			data = RemediationMap{}
		}
		// Add the remediation (this handles merging if prefix already seen)
		data.Add(valueLog, op.R, op.Origin)
		prefixMap[prefix] = data
	}

	// Now insert all unique prefixes using Insert
	for prefix, data := range prefixMap {
		// Only build logging fields if trace level is enabled
		var valueLog *log.Entry
		if s.logger.Logger.IsLevelEnabled(log.TraceLevel) {
			valueLog = s.logger.WithField("prefix", prefix.String())
			valueLog.Trace("initial load: inserting into bart trie")
		}

		// Use Insert for initial load - more memory efficient than ModifyPersist
		next.Insert(prefix, data)
	}

	// Atomically swap in the new table
	s.tableAtomicPtr.Store(next)
}

// updateBatch updates an existing table with the given operations using ModifyPersist.
// This handles incremental updates efficiently.
// All operations always succeed.
func (s *BartRangeSet) updateBatch(cur *bart.Table[RemediationMap], operations []BartAddOp) {
	// Process all operations, chaining the table updates
	next := cur
	for _, op := range operations {
		prefix := op.Prefix.Masked()

		// Only build logging fields if trace level is enabled
		var valueLog *log.Entry
		if s.logger.Logger.IsLevelEnabled(log.TraceLevel) {
			valueLog = s.logger.WithField("prefix", prefix.String()).WithField("remediation", op.R.String())
			valueLog.Trace("adding to bart trie")
		}

		// Use ModifyPersist to atomically update or create the prefix entry
		// This is more efficient than DeletePersist + InsertPersist as it only traverses once
		next, _, _ = next.ModifyPersist(prefix, func(existingData RemediationMap, exists bool) (RemediationMap, bool) {
			if exists {
				if valueLog != nil {
					valueLog.Trace("exact prefix exists, merging remediations")
				}
				// bart already cloned via our Cloner interface, modify directly
				existingData.Add(valueLog, op.R, op.Origin)
				return existingData, false // false = don't delete
			}
			if valueLog != nil {
				valueLog.Trace("creating new entry")
			}
			// Create new data
			newData := make(RemediationMap)
			newData.Add(valueLog, op.R, op.Origin)
			return newData, false // false = don't delete
		})
	}

	// Atomically swap in the final table (only once for the entire batch)
	s.tableAtomicPtr.Store(next)
}

// RemoveBatch removes multiple prefixes from the bart table in a single atomic operation.
// Returns a slice of pointers to successfully removed operations (nil for failures).
// This allows callers to access operation metadata (Origin, IPType, Scope) for metrics.
// IPs should be converted to /32 or /128 prefixes before calling this method.
func (s *BartRangeSet) RemoveBatch(operations []BartRemoveOp) []*BartRemoveOp {
	if len(operations) == 0 {
		return nil
	}

	s.writeMutex.Lock()
	defer s.writeMutex.Unlock()

	// Get current table atomically
	cur := s.tableAtomicPtr.Load()

	// If table is nil, nothing to remove - return all nil results
	if cur == nil {
		return make([]*BartRemoveOp, len(operations))
	}

	// Process all operations, chaining the table updates
	next := cur
	results := make([]*BartRemoveOp, len(operations))
	for i, op := range operations {
		prefix := op.Prefix.Masked()

		// Only build logging fields if trace level is enabled
		var valueLog *log.Entry
		if s.logger.Logger.IsLevelEnabled(log.TraceLevel) {
			valueLog = s.logger.WithField("prefix", prefix.String()).WithField("remediation", op.R.String())
			valueLog.Trace("removing from bart trie")
		}

		// Use ModifyPersist to atomically update or remove the prefix entry
		// This is more efficient than DeletePersist + InsertPersist as it only traverses once
		next, _, _ = next.ModifyPersist(prefix, func(existingData RemediationMap, exists bool) (RemediationMap, bool) {
			if !exists {
				if valueLog != nil {
					valueLog.Trace("exact prefix not found")
				}
				results[i] = nil
				return existingData, false // false = don't delete (prefix doesn't exist anyway)
			}

			// bart already cloned via our Cloner interface, modify directly
			// Remove returns nil if remediation doesn't exist (duplicate delete, safely ignored)
			err := existingData.Remove(valueLog, op.R)
			if err != nil {
				// Should never happen, but handle it gracefully
				if valueLog != nil {
					valueLog.Tracef("error removing: %v", err)
				}
				results[i] = nil
				return existingData, false // false = don't delete, keep data unchanged
			}

			// ID was successfully removed - return pointer to the operation for metadata access
			// Use index to get pointer to original operation (safe since we don't modify the slice)
			results[i] = &operations[i]

			if existingData.IsEmpty() {
				if valueLog != nil {
					valueLog.Trace("removed prefix entirely")
				}
				return existingData, true // true = delete the prefix (it's now empty)
			}
			if valueLog != nil {
				valueLog.Trace("removed remediation from existing prefix")
			}
			return existingData, false // false = don't delete, keep modified data
		})
	}

	// Atomically swap in the final table (only once for the entire batch)
	s.tableAtomicPtr.Store(next)

	return results
}

// Contains checks if an IP address matches any prefix in the bart table.
// Returns the longest matching prefix's remediation and origin.
// This method uses lock-free reads via atomic pointer for optimal performance.
func (s *BartRangeSet) Contains(ip netip.Addr) (remediation.Remediation, string) {
	// Lock-free read: atomically load the current table pointer
	table := s.tableAtomicPtr.Load()

	// Check for nil table (not yet initialized)
	if table == nil {
		return remediation.Allow, ""
	}

	// Only build logging fields if trace level is enabled
	var valueLog *log.Entry
	if s.logger.Logger.IsLevelEnabled(log.TraceLevel) {
		valueLog = s.logger.WithField("ip", ip.String())
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
