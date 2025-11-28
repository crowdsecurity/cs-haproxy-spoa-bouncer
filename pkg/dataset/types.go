package dataset

import (
	"sync"
	"sync/atomic"

	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
	log "github.com/sirupsen/logrus"
)

// RemediationMap stores one origin string per remediation type.
// ID is not tracked since LAPI behavior ensures we only have the longest decision.
//
// LAPI behavior:
//   - Startup: Returns the longest duration decision for each IP
//   - Stream: Only returns NEW decisions if they're LONGER than current
//   - Deletions: Delete means user wants to allow the IP - just remove the remediation entry.
//     Duplicate deletes are safely ignored (entry already gone).
type RemediationMap map[remediation.Remediation]string

// Remove removes a remediation entry (deletion means user wants to allow the IP).
// If the remediation doesn't exist, returns nil (duplicate delete, safely ignored).
func (rM RemediationMap) Remove(clog *log.Entry, r remediation.Remediation) error {
	_, ok := rM[r]
	if !ok {
		// Remediation not found - duplicate delete, safely ignore
		if clog != nil && clog.Logger.IsLevelEnabled(log.TraceLevel) {
			clog.Tracef("remediation %s not found, ignoring duplicate delete", r.String())
		}
		return nil
	}
	if clog != nil && clog.Logger.IsLevelEnabled(log.TraceLevel) {
		clog.Tracef("removing remediation %s", r.String())
	}
	delete(rM, r)
	return nil
}

// Add adds or updates a decision for the given remediation type.
// If a decision already exists, it's overwritten (since only one decision per remediation+value).
func (rM RemediationMap) Add(clog *log.Entry, r remediation.Remediation, origin string) {
	if clog != nil && clog.Logger.IsLevelEnabled(log.TraceLevel) {
		if _, exists := rM[r]; exists {
			clog.Tracef("remediation %s found, updating", r.String())
		} else {
			clog.Tracef("remediation %s not found, creating", r.String())
		}
	}
	rM[r] = origin
}

// GetRemediationAndOrigin returns the highest priority remediation and its origin.
func (rM RemediationMap) GetRemediationAndOrigin() (remediation.Remediation, string) {
	var maxRemediation remediation.Remediation
	var maxOrigin string
	first := true

	for k, v := range rM {
		if first || k > maxRemediation {
			maxRemediation = k
			maxOrigin = v
			first = false
		}
	}

	return maxRemediation, maxOrigin
}

// IsEmpty returns true if the RemediationMap has no entries
func (rM RemediationMap) IsEmpty() bool {
	return len(rM) == 0
}

// Clone creates a shallow copy of the RemediationMap.
// This is required for bart's InsertPersist/DeletePersist operations
// which use structural typing to detect the Clone method.
// Since we only store strings (no pointers), shallow copy is sufficient.
func (rM RemediationMap) Clone() RemediationMap {
	if rM == nil {
		return make(RemediationMap)
	}
	cloned := make(RemediationMap, len(rM))
	for k, v := range rM {
		cloned[k] = v // String copy is cheap
	}
	return cloned
}

// cnItems is the internal map type for CNSet
type cnItems map[string]RemediationMap

// CNSet stores country code decisions with lock-free reads.
// Uses atomic pointer for the items map - SPOA handlers never block.
//
// Concurrency model:
// - Reads are completely lock-free (atomic pointer load)
// - Writes use copy-on-write (clone entire map, modify, swap)
type CNSet struct {
	items   atomic.Pointer[cnItems]
	writeMu sync.Mutex // Serializes write operations
	logger  *log.Entry
}

// NewCNSet creates a new CNSet for storing country code decisions
func NewCNSet(logAlias string) *CNSet {
	s := &CNSet{
		logger: log.WithField("alias", logAlias),
	}
	items := make(cnItems)
	s.items.Store(&items)
	s.logger.Tracef("initialized")
	return s
}

func (s *CNSet) Add(cn string, origin string, r remediation.Remediation) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	// Only build logging fields if trace level is enabled
	var valueLog *log.Entry
	if s.logger.Logger.IsLevelEnabled(log.TraceLevel) {
		valueLog = s.logger.WithField("value", cn).WithField("remediation", r.String())
		valueLog.Trace("adding")
	}

	// Clone the current map
	current := s.items.Load()
	if current == nil {
		// Defensive: should never happen with proper initialization
		current = &cnItems{}
	}
	newItems := make(cnItems, len(*current))
	for k, v := range *current {
		newItems[k] = v.Clone()
	}

	if v, ok := newItems[cn]; ok {
		if valueLog != nil {
			valueLog.Trace("already exists")
		}
		v.Add(valueLog, r, origin)
	} else {
		if valueLog != nil {
			valueLog.Trace("not found, creating new entry")
		}
		newItems[cn] = make(RemediationMap)
		newItems[cn].Add(valueLog, r, origin)
	}

	// Atomic swap - readers see old or new, never partial
	s.items.Store(&newItems)
}

func (s *CNSet) Remove(cn string, r remediation.Remediation) bool {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	// Only build logging fields if trace level is enabled
	var valueLog *log.Entry
	if s.logger.Logger.IsLevelEnabled(log.TraceLevel) {
		valueLog = s.logger.WithField("value", cn).WithField("remediation", r.String())
	}

	current := s.items.Load()
	if current == nil {
		if valueLog != nil {
			valueLog.Trace("not initialized")
		}
		return false
	}
	if _, ok := (*current)[cn]; !ok {
		if valueLog != nil {
			valueLog.Trace("value not found")
		}
		return false
	}
	if valueLog != nil {
		valueLog.Trace("found")
	}

	// Clone the current map
	newItems := make(cnItems, len(*current))
	for k, val := range *current {
		newItems[k] = val.Clone()
	}

	// Modify the cloned entry
	// Remove returns nil if remediation doesn't exist (duplicate delete, safely ignored)
	err := newItems[cn].Remove(valueLog, r)
	if err != nil {
		// Should never happen, but handle it gracefully
		if valueLog != nil {
			valueLog.Tracef("error removing: %v", err)
		}
		return false
	}

	if newItems[cn].IsEmpty() {
		if valueLog != nil {
			valueLog.Tracef("removing as it has no active remediations")
		}
		delete(newItems, cn)
	}

	// Atomic swap - readers see old or new, never partial
	s.items.Store(&newItems)
	return true
}

// Contains checks if a country code has a decision.
// This method is completely lock-free - SPOA handlers never block.
func (s *CNSet) Contains(toCheck string) (remediation.Remediation, string) {
	// Only build logging fields if trace level is enabled
	var valueLog *log.Entry
	if s.logger.Logger.IsLevelEnabled(log.TraceLevel) {
		valueLog = s.logger.WithField("value", toCheck)
		valueLog.Trace("checking value")
	}

	r := remediation.Allow
	origin := ""

	// Lock-free read via atomic pointer
	items := s.items.Load()
	if items != nil {
		if v, ok := (*items)[toCheck]; ok {
			if valueLog != nil {
				valueLog.Trace("found")
			}
			r, origin = v.GetRemediationAndOrigin()
		}
	}
	if valueLog != nil {
		valueLog.Tracef("remediation: %s", r.String())
	}
	return r, origin
}
