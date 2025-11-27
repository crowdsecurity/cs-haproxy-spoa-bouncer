package dataset

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
	log "github.com/sirupsen/logrus"
)

type RemediationDetails struct {
	ID     int64
	Origin string
}

type RemediationIdsMap map[remediation.Remediation][]RemediationDetails

func (rM RemediationIdsMap) RemoveID(clog *log.Entry, r remediation.Remediation, id int64) error {
	ids, ok := rM[r]
	if !ok {
		return fmt.Errorf("remediation %s not found", r.String())
	}
	index, ok := rM.ContainsID(r, id)
	if !ok {
		return fmt.Errorf("id %d not found", id)
	}
	if clog != nil && clog.Logger.IsLevelEnabled(log.TraceLevel) {
		clog.Tracef("removing id %d", id)
	}
	// Optimize removal: swap with last element and truncate (order doesn't matter for RemediationDetails)
	lastIndex := len(ids) - 1
	if index != lastIndex {
		ids[index] = ids[lastIndex]
	}
	rM[r] = ids[:lastIndex]

	if len(rM[r]) == 0 {
		if clog != nil && clog.Logger.IsLevelEnabled(log.TraceLevel) {
			clog.Tracef("removing empty remediation %s", r.String())
		}
		delete(rM, r)
	}

	return nil
}

func (rM RemediationIdsMap) ContainsID(r remediation.Remediation, id int64) (int, bool) {
	if details, ok := rM[r]; ok {
		for i, v := range details {
			if v.ID == id {
				return i, true
			}
		}
	}
	return -1, false
}

func (rM RemediationIdsMap) AddID(clog *log.Entry, r remediation.Remediation, id int64, origin string) {
	ids, ok := rM[r]
	if !ok {
		if clog != nil && clog.Logger.IsLevelEnabled(log.TraceLevel) {
			clog.Tracef("remediation %s not found, creating", r.String())
		}
		// Pre-allocate slice with capacity for multiple IDs per remediation
		rM[r] = []RemediationDetails{{id, origin}}
		return
	}
	if clog != nil && clog.Logger.IsLevelEnabled(log.TraceLevel) {
		clog.Tracef("remediation %s found, appending id %d", r.String(), id)
	}
	rM[r] = append(ids, RemediationDetails{id, origin})
}

func (rM RemediationIdsMap) GetRemediationAndOrigin() (remediation.Remediation, string) {
	// Optimize: find max directly without allocating slice
	var maxRemediation remediation.Remediation
	var maxOrigin string
	first := true

	for k, v := range rM {
		if len(v) == 0 {
			continue // Skip empty slices (defensive check)
		}
		if first || k > maxRemediation {
			maxRemediation = k
			maxOrigin = v[0].Origin // We can use [0] here as crowdsec cannot return multiple decisions for the same remediation AND value
			first = false
		}
	}

	return maxRemediation, maxOrigin
}

// IsEmpty returns true if the RemediationIdsMap has no entries
func (rM RemediationIdsMap) IsEmpty() bool {
	return len(rM) == 0
}

// Clone creates a deep copy of the RemediationIdsMap.
// This is required for bart's InsertPersist/DeletePersist operations
// which use structural typing to detect the Clone method.
func (rM RemediationIdsMap) Clone() RemediationIdsMap {
	if rM == nil {
		return make(RemediationIdsMap)
	}
	cloned := make(RemediationIdsMap, len(rM))
	for k, v := range rM {
		// Deep copy the slice
		clonedSlice := make([]RemediationDetails, len(v))
		copy(clonedSlice, v)
		cloned[k] = clonedSlice
	}
	return cloned
}

// cnItems is the internal map type for CNSet
type cnItems map[string]RemediationIdsMap

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

func (s *CNSet) Add(cn string, origin string, r remediation.Remediation, id int64) {
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
	newItems := make(cnItems, len(*current)+1)
	for k, v := range *current {
		newItems[k] = v.Clone()
	}

	if v, ok := newItems[cn]; ok {
		if valueLog != nil {
			valueLog.Trace("already exists")
		}
		v.AddID(valueLog, r, id, origin)
	} else {
		if valueLog != nil {
			valueLog.Trace("not found, creating new entry")
		}
		newItems[cn] = RemediationIdsMap{r: []RemediationDetails{{id, origin}}}
	}

	// Atomic swap - readers see old or new, never partial
	s.items.Store(&newItems)
}

func (s *CNSet) Remove(cn string, r remediation.Remediation, id int64) bool {
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
	if err := newItems[cn].RemoveID(valueLog, r, id); err != nil {
		if valueLog != nil {
			valueLog.Error(err)
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
