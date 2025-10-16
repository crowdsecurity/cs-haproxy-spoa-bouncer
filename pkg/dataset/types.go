package dataset

import (
	"fmt"
	"sync"

	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
	log "github.com/sirupsen/logrus"
)

type RemediationDetails struct {
	ID     int64
	Origin string
}

type RemediationIdsMap map[remediation.Remediation][]RemediationDetails

func (rM *RemediationIdsMap) RemoveID(clog *log.Entry, r remediation.Remediation, id int64) error {
	ids, ok := (*rM)[r]
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
	(*rM)[r] = ids[:lastIndex]

	if len((*rM)[r]) == 0 {
		if clog != nil && clog.Logger.IsLevelEnabled(log.TraceLevel) {
			clog.Tracef("removing empty remediation %s", r.String())
		}
		delete(*rM, r)
	}

	return nil
}

func (rM *RemediationIdsMap) ContainsID(r remediation.Remediation, id int64) (int, bool) {
	if details, ok := (*rM)[r]; ok {
		for i, v := range details {
			if v.ID == id {
				return i, true
			}
		}
	}
	return -1, false
}

func (rM *RemediationIdsMap) AddID(clog *log.Entry, r remediation.Remediation, id int64, origin string) {
	// Initialize map if nil
	if *rM == nil {
		*rM = make(RemediationIdsMap, 1) // Pre-allocate for 1 remediation type
	}

	ids, ok := (*rM)[r]
	if !ok {
		if clog != nil && clog.Logger.IsLevelEnabled(log.TraceLevel) {
			clog.Tracef("remediation %s not found, creating", r.String())
		}
		// Pre-allocate slice with capacity for multiple IDs per remediation
		(*rM)[r] = make([]RemediationDetails, 0, 4) // Start with capacity 4
		(*rM)[r] = append((*rM)[r], RemediationDetails{id, origin})
		return
	}
	if clog != nil && clog.Logger.IsLevelEnabled(log.TraceLevel) {
		clog.Tracef("remediation %s found, appending id %d", r.String(), id)
	}
	(*rM)[r] = append(ids, RemediationDetails{id, origin})
}

func (rM *RemediationIdsMap) GetRemediationAndOrigin() (remediation.Remediation, string) {
	// Optimize: find max directly without allocating slice
	var maxRemediation remediation.Remediation
	var maxOrigin string
	first := true

	for k, v := range *rM {
		if first || k > maxRemediation {
			maxRemediation = k
			maxOrigin = v[0].Origin // We can use [0] here as crowdsec cannot return multiple decisions for the same remediation AND value
			first = false
		}
	}

	return maxRemediation, maxOrigin
}

// IsEmpty returns true if the RemediationIdsMap has no entries
func (rM *RemediationIdsMap) IsEmpty() bool {
	return len(*rM) == 0
}

type CNSet struct {
	sync.RWMutex
	Items  map[string]RemediationIdsMap
	logger *log.Entry
}

func (s *CNSet) Init(logAlias string) {
	s.Items = make(map[string]RemediationIdsMap)
	s.logger = log.WithField("alias", logAlias)
	s.logger.Tracef("initialized")
}

func (s *CNSet) Add(cn string, origin string, r remediation.Remediation, id int64) {
	s.Lock()
	defer s.Unlock()

	// Only build logging fields if trace level is enabled
	var valueLog *log.Entry
	if s.logger.Logger.IsLevelEnabled(log.TraceLevel) {
		valueLog = s.logger.WithField("value", cn).WithField("remediation", r.String())
		valueLog.Trace("adding")
	}

	if v, ok := s.Items[cn]; ok {
		if valueLog != nil {
			valueLog.Trace("already exists")
		}
		v.AddID(valueLog, r, id, origin)
		return
	}
	if valueLog != nil {
		valueLog.Trace("not found, creating new entry")
	}
	s.Items[cn] = RemediationIdsMap{r: []RemediationDetails{{id, origin}}}
}

func (s *CNSet) Remove(cn string, r remediation.Remediation, id int64) bool {
	s.Lock()
	defer s.Unlock()

	// Only build logging fields if trace level is enabled
	var valueLog *log.Entry
	if s.logger.Logger.IsLevelEnabled(log.TraceLevel) {
		valueLog = s.logger.WithField("value", cn).WithField("remediation", r.String())
	}

	v, ok := s.Items[cn]
	if !ok {
		if valueLog != nil {
			valueLog.Trace("value not found")
		}
		return false
	}
	if valueLog != nil {
		valueLog.Trace("found")
	}

	if err := v.RemoveID(valueLog, r, id); err != nil {
		if valueLog != nil {
			valueLog.Error(err)
		}
		return false
	}

	if len(s.Items[cn]) == 0 {
		if valueLog != nil {
			valueLog.Tracef("removing as it has no active remediations")
		}
		delete(s.Items, cn)
	}
	return true
}

func (s *CNSet) Contains(toCheck string) (remediation.Remediation, string) {
	s.RLock()
	defer s.RUnlock()

	// Only build logging fields if trace level is enabled
	var valueLog *log.Entry
	if s.logger.Logger.IsLevelEnabled(log.TraceLevel) {
		valueLog = s.logger.WithField("value", toCheck)
		valueLog.Trace("checking value")
	}

	r := remediation.Allow
	origin := ""

	if v, ok := s.Items[toCheck]; ok {
		if valueLog != nil {
			valueLog.Trace("found")
		}
		r, origin = v.GetRemediationAndOrigin()
	}
	if valueLog != nil {
		valueLog.Tracef("remediation: %s", r.String())
	}
	return r, origin
}
