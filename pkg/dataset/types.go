package dataset

import (
	"fmt"
	"net/netip"
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
	clog.Tracef("removing id %d", id)
	// Optimize removal: swap with last element and truncate (order doesn't matter for RemediationDetails)
	lastIndex := len(ids) - 1
	if index != lastIndex {
		ids[index] = ids[lastIndex]
	}
	(*rM)[r] = ids[:lastIndex]

	if len((*rM)[r]) == 0 {
		clog.Tracef("removing empty remediation %s", r.String())
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
	ids, ok := (*rM)[r]
	if !ok {
		clog.Tracef("remediation %s not found, creating", r.String())
		(*rM)[r] = []RemediationDetails{{id, origin}}
		return
	}
	clog.Tracef("remediation %s found, appending id %d", r.String(), id)
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

type Set[T string | netip.Prefix | netip.Addr] struct {
	sync.RWMutex

	Items  map[T]RemediationIdsMap
	logger *log.Entry
}

type PrefixSet struct {
	Set[netip.Prefix]
}

type IPSet struct {
	Set[netip.Addr]
}

type CNSet struct {
	Set[string]
}

func (s *Set[T]) Init(logAlias string) {
	s.Items = make(map[T]RemediationIdsMap)
	s.logger = log.WithField("alias", logAlias)
	s.logger.Tracef("initialized")
}

func (s *Set[T]) Add(item T, origin string, r remediation.Remediation, id int64) {
	s.Lock()
	defer s.Unlock()
	valueLog := s.logger.WithField("value", item).WithField("remediation", r.String())
	valueLog.Trace("adding")
	if v, ok := s.Items[item]; ok {
		valueLog.Trace("already exists")
		v.AddID(valueLog, r, id, origin)
		return
	}
	valueLog.Trace("not found, creating new entry")
	s.Items[item] = RemediationIdsMap{r: []RemediationDetails{{id, origin}}}
}

func (s *Set[T]) Remove(item T, r remediation.Remediation, id int64) bool {
	s.Lock()
	defer s.Unlock()
	valueLog := s.logger.WithField("value", item).WithField("remediation", r.String())
	v, ok := s.Items[item]
	if !ok {
		valueLog.Trace("value not found")
		return false
	}
	valueLog.Trace("found")

	if err := v.RemoveID(valueLog, r, id); err != nil {
		valueLog.Error(err)
		return false
	}

	if len(s.Items[item]) == 0 {
		valueLog.Tracef("removing as it has no active remediations")
		delete(s.Items, item)
	}
	return true
}

func (s *PrefixSet) Contains(ip netip.Addr) (remediation.Remediation, string) {
	s.RLock()
	defer s.RUnlock()
	valueLog := s.logger.WithField("value", ip.String())
	valueLog.Trace("checking value")
	r := remediation.Allow
	origin := ""
	for k, v := range s.Items {
		if k.Contains(ip) {
			prefixRemediation, prefixOrigin := v.GetRemediationAndOrigin()
			if prefixRemediation > r {
				r = prefixRemediation
				origin = prefixOrigin
			}
		}
	}
	valueLog.Tracef("remediation: %s", r.String())
	return r, origin
}

func (s *IPSet) Contains(toCheck netip.Addr) (remediation.Remediation, string) {
	s.RLock()
	defer s.RUnlock()
	valueLog := s.logger.WithField("value", toCheck)
	valueLog.Trace("checking value")
	r := remediation.Allow
	origin := ""
	if v, ok := s.Items[toCheck]; ok {
		valueLog.Trace("found")
		r, origin = v.GetRemediationAndOrigin()
	}
	valueLog.Tracef("remediation: %s", r.String())
	return r, origin
}

func (s *CNSet) Contains(toCheck string) (remediation.Remediation, string) {
	s.RLock()
	defer s.RUnlock()
	valueLog := s.logger.WithField("value", toCheck)
	valueLog.Trace("checking value")
	r := remediation.Allow
	origin := ""

	if v, ok := s.Items[toCheck]; ok {
		valueLog.Trace("found")
		r, origin = v.GetRemediationAndOrigin()
	}
	valueLog.Tracef("remediation: %s", r.String())
	return r, origin
}
