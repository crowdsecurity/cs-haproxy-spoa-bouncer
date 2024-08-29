package dataset

import (
	"fmt"
	"net/netip"
	"slices"
	"sync"

	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
	log "github.com/sirupsen/logrus"
)

type RemediationIdsMap map[remediation.Remediation][]int64

func (rM *RemediationIdsMap) RemoveId(clog *log.Entry, r remediation.Remediation, id int64) error {
	ids, ok := (*rM)[r]
	if !ok {
		return fmt.Errorf("remediation %s not found", r.String())
	}
	index, ok := rM.ContainsId(r, id)
	if !ok {
		return fmt.Errorf("id %d not found", id)
	}
	clog.Debugf("removing id %d", id)
	if index < len(ids)-1 {
		(*rM)[r] = append(ids[:index], ids[index+1:]...)
	} else {
		(*rM)[r] = ids[:index]
	}

	if len((*rM)[r]) == 0 {
		clog.Debugf("removing empty remediation %s", r.String())
		delete(*rM, r)
	}

	return nil
}

func (rM *RemediationIdsMap) ContainsId(r remediation.Remediation, id int64) (int, bool) {
	if ids, ok := (*rM)[r]; ok {
		for i, v := range ids {
			if v == id {
				return i, true
			}
		}
	}
	return -1, false
}

func (rM *RemediationIdsMap) AddId(clog *log.Entry, r remediation.Remediation, id int64) {
	ids, ok := (*rM)[r]
	if !ok {
		clog.Debugf("remediation %s not found, creating", r.String())
		(*rM)[r] = []int64{id}
		return
	}
	clog.Debugf("remediation %s found, appending id %d", r.String(), id)
	(*rM)[r] = append(ids, id)
}

func (rM *RemediationIdsMap) GetRemediation() remediation.Remediation {
	keys := make([]remediation.Remediation, 0, len(*rM))
	for k := range *rM {
		keys = append(keys, k)
	}
	return slices.Max(keys)
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
	s.Items = make(map[T]RemediationIdsMap, 0)
	s.logger = log.WithField("alias", logAlias)
	s.logger.Debugf("initialized")
}

func (s *Set[T]) Add(item T, r remediation.Remediation, id int64) {
	s.Lock()
	defer s.Unlock()
	valueLog := s.logger.WithField("value", item).WithField("remediation", r.String())
	valueLog.Debug("adding")
	if v, ok := s.Items[item]; ok {
		valueLog.Debug("already exists")
		v.AddId(valueLog, r, id)
		return
	}
	valueLog.Debug("not found, creating new entry")
	s.Items[item] = map[remediation.Remediation][]int64{r: {id}}
}

func (s *Set[T]) Remove(item T, r remediation.Remediation, id int64) {
	s.Lock()
	defer s.Unlock()
	valueLog := s.logger.WithField("value", item).WithField("remediation", r.String())
	s.logger.Tracef("current items: %+v", s.Items)
	v, ok := s.Items[item]
	if !ok {
		valueLog.Error("not found")
		return
	}
	valueLog.Debug("found")

	if err := v.RemoveId(valueLog, r, id); err != nil {
		valueLog.Error(err)
		return
	}

	if len(s.Items[item]) == 0 {
		valueLog.Debugf("removing as it has no active remediations")
		delete(s.Items, item)
	}
}

func (s *PrefixSet) Contains(ip netip.Addr) remediation.Remediation {
	s.RLock()
	defer s.RUnlock()
	valueLog := s.logger.WithField("value", ip.String())
	valueLog.Debug("checking value")
	s.logger.Tracef("current items: %+v", s.Items)
	r := remediation.Allow
	for k, v := range s.Items {
		if k.Contains(ip) {
			prefixRemediation := v.GetRemediation()
			if prefixRemediation > r {
				r = prefixRemediation
			}
		}
	}
	valueLog.Debugf("remediation: %s", r.String())
	return r
}

func (s *IPSet) Contains(toCheck netip.Addr) remediation.Remediation {
	s.RLock()
	defer s.RUnlock()
	valueLog := s.logger.WithField("value", toCheck)
	valueLog.Debug("checking value")
	s.logger.Tracef("current items: %+v", s.Items)
	r := remediation.Allow
	if v, ok := s.Items[toCheck]; ok {
		valueLog.Debug("found")
		r = v.GetRemediation()
	}
	valueLog.Debugf("remediation: %s", r.String())
	return r
}

func (s *CNSet) Contains(toCheck string) remediation.Remediation {
	s.RLock()
	defer s.RUnlock()
	valueLog := s.logger.WithField("value", toCheck)
	valueLog.Debug("checking value")
	s.logger.Tracef("current items: %+v", s.Items)
	r := remediation.Allow
	if v, ok := s.Items[toCheck]; ok {
		valueLog.Debug("found")
		r = v.GetRemediation()
	}
	valueLog.Debugf("remediation: %s", r.String())
	return r
}
