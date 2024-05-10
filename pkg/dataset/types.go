package dataset

import (
	"fmt"
	"net"
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

type StringSet struct {
	sync.RWMutex
	Items  map[string]RemediationIdsMap
	logger *log.Entry
}

type RangeSet struct {
	sync.RWMutex
	Items []struct {
		CIDR         *net.IPNet
		Remediations RemediationIdsMap
	}
	logger *log.Entry
}

type CIDRSet struct {
	RangeSet
}

type IPSet struct {
	StringSet
}

type CNSet struct {
	StringSet
}

func (s *RangeSet) Init(logAlias string) {
	s.Items = make([]struct {
		CIDR         *net.IPNet
		Remediations RemediationIdsMap
	}, 0)
	s.logger = log.WithField("type", "range").WithField("alias", logAlias)
	s.logger.Debugf("initialized")
}

func (s *RangeSet) Add(cidr *net.IPNet, r remediation.Remediation, id int64) {
	valueLog := s.logger.WithField("value", cidr.String())
	valueLog.Debug("adding")
	defer s.Unlock()
	for i := range s.Items {
		if s.Items[i].CIDR.String() == cidr.String() {
			s.Lock()
			valueLog.Debug("already exists")
			s.Items[i].Remediations.AddId(valueLog, r, id)
			return
		}
	}
	s.Lock()
	valueLog.Debug("not found, creating new entry")
	s.Items = append(s.Items, struct {
		CIDR         *net.IPNet
		Remediations RemediationIdsMap
	}{CIDR: cidr, Remediations: map[remediation.Remediation][]int64{r: {id}}})
}

func (s *RangeSet) Remove(cidr *net.IPNet, r remediation.Remediation, id int64) {
	valueLog := s.logger.WithField("value", cidr.String())
	valueLog.Debugf("removing id: %d", id)
	for index, v := range s.Items {
		if v.CIDR.String() == cidr.String() {
			s.Lock()
			defer s.Unlock()
			valueLog.Debug("found")

			if err := v.Remediations.RemoveId(valueLog, r, id); err != nil {
				valueLog.Error(err)
				return
			}

			if len(v.Remediations) == 0 {
				valueLog.Debug("removing as it has no active remediations")
				if index < len(s.Items)-1 {
					s.Items = append(s.Items[:index], s.Items[index+1:]...)
				} else {
					s.Items = s.Items[:index]
				}
			}
			return
		}
	}
	valueLog.Error("not found")
}

func (s *RangeSet) Contains(ip *net.IP) remediation.Remediation {
	s.RLock()
	defer s.RUnlock()
	valueLog := s.logger.WithField("value", ip.String())
	valueLog.Debug("checking value")
	s.logger.Tracef("current items: %+v", s.Items)
	r := remediation.Allow
	keys := make([]remediation.Remediation, 0)
	for _, v := range s.Items {
		if v.CIDR.Contains(*ip) {
			valueLog.Debugf("value matches CIDR: %s", v.CIDR.String())
			// Loop over all remediations
			for k := range v.Remediations {
				keys = append(keys, k)
			}
		}
	}
	if len(keys) > 0 {
		r = slices.Max(keys)
	}
	valueLog.Debugf("remediation: %s", r.String())
	return r
}

func (s *StringSet) Init(logAlias string) {
	s.Items = make(map[string]RemediationIdsMap, 0)
	s.logger = log.WithField("type", "string").WithField("alias", logAlias)
	s.logger.Debugf("initialized")
}

func (s *StringSet) Add(toAdd string, r remediation.Remediation, id int64) {
	s.Lock()
	defer s.Unlock()
	valueLog := s.logger.WithField("value", toAdd)
	valueLog.Debug("adding")
	s.logger.Tracef("current items: %+v", s.Items)
	if v, ok := s.Items[toAdd]; ok {
		valueLog.Debug("already exists")
		v.AddId(valueLog, r, id)
		return
	}
	valueLog.Debug("not found, creating new entry")
	s.Items[toAdd] = map[remediation.Remediation][]int64{r: {id}}
}

func (s *StringSet) Remove(toRemove string, r remediation.Remediation, id int64) {
	s.Lock()
	defer s.Unlock()
	valueLog := s.logger.WithField("value", toRemove)
	valueLog.Debugf("removing id: %d", id)
	s.logger.Tracef("current items: %+v", s.Items)
	v, ok := s.Items[toRemove]
	if !ok {
		valueLog.Error("not found")
		return
	}
	valueLog.Debug("found")

	if err := v.RemoveId(valueLog, r, id); err != nil {
		valueLog.Error(err)
		return
	}

	if len(s.Items[toRemove]) == 0 {
		valueLog.Debugf("removing as it has no active remediations")
		delete(s.Items, toRemove)
	}
}

func (s *StringSet) Contains(toCheck string) remediation.Remediation {
	s.RLock()
	defer s.RUnlock()
	valueLog := s.logger.WithField("value", toCheck)
	valueLog.Debug("checking value")
	s.logger.Tracef("current items: %+v", s.Items)
	r := remediation.Allow
	if v, ok := s.Items[toCheck]; ok {
		valueLog.Debug("found")
		keys := make([]remediation.Remediation, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		r = slices.Max(keys)
	}
	valueLog.Debugf("remediation: %s", r.String())
	return r
}
