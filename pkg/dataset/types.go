package dataset

import (
	"fmt"
	"net"
	"slices"
	"sync"

	log "github.com/sirupsen/logrus"
)

// The order matters since we use slices.Max to get the max value
const (
	Allow   Remediation = -1
	Unknown Remediation = iota
	Captcha Remediation = iota
	Ban     Remediation = iota
)

type Remediation int

type RemediationWithId struct {
	Remediation Remediation
	Id          int64
}

func (r Remediation) String() string {
	switch r {
	case Ban:
		return "ban"
	case Captcha:
		return "captcha"
	case Unknown:
		return "unknown"
	default:
		return "allow"
	}
}

func RemedationFromString(s string) Remediation {
	switch s {
	case "ban":
		return Ban
	case "captcha":
		return Captcha
	case "allow":
		return Allow
	default:
		return Unknown
	}
}

type RemediationIdsMap map[Remediation][]int64

func (r *RemediationIdsMap) RemoveId(clog *log.Entry, remediation Remediation, id int64) error {
	ids, ok := (*r)[remediation]
	if !ok {
		return fmt.Errorf("remediation %s not found", remediation.String())
	}
	index, ok := r.ContainsId(remediation, id)
	if !ok {
		return fmt.Errorf("id %d not found", id)
	}
	clog.Debugf("removing id %d", id)
	if index < len(ids)-1 {
		(*r)[remediation] = append(ids[:index], ids[index+1:]...)
	} else {
		(*r)[remediation] = ids[:index]
	}

	if len((*r)[remediation]) == 0 {
		clog.Debugf("removing empty remediation %s", remediation.String())
		delete(*r, remediation)
	}

	return nil
}

func (r *RemediationIdsMap) ContainsId(remediation Remediation, id int64) (int, bool) {
	if ids, ok := (*r)[remediation]; ok {
		for i, v := range ids {
			if v == id {
				return i, true
			}
		}
	}
	return -1, false
}

func (r *RemediationIdsMap) AddId(clog *log.Entry, remediation Remediation, id int64) {
	ids, ok := (*r)[remediation]
	if !ok {
		clog.Debugf("remediation %s not found, creating", remediation.String())
		(*r)[remediation] = []int64{id}
		return
	}
	clog.Debugf("remediation %s found, appending id %d", remediation.String(), id)
	(*r)[remediation] = append(ids, id)
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

func (s *RangeSet) Add(cidr *net.IPNet, rid RemediationWithId) {
	valueLog := s.logger.WithField("value", cidr.String())
	valueLog.Debug("adding")
	defer s.Unlock()
	for i := range s.Items {
		if s.Items[i].CIDR.String() == cidr.String() {
			s.Lock()
			valueLog.Debug("already exists")
			s.Items[i].Remediations.AddId(valueLog, rid.Remediation, rid.Id)
			return
		}
	}
	s.Lock()
	valueLog.Debug("not found, creating new entry")
	s.Items = append(s.Items, struct {
		CIDR         *net.IPNet
		Remediations RemediationIdsMap
	}{CIDR: cidr, Remediations: map[Remediation][]int64{rid.Remediation: {rid.Id}}})
}

func (s *RangeSet) Remove(cidr *net.IPNet, rid RemediationWithId) {
	valueLog := s.logger.WithField("value", cidr.String())
	valueLog.Debugf("removing id: %d", rid.Id)
	for index, v := range s.Items {
		if v.CIDR.String() == cidr.String() {
			s.Lock()
			defer s.Unlock()
			valueLog.Debug("found")

			if err := v.Remediations.RemoveId(valueLog, rid.Remediation, rid.Id); err != nil {
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

func (s *RangeSet) Contains(ip *net.IP) Remediation {
	s.RLock()
	defer s.RUnlock()
	valueLog := s.logger.WithField("value", ip.String())
	valueLog.Debug("checking value")
	s.logger.Tracef("current items: %+v", s.Items)
	remediation := Allow
	keys := make([]Remediation, 0)
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
		remediation = slices.Max(keys)
	}
	valueLog.Debugf("remediation: %s", remediation.String())
	return remediation
}

func (s *StringSet) Init(logAlias string) {
	s.Items = make(map[string]RemediationIdsMap, 0)
	s.logger = log.WithField("type", "string").WithField("alias", logAlias)
	s.logger.Debugf("initialized")
}

func (s *StringSet) Add(toAdd string, rid RemediationWithId) {
	s.Lock()
	defer s.Unlock()
	valueLog := s.logger.WithField("value", toAdd)
	valueLog.Debug("adding")
	s.logger.Tracef("current items: %+v", s.Items)
	if v, ok := s.Items[toAdd]; ok {
		valueLog.Debug("already exists")
		v.AddId(valueLog, rid.Remediation, rid.Id)
		return
	}
	valueLog.Debug("not found, creating new entry")
	s.Items[toAdd] = map[Remediation][]int64{rid.Remediation: {rid.Id}}
}

func (s *StringSet) Remove(toRemove string, rid RemediationWithId) {
	s.Lock()
	defer s.Unlock()
	valueLog := s.logger.WithField("value", toRemove)
	valueLog.Debugf("removing id: %d", rid.Id)
	s.logger.Tracef("current items: %+v", s.Items)
	v, ok := s.Items[toRemove]
	if !ok {
		valueLog.Error("not found")
		return
	}
	valueLog.Debug("found")

	if err := v.RemoveId(valueLog, rid.Remediation, rid.Id); err != nil {
		valueLog.Error(err)
		return
	}

	if len(s.Items[toRemove]) == 0 {
		valueLog.Debugf("removing as it has no active remediations")
		delete(s.Items, toRemove)
	}
}

func (s *StringSet) Contains(toCheck string) Remediation {
	s.RLock()
	defer s.RUnlock()
	valueLog := s.logger.WithField("value", toCheck)
	valueLog.Debug("checking value")
	s.logger.Tracef("current items: %+v", s.Items)
	remediation := Allow
	if v, ok := s.Items[toCheck]; ok {
		valueLog.Debug("found")
		keys := make([]Remediation, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		remediation = slices.Max(keys)
	}
	valueLog.Debugf("remediation: %s", remediation.String())
	return remediation
}
