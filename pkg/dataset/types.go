package dataset

import (
	"net"
	"slices"
	"sync"

	log "github.com/sirupsen/logrus"
)

// The order matters since we use slices.Max to get the max value
const (
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
	default:
		return "unknown"
	}
}

func RemedationFromString(s string) Remediation {
	switch s {
	case "ban":
		return Ban
	case "captcha":
		return Captcha
	default:
		return Unknown
	}
}

type StringSet struct {
	sync.RWMutex
	Items  map[string]map[Remediation][]int64
	logger *log.Entry
}

type RangeSet struct {
	sync.RWMutex
	Items []struct {
		CIDR         *net.IPNet
		Remediations map[Remediation][]int64
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
		Remediations map[Remediation][]int64
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
			if _, ok := s.Items[i].Remediations[rid.Remediation]; ok {
				valueLog.Debugf("already has %s appending id", rid.Remediation.String())
				s.Items[i].Remediations[rid.Remediation] = append(s.Items[i].Remediations[rid.Remediation], rid.Id)
				return
			}
			valueLog.Debugf("does not have %s creating and adding id", rid.Remediation.String())
			s.Items[i].Remediations[rid.Remediation] = []int64{rid.Id}
			return
		}
	}
	s.Lock()
	valueLog.Debug("not found, creating new entry")
	s.Items = append(s.Items, struct {
		CIDR         *net.IPNet
		Remediations map[Remediation][]int64
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
			ids, ok := v.Remediations[rid.Remediation]
			if !ok {
				valueLog.Errorf("remediation %s not found", rid.Remediation.String())
				return
			}
			for i, id := range ids {
				if id == rid.Id {
					valueLog.Debugf("found id %d", rid.Id)
					if i < len(ids)-1 {
						v.Remediations[rid.Remediation] = append(ids[:i], ids[i+1:]...)
					} else {
						v.Remediations[rid.Remediation] = ids[:i]
					}
					break
				}
			}
			if len(v.Remediations[rid.Remediation]) == 0 {
				valueLog.Debugf("removing empty remediation %s", rid.Remediation.String())
				delete(v.Remediations, rid.Remediation)
			}
			if len(v.Remediations) == 0 {
				valueLog.Debug("removing as it has no remediations")
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
	remediation := Unknown
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
	s.Items = make(map[string]map[Remediation][]int64, 0)
	s.logger = log.WithField("type", "string").WithField("alias", logAlias)
	s.logger.Debugf("initialized")
}

func (s *StringSet) Add(toAdd string, rid RemediationWithId) {
	s.Lock()
	defer s.Unlock()
	valueLog := s.logger.WithField("value", toAdd)
	valueLog.Debug("adding")
	s.logger.Tracef("current items: %+v", s.Items)
	if _, ok := s.Items[toAdd]; ok {
		valueLog.Debug("already exists")
		if _, ok := s.Items[toAdd][rid.Remediation]; ok {
			valueLog.Debugf("already has %s appending id", rid.Remediation.String())
			s.Items[toAdd][rid.Remediation] = append(s.Items[toAdd][rid.Remediation], rid.Id)
			return
		}
		valueLog.Debugf("does not have %s creating and adding id", rid.Remediation.String())
		s.Items[toAdd][rid.Remediation] = []int64{rid.Id}
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
	ids, ok := v[rid.Remediation]
	if !ok {
		valueLog.Errorf("remediation %s not found", rid.Remediation.String())
		return
	}
	for i, id := range ids {
		if id == rid.Id {
			valueLog.Debugf("found id %d", rid.Id)
			if i < len(ids)-1 {
				s.Items[toRemove][rid.Remediation] = append(ids[:i], ids[i+1:]...)
			} else {
				s.Items[toRemove][rid.Remediation] = ids[:i]
			}
			break
		}
	}
	if len(s.Items[toRemove][rid.Remediation]) == 0 {
		valueLog.Debugf("removing empty remediation %s", rid.Remediation.String())
		delete(s.Items[toRemove], rid.Remediation)
	}
	if len(s.Items[toRemove]) == 0 {
		valueLog.Debugf("removing as it has no remediations")
		delete(s.Items, toRemove)
	}
}

func (s *StringSet) Contains(toCheck string) Remediation {
	s.RLock()
	defer s.RUnlock()
	valueLog := s.logger.WithField("value", toCheck)
	valueLog.Debug("checking value")
	s.logger.Tracef("current items: %+v", s.Items)
	remediation := Unknown
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
