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
	Items map[string]map[Remediation][]int64
}

type RangeSet struct {
	sync.RWMutex
	Items []struct {
		CIDR         *net.IPNet
		Remediations map[Remediation][]int64
	}
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

func (s *RangeSet) Init() {
	s.Items = make([]struct {
		CIDR         *net.IPNet
		Remediations map[Remediation][]int64
	}, 0)
}

func (s *RangeSet) Add(cidr *net.IPNet, rid RemediationWithId) {
	defer s.Unlock()
	for i := range s.Items {
		if s.Items[i].CIDR.String() == cidr.String() {
			s.Lock()
			if _, ok := s.Items[i].Remediations[rid.Remediation]; ok {
				s.Items[i].Remediations[rid.Remediation] = append(s.Items[i].Remediations[rid.Remediation], rid.Id)
				return
			}
			s.Items[i].Remediations[rid.Remediation] = []int64{rid.Id}
			return
		}
	}
	s.Lock()
	s.Items = append(s.Items, struct {
		CIDR         *net.IPNet
		Remediations map[Remediation][]int64
	}{CIDR: cidr, Remediations: map[Remediation][]int64{rid.Remediation: {rid.Id}}})
}

func (s *RangeSet) Remove(cidr *net.IPNet, rid RemediationWithId) {
	for index, v := range s.Items {
		if v.CIDR.String() == cidr.String() {
			s.Lock()
			defer s.Unlock()
			if ids, ok := v.Remediations[rid.Remediation]; ok {
				for i, id := range ids {
					if id == rid.Id {
						if i < len(ids)-1 {
							v.Remediations[rid.Remediation] = append(ids[:i], ids[i+1:]...)
						} else {
							v.Remediations[rid.Remediation] = ids[:i]
						}
						break
					}
				}
			}
			if len(v.Remediations[rid.Remediation]) == 0 {
				delete(v.Remediations, rid.Remediation)
			}
			if len(v.Remediations) == 0 {
				if index < len(s.Items)-1 {
					s.Items = append(s.Items[:index], s.Items[index+1:]...)
				} else {
					s.Items = s.Items[:index]
				}
			}
			return
		}
	}
}

func (s *RangeSet) Contains(ip *net.IP) Remediation {
	s.RLock()
	defer s.RUnlock()
	log.Tracef("Checking IP %s, current items: %+v", ip.String(), s.Items)
	remediation := Unknown
	keys := make([]Remediation, 0)
	for _, v := range s.Items {
		if v.CIDR.Contains(*ip) {
			// Loop over all remediations
			for k := range v.Remediations {
				keys = append(keys, k)
			}
		}
	}
	remediation = slices.Max(keys)
	return remediation
}

func (s *StringSet) Init() {
	s.Items = make(map[string]map[Remediation][]int64, 0)
}

func (s *StringSet) Add(toAdd string, rid RemediationWithId) {
	s.Lock()
	defer s.Unlock()
	if _, ok := s.Items[toAdd]; ok {
		if _, ok := s.Items[toAdd][rid.Remediation]; ok {
			s.Items[toAdd][rid.Remediation] = append(s.Items[toAdd][rid.Remediation], rid.Id)
			return
		}
		s.Items[toAdd][rid.Remediation] = []int64{rid.Id}
		return
	}
	s.Items[toAdd] = map[Remediation][]int64{rid.Remediation: {rid.Id}}
}

func (s *StringSet) Remove(toRemove string, rid RemediationWithId) {
	s.Lock()
	defer s.Unlock()
	if v, ok := s.Items[toRemove]; ok {
		log.Tracef("Removing %s, current items: %+v", toRemove, s.Items)
		if ids, ok := v[rid.Remediation]; ok {
			for i, id := range ids {
				if id == rid.Id {
					if i < len(ids)-1 {
						s.Items[toRemove][rid.Remediation] = append(ids[:i], ids[i+1:]...)
					} else {
						s.Items[toRemove][rid.Remediation] = ids[:i]
					}
					break
				}
			}
			if len(s.Items[toRemove][rid.Remediation]) == 0 {
				delete(s.Items[toRemove], rid.Remediation)
			}
			if len(s.Items[toRemove]) == 0 {
				delete(s.Items, toRemove)
			}
		}
	}
}

func (s *StringSet) Contains(toCheck string) Remediation {
	s.RLock()
	defer s.RUnlock()
	log.Tracef("Checking %s, current items: %+v", toCheck, s.Items)
	remediation := Unknown
	if v, ok := s.Items[toCheck]; ok {
		keys := make([]Remediation, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		remediation = slices.Max(keys)
	}
	return remediation
}
