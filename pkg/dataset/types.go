package dataset

import (
	"net"

	log "github.com/sirupsen/logrus"
)

const (
	Unknown Remediation = iota
	Ban     Remediation = iota
	Captcha Remediation = iota
)

type Remediation int

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
	Items map[string][]Remediation
}

type RangeSet struct {
	Items []struct {
		CIDR        *net.IPNet
		Remediation []Remediation
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
		CIDR        *net.IPNet
		Remediation []Remediation
	}, 0)
}

func (s *RangeSet) Add(cidr *net.IPNet, remediation Remediation) {
	for i := range s.Items {
		if s.Items[i].CIDR.String() == cidr.String() {
			s.Items[i].Remediation = append(s.Items[i].Remediation, remediation)
			return
		}
	}
	s.Items = append(s.Items, struct {
		CIDR        *net.IPNet
		Remediation []Remediation
	}{
		CIDR:        cidr,
		Remediation: []Remediation{remediation},
	})
}

func (s *RangeSet) Remove(cidr *net.IPNet, remediation Remediation) {
	for i, v := range s.Items {
		if v.CIDR.String() == cidr.String() {
			// if there's only one remediation, remove the whole entry
			if len(v.Remediation) == 1 {
				if i < len(s.Items)-1 {
					s.Items = append(s.Items[:i], s.Items[i+1:]...)
				} else {
					s.Items = s.Items[:i]
				}
				return
			}
			// otherwise, remove the remediation
			for i, r := range v.Remediation {
				if r == remediation {
					if i < len(v.Remediation)-1 {
						s.Items[i].Remediation = append(v.Remediation[:i], v.Remediation[i+1:]...)
					} else {
						s.Items[i].Remediation = v.Remediation[:i]
					}
				}
			}
			break
		}
	}
}

func (s *RangeSet) Contains(ip *net.IP) Remediation {
	log.Tracef("Checking IP %s, current items: %+v", ip.String(), s.Items)
	remediation := Unknown
	for _, v := range s.Items {
		if v.CIDR.Contains(*ip) {
			// Loop over all remediations
			for _, r := range v.Remediation {
				remediation = r
				// if remediation is Ban, return it
				if remediation == Ban {
					break
				}
			}
			break
		}
	}
	return remediation
}

func (s *StringSet) Init() {
	s.Items = make(map[string][]Remediation, 0)
}

func (s *StringSet) Add(toAdd string, remediation Remediation) {
	if _, ok := s.Items[toAdd]; ok {
		s.Items[toAdd] = append(s.Items[toAdd], remediation)
		return
	}
	s.Items[toAdd] = []Remediation{remediation}
}

func (s *StringSet) Remove(toRemove string, remediation Remediation) {
	if v, ok := s.Items[toRemove]; ok {
		log.Tracef("Removing %s, current items: %+v", toRemove, s.Items)
		// if there's only one remediation, remove the whole entry
		if len(v) == 1 {
			delete(s.Items, toRemove)
			return
		}
		// otherwise, remove the remediation
		for i, r := range v {
			if r == remediation {
				if i < len(v)-1 {
					s.Items[toRemove] = append(v[:i], v[i+1:]...)
				} else {
					s.Items[toRemove] = v[:i]
				}
				break
			}
		}
	}
}

func (s *StringSet) Contains(toCheck string) Remediation {
	log.Tracef("Checking %s, current items: %+v", toCheck, s.Items)
	remediation := Unknown
	if v, ok := s.Items[toCheck]; ok {
		for _, r := range v {
			remediation = r
			if remediation == Ban {
				break
			}
		}
	}
	return remediation
}
