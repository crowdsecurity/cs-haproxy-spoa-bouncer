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
	Items map[string]Remediation
}

type RangeSet struct {
	Items []struct {
		CIDR        *net.IPNet
		Remediation Remediation
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
		Remediation Remediation
	}, 0)
}

func (s *RangeSet) Add(cidr *net.IPNet, remediation Remediation) {
	s.Items = append(s.Items, struct {
		CIDR        *net.IPNet
		Remediation Remediation
	}{
		CIDR:        cidr,
		Remediation: remediation,
	})
}

func (s *RangeSet) Remove(cidr *net.IPNet, remediation Remediation) {
	for i, v := range s.Items {
		if v.CIDR.String() == cidr.String() && v.Remediation == remediation {
			s.Items = append(s.Items[:i], s.Items[i+1:]...)
			break
		}
	}
}

func (s *RangeSet) Contains(ip *net.IP) Remediation {
	log.Tracef("Checking IP %s, current items: %d", ip.String(), len(s.Items))
	for _, v := range s.Items {
		if v.CIDR.Contains(*ip) {
			return v.Remediation
		}
	}
	return Unknown
}

func (s *StringSet) Init() {
	s.Items = make(map[string]Remediation, 0)
}

func (s *StringSet) Add(toAdd string, remediation Remediation) {
	s.Items[toAdd] = remediation
}

func (s *StringSet) Remove(toRemove string, remediation Remediation) {
	delete(s.Items, toRemove)
}

func (s *StringSet) Contains(toCheck string) Remediation {
	log.Tracef("Checking CN %s, current items: %d", toCheck, len(s.Items))
	if v, ok := s.Items[toCheck]; ok {
		return v
	}
	return Unknown
}
