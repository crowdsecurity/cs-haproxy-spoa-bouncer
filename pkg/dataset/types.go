package dataset

import (
	"net"

	log "github.com/sirupsen/logrus"
)

type BaseSetInt interface {
	Init()
	Add(interface{})
	Remove(interface{})
	Contains(interface{}) bool
}

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

type Item[c net.IPNet | string] struct {
	Value       *c
	Remediation Remediation
}

type Set[c net.IPNet | string] struct {
	BaseSetInt
	Items []Item[c]
}

type CIDRSet struct {
	Set[net.IPNet]
}

type CNSet struct {
	Set[string]
}

func (s *CIDRSet) Init() {
	s.Items = make([]Item[net.IPNet], 0)
}

func (s *CIDRSet) Add(cidr *net.IPNet, remediation Remediation) {
	s.Items = append(s.Items, Item[net.IPNet]{Value: cidr, Remediation: remediation})
}

func (s *CIDRSet) Remove(cidr *net.IPNet, remediation Remediation) {
	comparable := cidr.String()
	newItems := make([]Item[net.IPNet], 0, len(s.Items))
	for _, v := range s.Items {
		if v.Value == nil {
			continue // skip nil values
		}
		if v.Value.String() != comparable || (v.Value.String() == comparable && v.Remediation != remediation) {
			newItems = append(newItems, v)
		}
	}
	s.Items = newItems
}

func (s *CIDRSet) Contains(ip *net.IP) *Item[net.IPNet] {
	log.Tracef("Checking IP %s, current items: %d", ip.String(), len(s.Items))
	var ipNet *Item[net.IPNet]
	for _, v := range s.Items {
		if v.Value == nil {
			continue // skip nil values
		}
		if v.Value.Contains(*ip) {
			ipNet = &v
			if v.Remediation == Ban {
				break
			}
		}
	}
	return ipNet
}

func (s *CNSet) Init() {
	s.Items = make([]Item[string], 0)
}

func (s *CNSet) Add(cn *string, remediation Remediation) {
	s.Items = append(s.Items, Item[string]{Value: cn, Remediation: remediation})
}

func (s *CNSet) Remove(cn *string, remediation Remediation) {
	newItems := make([]Item[string], 0, len(s.Items))
	for _, v := range s.Items {
		if v.Value == nil {
			continue // skip nil values
		}
		if *v.Value != *cn || (*v.Value == *cn && v.Remediation != remediation) {
			newItems = append(newItems, v)
		}
	}
	s.Items = newItems
}

func (s *CNSet) Contains(cn *string) *Item[string] {
	var Value *Item[string]
	for _, v := range s.Items {
		if v.Value == nil {
			continue // skip nil values
		}
		if *v.Value == *cn {
			Value = &v
			if v.Remediation == Ban {
				break
			}
		}
	}
	return Value
}
