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

type Set[c net.IPNet | string] struct {
	BaseSetInt
	Items []*c
}

type CIDRSet struct {
	Set[net.IPNet]
}

type CNSet struct {
	Set[string]
}

func (s *CIDRSet) Init() {
	s.Items = make([]*net.IPNet, 0)
}

func (s *CIDRSet) Add(cidr *net.IPNet) {
	s.Items = append(s.Items, cidr)
}

func (s *CIDRSet) Remove(cidr *net.IPNet) {
	comparable := cidr.String()
	for i, v := range s.Items {
		if v.String() == comparable {
			s.Items = append(s.Items[:i], s.Items[i+1:]...)
		}
	}
}

func (s *CIDRSet) Contains(ip *net.IP) bool {
	log.Tracef("Checking IP %s, current items: %d", ip.String(), len(s.Items))
	for _, v := range s.Items {
		if v.Contains(*ip) {
			return true
		}
	}
	return false
}

func (s *CNSet) Init() {
	s.Items = make([]*string, 0)
}

func (s *CNSet) Add(cn *string) {
	s.Items = append(s.Items, cn)
}

func (s *CNSet) Remove(cn *string) {
	for i, v := range s.Items {
		if *v == *cn {
			s.Items = append(s.Items[:i], s.Items[i+1:]...)
		}
	}
}

func (s *CNSet) Contains(cn *string) bool {
	for _, v := range s.Items {
		if *v == *cn {
			return true
		}
	}
	return false
}
