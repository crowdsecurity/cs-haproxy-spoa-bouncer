package dataset

import (
	"fmt"
	"net"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	log "github.com/sirupsen/logrus"
)

type DataSet struct {
	CIDRSet *CIDRSet
	CNSet   *CNSet
}

func New() *DataSet {
	CIDRSet := CIDRSet{}
	CIDRSet.Init()
	CNSet := CNSet{}
	CNSet.Init()
	return &DataSet{
		CIDRSet: &CIDRSet,
		CNSet:   &CNSet,
	}
}

func (d *DataSet) Add(decisions models.GetDecisionsResponse) bool {
	for _, decision := range decisions {
		if err := d.AddDecision(decision); err != nil {
			log.Errorf("Error adding decision: %s", err.Error())
		}
	}
	return true
}

func (d *DataSet) Remove(decisions models.GetDecisionsResponse) bool {
	for _, decision := range decisions {
		d.RemoveDecision(decision)
	}
	return true
}

func (d *DataSet) CheckIP(ip *net.IP) bool {
	return d.CIDRSet.Contains(ip)
}

func (d *DataSet) CheckCN(cn *string) bool {
	return d.CNSet.Contains(cn)
}

func (d *DataSet) RemoveDecision(decision *models.Decision) {
	switch strings.ToLower(*decision.Scope) {
	case "ip":
		ip := *decision.Value
		parsedIP := parseIP(ip)
		switch len(parsedIP) {
		case net.IPv4len:
			ip += "/32"
		case net.IPv6len:
			ip += "/128"
		}
		d.RemoveCIDR(&ip)
	case "range":
		d.RemoveCIDR(decision.Value)
	case "country":
		d.RemoveCN(decision.Value)
	}
}

func (d *DataSet) AddDecision(decision *models.Decision) error {
	switch strings.ToLower(*decision.Scope) {
	case "ip":
		ip := *decision.Value
		parsedIP := parseIP(ip)
		switch len(parsedIP) {
		case net.IPv4len:
			ip += "/32"
		case net.IPv6len:
			ip += "/128"
		}
		return d.AddCIDR(&ip)
	case "range":
		return d.AddCIDR(decision.Value)
	case "country":
		return d.AddCN(decision.Value)
	}
	return fmt.Errorf("unknown scope %s", *decision.Scope)
}

func (d *DataSet) AddCIDR(cidr *string) error {
	_, ipnet, err := net.ParseCIDR(*cidr)
	if err != nil {
		return err
	}
	d.CIDRSet.Add(ipnet)
	return nil
}

func (d *DataSet) AddCN(cn *string) error {
	if *cn == "" {
		return fmt.Errorf("empty CN")
	}
	d.CNSet.Add(cn)
	return nil
}

func (d *DataSet) RemoveCIDR(cidr *string) error {
	_, ipnet, err := net.ParseCIDR(*cidr)
	if err != nil {
		return err
	}
	d.CIDRSet.Remove(ipnet)
	return nil
}

func (d *DataSet) RemoveCN(cn *string) {
	d.CNSet.Remove(cn)
}

func parseIP(ip string) net.IP {
	parsedIP := net.ParseIP(ip)
	if ipv4 := parsedIP.To4(); ipv4 != nil {
		return ipv4
	}
	return parsedIP
}
