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

func (d *DataSet) Add(decisions models.GetDecisionsResponse) {
	for _, decision := range decisions {
		if err := d.AddDecision(decision); err != nil {
			log.Errorf("Error adding decision: %s", err.Error())
		}
	}
}

func (d *DataSet) Remove(decisions models.GetDecisionsResponse) {
	for _, decision := range decisions {
		if err := d.RemoveDecision(decision); err != nil {
			log.Errorf("Error removing decision: %s", err.Error())
		}
	}
}

func (d *DataSet) CheckIP(ip *net.IP) *Item[net.IPNet] {
	return d.CIDRSet.Contains(ip)
}

func (d *DataSet) CheckCN(cn *string) *Item[string] {
	return d.CNSet.Contains(cn)
}

func (d *DataSet) RemoveDecision(decision *models.Decision) error {
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
		return d.RemoveCIDR(&ip, RemedationFromString(*decision.Type))
	case "range":
		return d.RemoveCIDR(decision.Value, RemedationFromString(*decision.Type))
	case "country":
		return d.RemoveCN(decision.Value, RemedationFromString(*decision.Type))
	}
	return fmt.Errorf("unknown scope %s", *decision.Scope)
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
		return d.AddCIDR(&ip, RemedationFromString(*decision.Type))
	case "range":
		return d.AddCIDR(decision.Value, RemedationFromString(*decision.Type))
	case "country":
		return d.AddCN(decision.Value, RemedationFromString(*decision.Type))
	}
	return fmt.Errorf("unknown scope %s", *decision.Scope)
}

func (d *DataSet) AddCIDR(cidr *string, remediation Remediation) error {
	_, ipnet, err := net.ParseCIDR(*cidr)
	if err != nil {
		return err
	}
	d.CIDRSet.Add(ipnet, remediation)
	return nil
}

func (d *DataSet) AddCN(cn *string, remediation Remediation) error {
	if *cn == "" {
		return fmt.Errorf("empty CN")
	}
	d.CNSet.Add(cn, remediation)
	return nil
}

func (d *DataSet) RemoveCIDR(cidr *string, remediation Remediation) error {
	_, ipnet, err := net.ParseCIDR(*cidr)
	if err != nil {
		return err
	}
	d.CIDRSet.Remove(ipnet, remediation)
	return nil
}

func (d *DataSet) RemoveCN(cn *string, remediation Remediation) error {
	if *cn == "" {
		return fmt.Errorf("empty CN")
	}
	d.CNSet.Remove(cn, remediation)
	return nil
}

func parseIP(ip string) net.IP {
	parsedIP := net.ParseIP(ip)
	if ipv4 := parsedIP.To4(); ipv4 != nil {
		return ipv4
	}
	return parsedIP
}
