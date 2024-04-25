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
	IPSet   *IPSet
	CNSet   *CNSet
}

func New() *DataSet {
	CIDRSet := CIDRSet{}
	CIDRSet.Init()
	CNSet := CNSet{}
	CNSet.Init()
	IPSet := IPSet{}
	IPSet.Init()
	return &DataSet{
		CIDRSet: &CIDRSet,
		CNSet:   &CNSet,
		IPSet:   &IPSet,
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

func (d *DataSet) CheckIP(ip *net.IP) Remediation {
	ipCheck := d.IPSet.Contains(ip.String())
	if ipCheck != Unknown {
		return ipCheck
	}
	return d.CIDRSet.Contains(ip)
}

func (d *DataSet) CheckCN(cn string) Remediation {
	return d.CNSet.Contains(cn)
}

func (d *DataSet) RemoveDecision(decision *models.Decision) error {
	switch strings.ToLower(*decision.Scope) {
	case "ip":
		return d.RemoveIP(*decision.Value, RemedationFromString(*decision.Type))
	case "range":
		return d.RemoveCIDR(decision.Value, RemedationFromString(*decision.Type))
	case "country":
		return d.RemoveCN(*decision.Value, RemedationFromString(*decision.Type))
	}
	return fmt.Errorf("unknown scope %s", *decision.Scope)
}

func (d *DataSet) AddDecision(decision *models.Decision) error {
	switch strings.ToLower(*decision.Scope) {
	case "ip":
		return d.AddIP(*decision.Value, RemedationFromString(*decision.Type))
	case "range":
		return d.AddCIDR(decision.Value, RemedationFromString(*decision.Type))
	case "country":
		return d.AddCN(*decision.Value, RemedationFromString(*decision.Type))
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

func (d *DataSet) AddIP(ip string, remediation Remediation) error {
	if ip == "" {
		return fmt.Errorf("empty IP")
	}
	d.IPSet.Add(ip, remediation)
	return nil
}

func (d *DataSet) AddCN(cn string, remediation Remediation) error {
	if cn == "" {
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

func (d *DataSet) RemoveCN(cn string, remediation Remediation) error {
	if cn == "" {
		return fmt.Errorf("empty CN")
	}
	d.CNSet.Remove(cn, remediation)
	return nil
}

func (d *DataSet) RemoveIP(ip string, remediation Remediation) error {
	if ip == "" {
		return fmt.Errorf("empty IP")
	}
	d.IPSet.Remove(ip, remediation)
	return nil
}
