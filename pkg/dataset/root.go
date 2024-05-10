package dataset

import (
	"fmt"
	"net"
	"strings"

	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
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
	CIDRSet.Init("CIDRSet")
	CNSet := CNSet{}
	CNSet.Init("CNSet")
	IPSet := IPSet{}
	IPSet.Init("IPSet")
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

func (d *DataSet) CheckIP(ip *net.IP) remediation.Remediation {
	ipCheck := d.IPSet.Contains(ip.String())
	if ipCheck > remediation.Unknown {
		return ipCheck
	}
	return d.CIDRSet.Contains(ip)
}

func (d *DataSet) CheckCN(cn string) remediation.Remediation {
	return d.CNSet.Contains(cn)
}

func (d *DataSet) RemoveDecision(decision *models.Decision) error {
	switch strings.ToLower(*decision.Scope) {
	case "ip":
		return d.RemoveIP(*decision.Value, remediation.FromString(*decision.Type), decision.ID)
	case "range":
		return d.RemoveCIDR(decision.Value, remediation.FromString(*decision.Type), decision.ID)
	case "country":
		return d.RemoveCN(*decision.Value, remediation.FromString(*decision.Type), decision.ID)
	}
	return fmt.Errorf("unknown scope %s", *decision.Scope)
}

func (d *DataSet) AddDecision(decision *models.Decision) error {
	switch strings.ToLower(*decision.Scope) {
	case "ip":
		return d.AddIP(*decision.Value, remediation.FromString(*decision.Type), decision.ID)
	case "range":
		return d.AddCIDR(decision.Value, remediation.FromString(*decision.Type), decision.ID)
	case "country":
		return d.AddCN(*decision.Value, remediation.FromString(*decision.Type), decision.ID)
	}
	return fmt.Errorf("unknown scope %s", *decision.Scope)
}

func (d *DataSet) AddCIDR(cidr *string, r remediation.Remediation, id int64) error {
	_, ipnet, err := net.ParseCIDR(*cidr)
	if err != nil {
		return err
	}
	d.CIDRSet.Add(ipnet, r, id)
	return nil
}

func (d *DataSet) AddIP(ip string, r remediation.Remediation, id int64) error {
	if ip == "" {
		return fmt.Errorf("empty IP")
	}
	d.IPSet.Add(ip, r, id)
	return nil
}

func (d *DataSet) AddCN(cn string, r remediation.Remediation, id int64) error {
	if cn == "" {
		return fmt.Errorf("empty CN")
	}
	d.CNSet.Add(cn, r, id)
	return nil
}

func (d *DataSet) RemoveCIDR(cidr *string, r remediation.Remediation, id int64) error {
	_, ipnet, err := net.ParseCIDR(*cidr)
	if err != nil {
		return err
	}
	d.CIDRSet.Remove(ipnet, r, id)
	return nil
}

func (d *DataSet) RemoveCN(cn string, r remediation.Remediation, id int64) error {
	if cn == "" {
		return fmt.Errorf("empty CN")
	}
	d.CNSet.Remove(cn, r, id)
	return nil
}

func (d *DataSet) RemoveIP(ip string, r remediation.Remediation, id int64) error {
	if ip == "" {
		return fmt.Errorf("empty IP")
	}
	d.IPSet.Remove(ip, r, id)
	return nil
}
