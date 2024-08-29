package dataset

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	log "github.com/sirupsen/logrus"
)

type DataSet struct {
	PrefixSet *PrefixSet
	IPSet     *IPSet
	CNSet     *CNSet
}

func New() *DataSet {
	PrefixSet := PrefixSet{}
	PrefixSet.Init("CIDRSet")
	CNSet := CNSet{}
	CNSet.Init("CNSet")
	IPSet := IPSet{}
	IPSet.Init("IPSet")
	return &DataSet{
		PrefixSet: &PrefixSet,
		CNSet:     &CNSet,
		IPSet:     &IPSet,
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

func (d *DataSet) CheckIP(ipString string) (remediation.Remediation, error) {
	ip, err := netip.ParseAddr(ipString)
	if err != nil || !ip.IsValid() {
		return remediation.Allow, err
	}
	if ipCheck := d.IPSet.Contains(ip); ipCheck > remediation.Unknown {
		return ipCheck, nil
	}
	return d.PrefixSet.Contains(ip), nil
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
	prefix, err := netip.ParsePrefix(*cidr)
	if err != nil {
		return err
	}
	d.PrefixSet.Add(prefix, r, id)
	return nil
}

func (d *DataSet) AddIP(ipString string, r remediation.Remediation, id int64) error {
	ip, err := netip.ParseAddr(ipString)
	if err != nil || !ip.IsValid() {
		return err
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
	prefix, err := netip.ParsePrefix(*cidr)
	if err != nil {
		return err
	}
	d.PrefixSet.Remove(prefix, r, id)
	return nil
}

func (d *DataSet) RemoveCN(cn string, r remediation.Remediation, id int64) error {
	if cn == "" {
		return fmt.Errorf("empty CN")
	}
	d.CNSet.Remove(cn, r, id)
	return nil
}

func (d *DataSet) RemoveIP(ipString string, r remediation.Remediation, id int64) error {
	ip, err := netip.ParseAddr(ipString)
	if err != nil || !ip.IsValid() {
		return err
	}
	d.IPSet.Remove(ip, r, id)
	return nil
}
