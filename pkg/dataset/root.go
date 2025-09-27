package dataset

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

type DataSet struct {
	CNSet *CNSet
	// CIDR-based trie implementation using cidranger library
	CIDRUnifiedIPSet *CIDRUnifiedIPSet
}

func New() *DataSet {
	CNSet := CNSet{}
	CNSet.Init("CNSet")
	CIDRUnifiedIPSet := NewCIDRUnifiedIPSet("CIDRUnifiedIPSet")
	return &DataSet{
		CNSet:            &CNSet,
		CIDRUnifiedIPSet: CIDRUnifiedIPSet,
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

func (d *DataSet) CheckIP(ipString string) (remediation.Remediation, string, error) {
	ip, err := netip.ParseAddr(ipString)
	if err != nil || !ip.IsValid() {
		return remediation.Allow, "", err
	}
	r, origin := d.CIDRUnifiedIPSet.Contains(ip)
	return r, origin, nil
}

func (d *DataSet) CheckCN(cn string) (remediation.Remediation, string) {
	return d.CNSet.Contains(cn)
}

func (d *DataSet) RemoveDecision(decision *models.Decision) error {
	origin := *decision.Origin
	if origin == "lists" {
		origin = *decision.Origin + ":" + *decision.Scenario
	}
	switch strings.ToLower(*decision.Scope) {
	case "ip":
		removed, err := d.RemoveIP(*decision.Value, remediation.FromString(*decision.Type), decision.ID)
		if err != nil {
			return err
		}
		if removed {
			ipType := "ipv4"
			if strings.Contains(*decision.Value, ":") {
				ipType = "ipv6"
			}
			metrics.TotalActiveDecisions.With(prometheus.Labels{"origin": origin, "ip_type": ipType, "scope": "ip"}).Dec()
		}
		return nil
	case "range":
		removed, err := d.RemoveCIDR(decision.Value, remediation.FromString(*decision.Type), decision.ID)
		if err != nil {
			return err
		}
		if removed {
			ipType := "ipv4"
			if strings.Contains(*decision.Value, ":") {
				ipType = "ipv6"
			}
			metrics.TotalActiveDecisions.With(prometheus.Labels{"origin": origin, "ip_type": ipType, "scope": "range"}).Dec()
		}
		return nil
	case "country":
		removed, err := d.RemoveCN(*decision.Value, remediation.FromString(*decision.Type), decision.ID)
		if err != nil {
			return err
		}
		if removed {
			metrics.TotalActiveDecisions.With(prometheus.Labels{"origin": origin, "ip_type": "", "scope": "country"}).Dec()
		}
		return nil
	}
	return fmt.Errorf("unknown scope %s", *decision.Scope)
}

func (d *DataSet) AddDecision(decision *models.Decision) error {
	origin := *decision.Origin
	if origin == "lists" {
		origin = *decision.Origin + ":" + *decision.Scenario
	}
	switch strings.ToLower(*decision.Scope) {
	case "ip":
		ipType := "ipv4"
		if strings.Contains(*decision.Value, ":") {
			ipType = "ipv6"
		}
		metrics.TotalActiveDecisions.With(prometheus.Labels{"origin": origin, "ip_type": ipType, "scope": "ip"}).Inc()
		return d.AddIP(*decision.Value, origin, remediation.FromString(*decision.Type), decision.ID)
	case "range":
		ipType := "ipv4"
		if strings.Contains(*decision.Value, ":") {
			ipType = "ipv6"
		}
		metrics.TotalActiveDecisions.With(prometheus.Labels{"origin": origin, "ip_type": ipType, "scope": "range"}).Inc()
		return d.AddCIDR(decision.Value, origin, remediation.FromString(*decision.Type), decision.ID)
	case "country":
		metrics.TotalActiveDecisions.With(prometheus.Labels{"origin": origin, "ip_type": "", "scope": "country"}).Inc()
		return d.AddCN(*decision.Value, origin, remediation.FromString(*decision.Type), decision.ID)
	}
	return fmt.Errorf("unknown scope %s", *decision.Scope)
}

func (d *DataSet) AddCIDR(cidr *string, origin string, r remediation.Remediation, id int64) error {
	prefix, err := netip.ParsePrefix(*cidr)
	if err != nil {
		return err
	}
	return d.CIDRUnifiedIPSet.AddPrefix(prefix, origin, r, id)
}

func (d *DataSet) AddIP(ipString string, origin string, r remediation.Remediation, id int64) error {
	ip, err := netip.ParseAddr(ipString)
	if err != nil || !ip.IsValid() {
		return err
	}
	return d.CIDRUnifiedIPSet.AddIP(ip, origin, r, id)
}

func (d *DataSet) AddCN(cn string, origin string, r remediation.Remediation, id int64) error {
	if cn == "" {
		return fmt.Errorf("empty CN")
	}
	d.CNSet.Add(cn, origin, r, id)
	return nil
}

func (d *DataSet) RemoveCIDR(cidr *string, r remediation.Remediation, id int64) (bool, error) {
	prefix, err := netip.ParsePrefix(*cidr)
	if err != nil {
		return false, err
	}
	removed := d.CIDRUnifiedIPSet.RemovePrefix(prefix, r, id)
	return removed, nil
}

func (d *DataSet) RemoveCN(cn string, r remediation.Remediation, id int64) (bool, error) {
	if cn == "" {
		return false, fmt.Errorf("empty CN")
	}
	removed := d.CNSet.Remove(cn, r, id)
	return removed, nil
}

func (d *DataSet) RemoveIP(ipString string, r remediation.Remediation, id int64) (bool, error) {
	ip, err := netip.ParseAddr(ipString)
	if err != nil || !ip.IsValid() {
		return false, err
	}
	removed := d.CIDRUnifiedIPSet.RemoveIP(ip, r, id)
	return removed, nil
}
