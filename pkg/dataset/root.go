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
	// CIDR-based trie implementation using bart library
	BartUnifiedIPSet *BartUnifiedIPSet
}

func New() *DataSet {
	CNSet := CNSet{}
	CNSet.Init("CNSet")
	BartUnifiedIPSet := NewBartUnifiedIPSet("BartUnifiedIPSet")
	return &DataSet{
		CNSet:            &CNSet,
		BartUnifiedIPSet: BartUnifiedIPSet,
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
	r, origin := d.BartUnifiedIPSet.Contains(ip)
	return r, origin, nil
}

func (d *DataSet) CheckCN(cn string) (remediation.Remediation, string) {
	return d.CNSet.Contains(cn)
}

func (d *DataSet) RemoveDecision(decision *models.Decision) error {
	origin := *decision.Origin
	if origin == "lists" && decision.Scenario != nil {
		origin = *decision.Origin + ":" + *decision.Scenario
	}

	// Use strings.ToLower for case-insensitive comparison (required for compatibility)
	scope := strings.ToLower(*decision.Scope)

	switch scope {
	case "ip":
		// Parse IP directly to determine type efficiently
		ip, err := netip.ParseAddr(*decision.Value)
		if err != nil {
			return err
		}
		removed := d.BartUnifiedIPSet.RemoveIP(ip, remediation.FromString(*decision.Type), decision.ID)
		if removed {
			ipType := "ipv4"
			if ip.Is6() {
				ipType = "ipv6"
			}
			metrics.TotalActiveDecisions.With(prometheus.Labels{"origin": origin, "ip_type": ipType, "scope": "ip"}).Dec()
		}
		return nil
	case "range":
		// Parse prefix directly to determine type efficiently
		prefix, err := netip.ParsePrefix(*decision.Value)
		if err != nil {
			return err
		}
		removed := d.BartUnifiedIPSet.RemovePrefix(prefix, remediation.FromString(*decision.Type), decision.ID)
		if removed {
			ipType := "ipv4"
			if prefix.Addr().Is6() {
				ipType = "ipv6"
			}
			metrics.TotalActiveDecisions.With(prometheus.Labels{"origin": origin, "ip_type": ipType, "scope": "range"}).Dec()
		}
		return nil
	case "country":
		removed, err := d.removeCN(*decision.Value, remediation.FromString(*decision.Type), decision.ID)
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
	if origin == "lists" && decision.Scenario != nil {
		origin = *decision.Origin + ":" + *decision.Scenario
	}

	// Use strings.ToLower for case-insensitive comparison (required for compatibility)
	scope := strings.ToLower(*decision.Scope)

	switch scope {
	case "ip":
		// Parse IP directly to determine type efficiently
		ip, err := netip.ParseAddr(*decision.Value)
		if err != nil {
			return err
		}
		ipType := "ipv4"
		if ip.Is6() {
			ipType = "ipv6"
		}
		metrics.TotalActiveDecisions.With(prometheus.Labels{"origin": origin, "ip_type": ipType, "scope": "ip"}).Inc()
		return d.BartUnifiedIPSet.AddIP(ip, origin, remediation.FromString(*decision.Type), decision.ID)
	case "range":
		// Parse prefix directly to determine type efficiently
		prefix, err := netip.ParsePrefix(*decision.Value)
		if err != nil {
			return err
		}
		ipType := "ipv4"
		if prefix.Addr().Is6() {
			ipType = "ipv6"
		}
		metrics.TotalActiveDecisions.With(prometheus.Labels{"origin": origin, "ip_type": ipType, "scope": "range"}).Inc()
		return d.BartUnifiedIPSet.AddPrefix(prefix, origin, remediation.FromString(*decision.Type), decision.ID)
	case "country":
		metrics.TotalActiveDecisions.With(prometheus.Labels{"origin": origin, "ip_type": "", "scope": "country"}).Inc()
		return d.addCN(*decision.Value, origin, remediation.FromString(*decision.Type), decision.ID)
	}
	return fmt.Errorf("unknown scope %s", *decision.Scope)
}

// Helper method for CN operations (still needed for country scope)
func (d *DataSet) addCN(cn string, origin string, r remediation.Remediation, id int64) error {
	if cn == "" {
		return fmt.Errorf("empty CN")
	}
	d.CNSet.Add(cn, origin, r, id)
	return nil
}

func (d *DataSet) removeCN(cn string, r remediation.Remediation, id int64) (bool, error) {
	if cn == "" {
		return false, fmt.Errorf("empty CN")
	}
	removed := d.CNSet.Remove(cn, r, id)
	return removed, nil
}
