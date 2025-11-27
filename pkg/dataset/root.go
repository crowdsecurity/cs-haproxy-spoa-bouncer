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
	if len(decisions) == 0 {
		return
	}
	log.Infof("Processing %d new decisions", len(decisions))

	// Batch operations for better performance, especially during initial load
	// Convert IPs to prefixes immediately so we can use a single unified batch
	type cnOp struct {
		cn     string
		origin string
		r      remediation.Remediation
		id     int64
	}
	// Pre-allocate with estimated capacity for better performance
	prefixOps := make([]BartAddOp, 0, len(decisions))
	cnOps := make([]cnOp, 0)

	// Collect all operations, converting IPs to prefixes immediately
	for _, decision := range decisions {
		// Clone origin string to break reference to Decision struct memory
		// This allows GC to reclaim the DecisionsStreamResponse after processing
		var origin string
		if *decision.Origin == "lists" && decision.Scenario != nil {
			origin = strings.Clone(*decision.Origin + ":" + *decision.Scenario)
		} else {
			origin = strings.Clone(*decision.Origin)
		}

		scope := strings.ToLower(*decision.Scope)
		r := remediation.FromString(*decision.Type)

		switch scope {
		case "ip":
			ip, err := netip.ParseAddr(*decision.Value)
			if err != nil {
				log.Errorf("Error parsing IP address %s: %s", *decision.Value, err.Error())
				continue
			}
			// Convert IP to prefix immediately
			prefixLen := 32
			ipType := "ipv4"
			if ip.Is6() {
				prefixLen = 128
				ipType = "ipv6"
			}
			prefix := netip.PrefixFrom(ip, prefixLen)
			prefixOps = append(prefixOps, BartAddOp{Prefix: prefix, Origin: origin, R: r, ID: decision.ID, IPType: ipType, Scope: "ip"})
			// Increment metrics immediately - all operations always succeed
			metrics.TotalActiveDecisions.With(prometheus.Labels{"origin": origin, "ip_type": ipType, "scope": "ip"}).Inc()
		case "range":
			prefix, err := netip.ParsePrefix(*decision.Value)
			if err != nil {
				log.Errorf("Error parsing prefix %s: %s", *decision.Value, err.Error())
				continue
			}
			ipType := "ipv4"
			if prefix.Addr().Is6() {
				ipType = "ipv6"
			}
			prefixOps = append(prefixOps, BartAddOp{Prefix: prefix, Origin: origin, R: r, ID: decision.ID, IPType: ipType, Scope: "range"})
			// Increment metrics immediately - all operations always succeed
			metrics.TotalActiveDecisions.With(prometheus.Labels{"origin": origin, "ip_type": ipType, "scope": "range"}).Inc()
		case "country":
			// Clone country code to break reference to Decision struct memory
			cnOps = append(cnOps, cnOp{cn: strings.Clone(*decision.Value), origin: origin, r: r, id: decision.ID})
		default:
			log.Errorf("Unknown scope %s", *decision.Scope)
		}
	}

	// Execute unified batch for all prefixes (IPs and ranges)
	// Metrics already incremented during batch creation since all operations always succeed
	d.BartUnifiedIPSet.AddBatch(prefixOps)
	log.Infof("Finished processing %d decisions", len(decisions))
	// CN operations are handled individually (they use a different data structure)
	// Only increment metrics for successful additions
	for _, op := range cnOps {
		if err := d.addCN(op.cn, op.origin, op.r, op.id); err != nil {
			log.Errorf("Error adding CN decision: %s", err.Error())
			continue
		}
		metrics.TotalActiveDecisions.With(prometheus.Labels{"origin": op.origin, "ip_type": "", "scope": "country"}).Inc()
	}
}

func (d *DataSet) Remove(decisions models.GetDecisionsResponse) {
	if len(decisions) == 0 {
		return
	}
	log.Infof("Processing %d deleted decisions", len(decisions))
	// Batch operations for better performance
	// Convert IPs to prefixes immediately so we can use a single unified batch
	type cnOp struct {
		cn     string
		r      remediation.Remediation
		id     int64
		origin string
	}

	// Pre-allocate with estimated capacity for better performance
	prefixOps := make([]BartRemoveOp, 0, len(decisions))
	cnOps := make([]cnOp, 0)

	// Collect all operations, converting IPs to prefixes immediately
	for _, decision := range decisions {
		// Clone origin string to break reference to Decision struct memory
		// This allows GC to reclaim the DecisionsStreamResponse after processing
		var origin string
		if *decision.Origin == "lists" && decision.Scenario != nil {
			origin = *decision.Origin + ":" + *decision.Scenario
		} else {
			origin = strings.Clone(*decision.Origin)
		}

		scope := strings.ToLower(*decision.Scope)
		r := remediation.FromString(*decision.Type)

		switch scope {
		case "ip":
			ip, err := netip.ParseAddr(*decision.Value)
			if err != nil {
				log.Errorf("Error parsing IP address %s: %s", *decision.Value, err.Error())
				continue
			}
			// Convert IP to prefix immediately
			prefixLen := 32
			ipType := "ipv4"
			if ip.Is6() {
				prefixLen = 128
				ipType = "ipv6"
			}
			prefix := netip.PrefixFrom(ip, prefixLen)
			prefixOps = append(prefixOps, BartRemoveOp{Prefix: prefix, R: r, ID: decision.ID, Origin: origin, IPType: ipType, Scope: "ip"})
		case "range":
			prefix, err := netip.ParsePrefix(*decision.Value)
			if err != nil {
				log.Errorf("Error parsing prefix %s: %s", *decision.Value, err.Error())
				continue
			}
			ipType := "ipv4"
			if prefix.Addr().Is6() {
				ipType = "ipv6"
			}
			prefixOps = append(prefixOps, BartRemoveOp{Prefix: prefix, R: r, ID: decision.ID, Origin: origin, IPType: ipType, Scope: "range"})
		case "country":
			// Clone country code to break reference to Decision struct memory
			cnOps = append(cnOps, cnOp{cn: strings.Clone(*decision.Value), r: r, id: decision.ID, origin: origin})
		default:
			log.Errorf("Unknown scope %s", *decision.Scope)
		}
	}

	// Execute unified batch for all prefixes (IPs and ranges)
	// Only decrement metrics for successful removals
	results := d.BartUnifiedIPSet.RemoveBatch(prefixOps)
	for _, op := range results {
		if op != nil {
			metrics.TotalActiveDecisions.With(prometheus.Labels{"origin": op.Origin, "ip_type": op.IPType, "scope": op.Scope}).Dec()
		}
	}
	log.Infof("Finished processing %d deleted decisions", len(decisions))
	// CN operations are handled individually (they use a different data structure)
	// Only decrement metrics for successful removals
	for _, op := range cnOps {
		removed, err := d.removeCN(op.cn, op.r, op.id)
		if err != nil {
			log.Errorf("Error removing CN decision: %s", err.Error())
			continue
		}
		if removed {
			metrics.TotalActiveDecisions.With(prometheus.Labels{"origin": op.origin, "ip_type": "", "scope": "country"}).Dec()
		}
	}
}

func (d *DataSet) CheckIP(ip netip.Addr) (remediation.Remediation, string, error) {
	if !ip.IsValid() {
		return remediation.Allow, "", fmt.Errorf("invalid IP address")
	}
	r, origin := d.BartUnifiedIPSet.Contains(ip)
	return r, origin, nil
}

func (d *DataSet) CheckCN(cn string) (remediation.Remediation, string) {
	return d.CNSet.Contains(cn)
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
