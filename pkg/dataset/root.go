package dataset

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"

	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

type DataSet struct {
	CNSet *CNSet
	// Individual IP addresses - uses sync.Map for O(1) lookups
	// Much more memory efficient than BART for individual IPs
	IPMap *IPMap
	// Range-based trie implementation using bart library
	// Only used for CIDR ranges that need Longest Prefix Match (LPM)
	RangeSet *BartRangeSet
}

func New() *DataSet {
	return &DataSet{
		CNSet:    NewCNSet("CNSet"),
		IPMap:    NewIPMap("IPMap"),
		RangeSet: NewBartRangeSet("RangeSet"),
	}
}

func (d *DataSet) Add(decisions models.GetDecisionsResponse) {
	if len(decisions) == 0 {
		return
	}
	log.Infof("Processing %d new decisions", len(decisions))

	// Batch operations for better performance, especially during initial load
	type cnOp struct {
		cn     string
		origin string
		r      remediation.Remediation
		id     int64
	}

	// Separate operations by type:
	// - Individual IPs go to IPMap (memory efficient, O(1) lookup)
	// - Ranges go to RangeSet/BART (needed for LPM)
	ipOps := make([]IPAddOp, 0, len(decisions))
	rangeOps := make([]BartAddOp, 0)
	cnOps := make([]cnOp, 0)

	for _, decision := range decisions {
		origin := *decision.Origin
		if origin == "lists" && decision.Scenario != nil {
			origin = *decision.Origin + ":" + *decision.Scenario
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
			ipType := "ipv4"
			if ip.Is6() {
				ipType = "ipv6"
			}
			// Individual IPs go to IPMap for memory efficiency
			ipOps = append(ipOps, IPAddOp{IP: ip, Origin: origin, R: r, ID: decision.ID, IPType: ipType})
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
			// Ranges go to BART for LPM support
			rangeOps = append(rangeOps, BartAddOp{Prefix: prefix, Origin: origin, R: r, ID: decision.ID, IPType: ipType, Scope: "range"})
			metrics.TotalActiveDecisions.With(prometheus.Labels{"origin": origin, "ip_type": ipType, "scope": "range"}).Inc()
		case "country":
			cnOps = append(cnOps, cnOp{cn: *decision.Value, origin: origin, r: r, id: decision.ID})
		default:
			log.Errorf("Unknown scope %s", *decision.Scope)
		}
	}

	// Execute batches in parallel using sync.WaitGroup.Go (Go 1.23+)
	var wg sync.WaitGroup

	// IPMap batch (individual IPs)
	if len(ipOps) > 0 {
		wg.Go(func() {
			d.IPMap.AddBatch(ipOps)
		})
	}

	// RangeSet batch (CIDR ranges)
	if len(rangeOps) > 0 {
		wg.Go(func() {
			d.RangeSet.AddBatch(rangeOps)
		})
	}

	// CN operations batch
	if len(cnOps) > 0 {
		wg.Go(func() {
			for _, op := range cnOps {
				if err := d.addCN(op.cn, op.origin, op.r, op.id); err != nil {
					log.Errorf("Error adding CN decision: %s", err.Error())
					continue
				}
				metrics.TotalActiveDecisions.With(prometheus.Labels{"origin": op.origin, "ip_type": "", "scope": "country"}).Inc()
			}
		})
	}

	wg.Wait()
	log.Infof("Finished processing %d decisions", len(decisions))
}

func (d *DataSet) Remove(decisions models.GetDecisionsResponse) {
	if len(decisions) == 0 {
		return
	}
	log.Infof("Processing %d deleted decisions", len(decisions))

	type cnOp struct {
		cn     string
		r      remediation.Remediation
		id     int64
		origin string
	}

	// Separate operations by type
	ipOps := make([]IPRemoveOp, 0, len(decisions))
	rangeOps := make([]BartRemoveOp, 0)
	cnOps := make([]cnOp, 0)

	for _, decision := range decisions {
		origin := *decision.Origin
		if origin == "lists" && decision.Scenario != nil {
			origin = *decision.Origin + ":" + *decision.Scenario
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
			ipType := "ipv4"
			if ip.Is6() {
				ipType = "ipv6"
			}
			ipOps = append(ipOps, IPRemoveOp{IP: ip, R: r, ID: decision.ID, Origin: origin, IPType: ipType})
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
			rangeOps = append(rangeOps, BartRemoveOp{Prefix: prefix, R: r, ID: decision.ID, Origin: origin, IPType: ipType, Scope: "range"})
		case "country":
			cnOps = append(cnOps, cnOp{cn: *decision.Value, r: r, id: decision.ID, origin: origin})
		default:
			log.Errorf("Unknown scope %s", *decision.Scope)
		}
	}

	// Execute batches in parallel using sync.WaitGroup.Go (Go 1.23+)
	var wg sync.WaitGroup

	// Variables to collect results for metrics
	var ipResults []*IPRemoveOp
	var rangeResults []*BartRemoveOp

	// IPMap batch (individual IPs)
	if len(ipOps) > 0 {
		wg.Go(func() {
			ipResults = d.IPMap.RemoveBatch(ipOps)
		})
	}

	// RangeSet batch (CIDR ranges)
	if len(rangeOps) > 0 {
		wg.Go(func() {
			rangeResults = d.RangeSet.RemoveBatch(rangeOps)
		})
	}

	// CN operations batch
	if len(cnOps) > 0 {
		wg.Go(func() {
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
		})
	}

	wg.Wait()

	// Update metrics for IP and Range removals (after goroutines complete)
	for _, op := range ipResults {
		if op != nil {
			metrics.TotalActiveDecisions.With(prometheus.Labels{"origin": op.Origin, "ip_type": op.IPType, "scope": "ip"}).Dec()
		}
	}
	for _, op := range rangeResults {
		if op != nil {
			metrics.TotalActiveDecisions.With(prometheus.Labels{"origin": op.Origin, "ip_type": op.IPType, "scope": op.Scope}).Dec()
		}
	}

	log.Infof("Finished processing %d deleted decisions", len(decisions))
}

func (d *DataSet) CheckIP(ip netip.Addr) (remediation.Remediation, string, error) {
	if !ip.IsValid() {
		return remediation.Allow, "", fmt.Errorf("invalid IP address")
	}

	// First check the IPMap for exact IP match (O(1) lookup)
	if r, origin, found := d.IPMap.Contains(ip); found {
		return r, origin, nil
	}

	// Fall back to RangeSet (BART) for LPM on ranges
	r, origin := d.RangeSet.Contains(ip)
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
