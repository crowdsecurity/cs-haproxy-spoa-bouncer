package dataset

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"

	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/models"
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
	}

	// Separate operations by type:
	// - Individual IPs go to IPMap (memory efficient, O(1) lookup)
	// - Ranges go to RangeSet/BART (needed for LPM)
	// Note: We don't pre-allocate capacity here because many decisions might be no-ops
	// (duplicates) and would waste allocated memory. Let Go handle dynamic growth.
	ipOps := make([]IPAddOp, 0)
	rangeOps := make([]BartAddOp, 0)
	cnOps := make([]cnOp, 0)

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
			// Check for no-op: same IP, same remediation, same origin already exists
			if d.IPMap.HasRemediation(ip, r, origin) {
				// Exact duplicate - skip processing (no-op)
				continue
			}
			ipType := "ipv4"
			if ip.Is6() {
				ipType = "ipv6"
			}
			// Check if we're overwriting an existing decision with different origin
			if existingR, existingOrigin, found := d.IPMap.Contains(ip); found && existingR == r && existingOrigin != origin {
				// Decrement old origin's metric before incrementing new one
				// Label order: origin, ip_type, scope (as defined in metrics.go)
				metrics.TotalActiveDecisions.WithLabelValues(existingOrigin, ipType, "ip").Dec()
			}
			// Individual IPs go to IPMap for memory efficiency
			ipOps = append(ipOps, IPAddOp{IP: ip, Origin: origin, R: r, IPType: ipType})
			// Label order: origin, ip_type, scope (as defined in metrics.go)
			metrics.TotalActiveDecisions.WithLabelValues(origin, ipType, "ip").Inc()
		case "range":
			prefix, err := netip.ParsePrefix(*decision.Value)
			if err != nil {
				log.Errorf("Error parsing prefix %s: %s", *decision.Value, err.Error())
				continue
			}
			// Check for no-op: same prefix, same remediation, same origin already exists
			if d.RangeSet.HasRemediation(prefix, r, origin) {
				// Exact duplicate - skip processing (no-op)
				continue
			}
			ipType := "ipv4"
			if prefix.Addr().Is6() {
				ipType = "ipv6"
			}
			// Check if we're overwriting an existing decision with different origin
			if existingOrigin, found := d.RangeSet.GetOriginForRemediation(prefix, r); found && existingOrigin != origin {
				// Decrement old origin's metric before incrementing new one
				// Label order: origin, ip_type, scope (as defined in metrics.go)
				metrics.TotalActiveDecisions.WithLabelValues(existingOrigin, ipType, "range").Dec()
			}
			// Ranges go to BART for LPM support
			rangeOps = append(rangeOps, BartAddOp{Prefix: prefix, Origin: origin, R: r, IPType: ipType, Scope: "range"})
			// Label order: origin, ip_type, scope (as defined in metrics.go)
			metrics.TotalActiveDecisions.WithLabelValues(origin, ipType, "range").Inc()
		case "country":
			// Clone country code to break reference to Decision struct memory
			cn := strings.Clone(*decision.Value)
			// Check for no-op: same country, same remediation, same origin already exists
			if d.CNSet.HasRemediation(cn, r, origin) {
				// Exact duplicate - skip processing (no-op)
				continue
			}
			// Check if we're overwriting an existing decision with different origin
			if existingR, existingOrigin := d.CNSet.Contains(cn); existingR == r && existingOrigin != "" && existingOrigin != origin {
				// Decrement old origin's metric before incrementing new one
				// Label order: origin, ip_type, scope (as defined in metrics.go)
				metrics.TotalActiveDecisions.WithLabelValues(existingOrigin, "", "country").Dec()
			}
			cnOps = append(cnOps, cnOp{cn: cn, origin: origin, r: r})
		default:
			log.Errorf("Unknown scope %s", *decision.Scope)
		}
	}

	// Execute batches in parallel using sync.WaitGroup.Go (Go 1.22+)
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
				if err := d.addCN(op.cn, op.origin, op.r); err != nil {
					log.Errorf("Error adding CN decision: %s", err.Error())
					continue
				}
				// Label order: origin, ip_type, scope (as defined in metrics.go)
				metrics.TotalActiveDecisions.WithLabelValues(op.origin, "", "country").Inc()
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
		origin string
	}

	// Separate operations by type
	// Note: We don't pre-allocate capacity here because many decisions might be no-ops
	// (duplicates) and would waste allocated memory. Let Go handle dynamic growth.
	ipOps := make([]IPRemoveOp, 0)
	rangeOps := make([]BartRemoveOp, 0)
	cnOps := make([]cnOp, 0)

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
			ipType := "ipv4"
			if ip.Is6() {
				ipType = "ipv6"
			}
			ipOps = append(ipOps, IPRemoveOp{IP: ip, R: r, Origin: origin, IPType: ipType})
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
			rangeOps = append(rangeOps, BartRemoveOp{Prefix: prefix, R: r, Origin: origin, IPType: ipType, Scope: "range"})
		case "country":
			// Clone country code to break reference to Decision struct memory
			cnOps = append(cnOps, cnOp{cn: strings.Clone(*decision.Value), r: r, origin: origin})
		default:
			log.Errorf("Unknown scope %s", *decision.Scope)
		}
	}

	// Execute batches in parallel using sync.WaitGroup.Go (Go 1.22+)
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
				removed, err := d.removeCN(op.cn, op.r)
				if err != nil {
					log.Errorf("Error removing CN decision: %s", err.Error())
					continue
				}
				if removed {
					// Label order: origin, ip_type, scope (as defined in metrics.go)
					metrics.TotalActiveDecisions.WithLabelValues(op.origin, "", "country").Dec()
				}
			}
		})
	}

	wg.Wait()

	// Update metrics for IP and Range removals (after goroutines complete)
	// Label order: origin, ip_type, scope (as defined in metrics.go)
	for _, op := range ipResults {
		if op != nil {
			metrics.TotalActiveDecisions.WithLabelValues(op.Origin, op.IPType, "ip").Dec()
		}
	}
	for _, op := range rangeResults {
		if op != nil {
			metrics.TotalActiveDecisions.WithLabelValues(op.Origin, op.IPType, op.Scope).Dec()
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
func (d *DataSet) addCN(cn string, origin string, r remediation.Remediation) error {
	if cn == "" {
		return fmt.Errorf("empty CN")
	}
	d.CNSet.Add(cn, origin, r)
	return nil
}

func (d *DataSet) removeCN(cn string, r remediation.Remediation) (bool, error) {
	if cn == "" {
		return false, fmt.Errorf("empty CN")
	}
	removed := d.CNSet.Remove(cn, r)
	return removed, nil
}
