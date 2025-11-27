package dataset

import (
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
	log "github.com/sirupsen/logrus"
)

// IPMap provides efficient storage for individual IP addresses.
// Uses sync.Map for concurrent access with O(1) lookups.
// This is much more memory efficient than BART for individual IPs
// since it doesn't require the radix trie overhead.
type IPMap struct {
	// IPv4 addresses stored by their 4-byte representation
	ipv4 sync.Map // map[netip.Addr]RemediationIdsMap
	// IPv6 addresses stored by their 16-byte representation
	ipv6   sync.Map // map[netip.Addr]RemediationIdsMap
	logger *log.Entry
	// Counters for monitoring
	ipv4Count atomic.Int64
	ipv6Count atomic.Int64
}

// NewIPMap creates a new IPMap for storing individual IP addresses
func NewIPMap(logAlias string) *IPMap {
	return &IPMap{
		logger: log.WithField("alias", logAlias),
	}
}

// IPAddOp represents an add operation for an individual IP
type IPAddOp struct {
	IP     netip.Addr
	Origin string
	R      remediation.Remediation
	ID     int64
	IPType string
}

// IPRemoveOp represents a remove operation for an individual IP
type IPRemoveOp struct {
	IP     netip.Addr
	R      remediation.Remediation
	ID     int64
	Origin string
	IPType string
}

// AddBatch adds multiple IPs to the map
func (m *IPMap) AddBatch(operations []IPAddOp) {
	if len(operations) == 0 {
		return
	}

	for _, op := range operations {
		m.add(op)
	}
}

// add adds a single IP to the appropriate map
func (m *IPMap) add(op IPAddOp) {
	var valueLog *log.Entry
	if m.logger.Logger.IsLevelEnabled(log.TraceLevel) {
		valueLog = m.logger.WithField("ip", op.IP.String()).WithField("remediation", op.R.String())
		valueLog.Trace("adding IP to map")
	}

	// Select the appropriate map based on IP version
	ipMap := &m.ipv4
	counter := &m.ipv4Count
	if op.IP.Is6() {
		ipMap = &m.ipv6
		counter = &m.ipv6Count
	}

	// Try to load existing entry first
	if existing, ok := ipMap.Load(op.IP); ok {
		if data, ok := existing.(RemediationIdsMap); ok {
			data.AddID(valueLog, op.R, op.ID, op.Origin)
			ipMap.Store(op.IP, data)
			return
		}
	}

	// Create new entry
	data := make(RemediationIdsMap)
	data.AddID(valueLog, op.R, op.ID, op.Origin)

	// Use LoadOrStore to handle race conditions
	if actual, loaded := ipMap.LoadOrStore(op.IP, data); loaded {
		// Another goroutine beat us, merge into existing
		if existingData, ok := actual.(RemediationIdsMap); ok {
			existingData.AddID(valueLog, op.R, op.ID, op.Origin)
			ipMap.Store(op.IP, existingData)
		}
	} else {
		// We stored a new entry, increment counter
		counter.Add(1)
	}
}

// RemoveBatch removes multiple IPs from the map
// Returns a slice of pointers to successfully removed operations (nil for failures)
func (m *IPMap) RemoveBatch(operations []IPRemoveOp) []*IPRemoveOp {
	if len(operations) == 0 {
		return nil
	}

	results := make([]*IPRemoveOp, len(operations))
	for i, op := range operations {
		if m.remove(op) {
			results[i] = &operations[i]
		}
	}
	return results
}

// remove removes a single IP from the appropriate map
// Returns true if the ID was successfully removed
func (m *IPMap) remove(op IPRemoveOp) bool {
	var valueLog *log.Entry
	if m.logger.Logger.IsLevelEnabled(log.TraceLevel) {
		valueLog = m.logger.WithField("ip", op.IP.String()).WithField("remediation", op.R.String())
		valueLog.Trace("removing IP from map")
	}

	// Select the appropriate map based on IP version
	ipMap := &m.ipv4
	counter := &m.ipv4Count
	if op.IP.Is6() {
		ipMap = &m.ipv6
		counter = &m.ipv6Count
	}

	existing, ok := ipMap.Load(op.IP)
	if !ok {
		if valueLog != nil {
			valueLog.Trace("IP not found in map")
		}
		return false
	}

	data, ok := existing.(RemediationIdsMap)
	if !ok {
		return false
	}
	err := data.RemoveID(valueLog, op.R, op.ID)
	if err != nil {
		if valueLog != nil {
			valueLog.Trace("ID not found for IP")
		}
		return false
	}

	// Check if entry is now empty
	if data.IsEmpty() {
		ipMap.Delete(op.IP)
		counter.Add(-1)
		if valueLog != nil {
			valueLog.Trace("removed IP entirely")
		}
	} else {
		ipMap.Store(op.IP, data)
		if valueLog != nil {
			valueLog.Trace("removed ID from IP")
		}
	}

	return true
}

// Contains checks if an IP address exists in the map
// Returns the remediation and origin if found
func (m *IPMap) Contains(ip netip.Addr) (remediation.Remediation, string, bool) {
	var valueLog *log.Entry
	if m.logger.Logger.IsLevelEnabled(log.TraceLevel) {
		valueLog = m.logger.WithField("ip", ip.String())
		valueLog.Trace("checking IP in map")
	}

	// Select the appropriate map based on IP version
	ipMap := &m.ipv4
	if ip.Is6() {
		ipMap = &m.ipv6
	}

	existing, ok := ipMap.Load(ip)
	if !ok {
		if valueLog != nil {
			valueLog.Trace("IP not found in map")
		}
		return remediation.Allow, "", false
	}

	data, ok := existing.(RemediationIdsMap)
	if !ok {
		return remediation.Allow, "", false
	}
	r, origin := data.GetRemediationAndOrigin()
	if valueLog != nil {
		valueLog.Tracef("found IP with remediation: %s", r.String())
	}
	return r, origin, true
}

// Count returns the number of IPs stored (for monitoring)
func (m *IPMap) Count() (ipv4 int64, ipv6 int64) {
	return m.ipv4Count.Load(), m.ipv6Count.Load()
}

