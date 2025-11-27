package dataset

import (
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
	log "github.com/sirupsen/logrus"
)

// ipEntry wraps RemediationIdsMap with an atomic pointer for lock-free reads.
// This ensures SPOA handlers never block when checking IPs, even during updates.
// - Readers load the atomic pointer (instant, never blocks)
// - Writers clone, modify, and swap (readers see old or new, never partial state)
type ipEntry struct {
	data atomic.Pointer[RemediationIdsMap]
}

// IPMap provides efficient storage for individual IP addresses.
// Uses sync.Map with atomic pointers per entry for lock-free reads.
// This is much more memory efficient than BART for individual IPs
// since it doesn't require the radix trie overhead.
//
// Concurrency model:
// - Reads are completely lock-free (atomic pointer load)
// - Writes use copy-on-write (clone, modify, swap)
// - SPOA handlers never block, even during batch updates
type IPMap struct {
	// IPv4 addresses stored by their 4-byte representation
	ipv4 sync.Map // map[netip.Addr]*ipEntry
	// IPv6 addresses stored by their 16-byte representation
	ipv6 sync.Map // map[netip.Addr]*ipEntry
	// Write mutex to serialize modifications (prevents lost updates)
	writeMu sync.Mutex
	logger  *log.Entry
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

	// Hold write lock for entire batch to prevent interleaving
	m.writeMu.Lock()
	defer m.writeMu.Unlock()

	for _, op := range operations {
		m.addLocked(op)
	}
}

// addLocked adds a single IP (caller must hold writeMu)
func (m *IPMap) addLocked(op IPAddOp) {
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
		if entry, ok := existing.(*ipEntry); ok {
			// Clone current data, modify, and swap atomically
			current := entry.data.Load()
			var newData RemediationIdsMap
			if current != nil {
				newData = current.Clone()
			} else {
				newData = make(RemediationIdsMap)
			}
			newData.AddID(valueLog, op.R, op.ID, op.Origin)
			entry.data.Store(&newData)
			return
		}
	}

	// Create new entry with data
	// Since we hold writeMu, no race is possible - use Store directly
	newData := make(RemediationIdsMap)
	newData.AddID(valueLog, op.R, op.ID, op.Origin)
	entry := &ipEntry{}
	entry.data.Store(&newData)
	ipMap.Store(op.IP, entry)
	counter.Add(1)
}

// RemoveBatch removes multiple IPs from the map
// Returns a slice of pointers to successfully removed operations (nil for failures)
func (m *IPMap) RemoveBatch(operations []IPRemoveOp) []*IPRemoveOp {
	if len(operations) == 0 {
		return nil
	}

	// Hold write lock for entire batch to prevent interleaving
	m.writeMu.Lock()
	defer m.writeMu.Unlock()

	results := make([]*IPRemoveOp, len(operations))
	for i, op := range operations {
		if m.removeLocked(op) {
			results[i] = &operations[i]
		}
	}
	return results
}

// removeLocked removes a single IP (caller must hold writeMu)
func (m *IPMap) removeLocked(op IPRemoveOp) bool {
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

	entry, ok := existing.(*ipEntry)
	if !ok {
		return false
	}

	current := entry.data.Load()
	if current == nil {
		if valueLog != nil {
			valueLog.Trace("IP entry has no data")
		}
		return false
	}

	// Clone, modify, and swap
	newData := current.Clone()
	err := newData.RemoveID(valueLog, op.R, op.ID)
	if err != nil {
		if valueLog != nil {
			valueLog.Trace("ID not found for IP")
		}
		return false
	}

	// Check if entry is now empty
	if newData.IsEmpty() {
		ipMap.Delete(op.IP)
		counter.Add(-1)
		if valueLog != nil {
			valueLog.Trace("removed IP entirely")
		}
	} else {
		entry.data.Store(&newData)
		if valueLog != nil {
			valueLog.Trace("removed ID from IP")
		}
	}

	return true
}

// Contains checks if an IP address exists in the map
// Returns the remediation and origin if found
// This method is completely lock-free - SPOA handlers never block
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

	entry, ok := existing.(*ipEntry)
	if !ok {
		return remediation.Allow, "", false
	}

	// Lock-free read via atomic pointer
	data := entry.data.Load()
	if data == nil {
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
