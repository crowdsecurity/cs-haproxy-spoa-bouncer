package metrics

import "github.com/prometheus/client_golang/prometheus"

const (
	BlockedRequestMetricName   = "crowdsec_haproxy_spoa_bouncer_blocked_requests"
	ProcessedRequestMetricName = "crowdsec_haproxy_spoa_bouncer_processed_requests"
	ActiveBannedIPsMetricName  = "crowdsec_haproxy_spoa_bouncer_banned_ips"
)

var TotalBlockedRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: BlockedRequestMetricName,
	Help: "Total number of blocked requests",
}, []string{"origin", "ip_type", "remediation"})
var LastBlockedRequestValue map[string]float64 = make(map[string]float64)

var TotalProcessedRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: ProcessedRequestMetricName,
	Help: "Total number of processed requests",
}, []string{"ip_type"})
var LastProcessedRequestValue map[string]float64 = make(map[string]float64)

var TotalActiveBannedIPs = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: ActiveBannedIPsMetricName,
	Help: "Total number of active banned IPs",
}, []string{"origin", "ip_type"})
