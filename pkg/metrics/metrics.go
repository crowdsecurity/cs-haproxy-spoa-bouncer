package metrics

import "github.com/prometheus/client_golang/prometheus"

const (
	BlockedRequestMetricName   = "crowdsec_haproxy_spoa_bouncer_blocked_requests"
	ProcessedRequestMetricName = "crowdsec_haproxy_spoa_bouncer_processed_requests"
	ActiveDecisionsMetricName  = "crowdsec_haproxy_spoa_bouncer_active_decisions"
	MessageDurationMetricName  = "crowdsec_haproxy_spoa_bouncer_message_duration_seconds"
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

var TotalActiveDecisions = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: ActiveDecisionsMetricName,
	Help: "Total number of active decisions",
}, []string{"origin", "ip_type", "scope"})

// MessageDuration tracks the duration of processing each SPOA message type
// Labels: message_type (crowdsec-http, crowdsec-ip)
var MessageDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
	Name:    MessageDurationMetricName,
	Help:    "Duration of processing SPOA messages in seconds",
	Buckets: prometheus.ExponentialBuckets(0.0001, 2, 16), // 0.1ms to ~6.5s
}, []string{"message_type"})
