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
// Buckets optimized for 0-500ms range with good granularity:
// - Fine-grained from 0.1ms to 100ms
// - More granular around 200-500ms (every 25ms) for accurate timeout monitoring
// - Extended beyond 500ms for outliers
var MessageDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
	Name: MessageDurationMetricName,
	Help: "Duration of processing SPOA messages in seconds",
	Buckets: []float64{
		// Fine-grained buckets: 0.1ms to 100ms
		0.0001, 0.0005, 0.001, 0.002, 0.005, // 0.1ms, 0.5ms, 1ms, 2ms, 5ms
		0.01, 0.02, 0.05, // 10ms, 20ms, 50ms
		0.1, 0.15, 0.2, // 100ms, 150ms, 200ms
		// High granularity around timeout threshold (200-500ms, every 25ms)
		0.225, 0.25, 0.275, 0.3, 0.325, 0.35, 0.375, 0.4, 0.425, 0.45, 0.475, 0.5,
		// Extended buckets for outliers beyond 500ms
		0.6, 0.8, 1.0, 1.5, 2.0, 3.0, 5.0, // 600ms to 5s
	},
}, []string{"message_type"})
