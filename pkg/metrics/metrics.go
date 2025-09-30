package metrics

import "github.com/prometheus/client_golang/prometheus"

const (
	BlockedRequestMetricName            = "crowdsec_haproxy_spoa_bouncer_blocked_requests"
	ProcessedRequestMetricName          = "crowdsec_haproxy_spoa_bouncer_processed_requests"
	ActiveDecisionsMetricName           = "crowdsec_haproxy_spoa_bouncer_active_decisions"
	WorkerAPIConnectionErrorsMetricName = "crowdsec_haproxy_spoa_bouncer_worker_api_connection_errors"
	WorkerAPIConnectionEventsMetricName = "crowdsec_haproxy_spoa_bouncer_worker_api_connection_events"
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

// Worker-to-API connection metrics
var TotalWorkerAPIConnectionErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: WorkerAPIConnectionErrorsMetricName,
	Help: "Total number of worker-to-API connection errors by type and worker",
}, []string{"worker_name", "error_type"}) // worker_name: specific worker identifier, error_type: decode, encode, connection

var TotalWorkerAPIConnectionEvents = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: WorkerAPIConnectionEventsMetricName,
	Help: "Total number of worker-to-API connection events",
}, []string{"worker_name", "event_type"}) // event_type: connect, disconnect
