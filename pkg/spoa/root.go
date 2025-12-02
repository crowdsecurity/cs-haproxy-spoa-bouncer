package spoa

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"syscall"

	"github.com/crowdsecurity/crowdsec-spoa/internal/geo"
	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation/captcha"
	"github.com/crowdsecurity/crowdsec-spoa/internal/session"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/dataset"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/host"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/metrics"
	"github.com/negasus/haproxy-spoe-go/action"
	"github.com/negasus/haproxy-spoe-go/agent"
	"github.com/negasus/haproxy-spoe-go/message"
	"github.com/negasus/haproxy-spoe-go/request"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

var (
	messageNames = []string{"crowdsec-http", "crowdsec-ip"}
)

type Spoa struct {
	ListenAddr   net.Listener
	ListenSocket net.Listener
	Server       *agent.Agent
	logger       *log.Entry
	// Direct access to shared data (no IPC needed)
	dataset        *dataset.DataSet
	hostManager    *host.Manager
	geoDatabase    *geo.GeoDatabase
	globalSessions *session.Sessions // Global session manager for all hosts
}

type SpoaConfig struct {
	TcpAddr        string
	UnixAddr       string
	Dataset        *dataset.DataSet
	HostManager    *host.Manager
	GeoDatabase    *geo.GeoDatabase
	GlobalSessions *session.Sessions // Global session manager for all hosts
	Logger         *log.Entry        // Parent logger to inherit from
}

func New(config *SpoaConfig) (*Spoa, error) {
	if config == nil {
		return nil, fmt.Errorf("spoa configuration is nil")
	}

	if config.TcpAddr == "" && config.UnixAddr == "" {
		return nil, fmt.Errorf("at least one listener must be configured: set listen_tcp or listen_unix")
	}

	// Use provided logger or fallback to standard logger
	var workerLogger *log.Entry
	if config.Logger != nil {
		workerLogger = config.Logger
	} else {
		workerLogger = log.WithField("component", "spoa")
	}

	// No worker-specific log level; inherits from parent logger

	s := &Spoa{
		logger:         workerLogger,
		dataset:        config.Dataset,
		hostManager:    config.HostManager,
		geoDatabase:    config.GeoDatabase,
		globalSessions: config.GlobalSessions,
	}

	if config.TcpAddr != "" {
		addr, err := net.Listen("tcp", config.TcpAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to listen on %s: %w", config.TcpAddr, err)
		}
		s.ListenAddr = addr
	}

	if config.UnixAddr != "" {
		// Remove existing socket if present
		_ = syscall.Unlink(config.UnixAddr)

		// Set umask to 0o117 (result: 0o660 permissions)
		// Socket inherits group ownership from parent directory if setgid bit is set
		// When using systemd: RuntimeDirectoryMode=2750 already sets the setgid bit
		// For manual/Docker setups: chmod g+s /run/crowdsec-spoa && chgrp haproxy /run/crowdsec-spoa
		origUmask := syscall.Umask(0o117)

		// Create new socket
		addr, err := net.Listen("unix", config.UnixAddr)
		if err != nil {
			syscall.Umask(origUmask)
			return nil, fmt.Errorf("failed to listen on %s: %w", config.UnixAddr, err)
		}

		// Reset umask
		syscall.Umask(origUmask)

		s.ListenSocket = addr
	}

	s.Server = agent.New(handlerWrapper(s), s.logger)

	return s, nil
}

func (s *Spoa) Serve(ctx context.Context) error {
	serverError := make(chan error, 2)

	startServer := func(listener net.Listener) {
		err := s.Server.Serve(listener)
		switch {
		case errors.Is(err, net.ErrClosed):
			// Server closed normally during shutdown
		case err != nil:
			serverError <- err
		}
	}

	// Launch TCP server if configured
	if s.ListenAddr != nil {
		s.logger.Infof("Serving TCP server on %s", s.ListenAddr.Addr().String())
		go func() {
			startServer(s.ListenAddr)
		}()
	}

	// Launch Unix server if configured
	if s.ListenSocket != nil {
		s.logger.Infof("Serving Unix server on %s", s.ListenSocket.Addr().String())
		go func() {
			startServer(s.ListenSocket)
		}()
	}

	// If no listeners are configured, return immediately
	if s.ListenAddr == nil && s.ListenSocket == nil {
		return nil
	}

	select {
	case err := <-serverError:
		return err
	case <-ctx.Done():
		return nil
	}
}

func (s *Spoa) Shutdown(ctx context.Context) error {
	s.logger.Info("Shutting down")

	// Close TCP listener - the library now handles waiting for handlers internally
	if s.ListenAddr != nil {
		s.ListenAddr.Close()
	}

	// Close Unix socket - the library now handles waiting for handlers internally
	if s.ListenSocket != nil {
		s.ListenSocket.Close()
	}

	// The library's workgroup now handles waiting for all frame handlers to complete
	// when the listeners are closed, so we don't need to wait here
	return nil
}

// HTTPRequestData holds parsed HTTP request data for reuse across handlers
type HTTPRequestData struct {
	URL     *string
	Method  *string
	Body    *[]byte
	Headers http.Header
}

// Handles checking the http request which has 2 stages
// First stage is to check the host header and determine if the remediation from handleIpRequest is still valid
// Second stage is to check if AppSec is enabled and then forward to the component if needed
func (s *Spoa) handleHTTPRequest(req *request.Request, mes *message.Message) {
	r := remediation.Allow
	var origin string
	shouldCountMetrics := false

	rstring, err := readKeyFromMessage[string](mes, "remediation")
	if err != nil {
		// IP remediation not found - fallback to checking IP directly
		// This handles cases where crowdsec-ip message didn't fire (e.g., on-client-session not triggered)
		// Also handles upstream proxy mode where no IP check happened
		s.logger.WithFields(log.Fields{
			"error": err,
			"key":   "remediation",
		}).Debug("remediation key not found in message (expected from crowdsec-ip message), checking IP directly as fallback")
		// Get IP from message for both remediation and origin (needed for metrics)
		ipAddrPtr, ipErr := readKeyFromMessage[netip.Addr](mes, "src-ip")
		if ipErr == nil && ipAddrPtr != nil {
			r, origin = s.getIPRemediation(req, *ipAddrPtr)
			// Only count metrics if we successfully got IP and checked remediation
			shouldCountMetrics = true
		}
	}

	if rstring != nil {
		r = remediation.FromString(*rstring)
		// Remediation came from IP check, already counted
	}

	hoststring, err := readKeyFromMessage[string](mes, "host")

	var matchedHost *host.Host

	// defer a function that always add the remediation to the request at end of processing
	defer func() {
		if matchedHost == nil && r == remediation.Captcha {
			s.logger.Warn("remediation is captcha, no matching host was found cannot issue captcha remediation reverting to ban")
			r = remediation.Ban
		}
		rString := r.String()
		req.Actions.SetVar(action.ScopeTransaction, "remediation", rString)

		// Count metrics if this is the only handler (upstream proxy mode)
		if shouldCountMetrics {
			// Get IP from message for metrics
			ipTypeLabel := "ipv4"
			srcIP, ipErr := readKeyFromMessage[netip.Addr](mes, "src-ip")
			if ipErr != nil {
				s.logger.WithFields(log.Fields{
					"error": ipErr,
					"key":   "src-ip",
				}).Warn("failed to read src-ip from message for metrics, assuming ipv4")
			} else if srcIP != nil && srcIP.IsValid() && srcIP.Is6() {
				ipTypeLabel = "ipv6"
			}

			// Count processed request - use WithLabelValues to avoid map allocation on hot path
			metrics.TotalProcessedRequests.WithLabelValues(ipTypeLabel).Inc()

			// Count blocked request if remediation applied
			if r > remediation.Unknown {
				// Label order: origin, ip_type, remediation (as defined in metrics.go)
				metrics.TotalBlockedRequests.WithLabelValues(origin, ipTypeLabel, r.String()).Inc()
			}
		}
	}()

	if err != nil {
		s.logger.WithFields(log.Fields{
			"error": err,
			"key":   "host",
		}).Warn("failed to read host header from message, cannot match host configuration - ensure HAProxy is sending the 'host' variable in crowdsec-http message")
		return
	}

	matchedHost = s.hostManager.MatchFirstHost(*hoststring)

	// if the host is not found we cannot alter the remediation or do appsec checks
	if matchedHost == nil {
		return
	}

	var httpData HTTPRequestData

	switch r {
	case remediation.Allow:
		// If user has a captcha cookie but decision is Allow, generate unset cookie
		// We don't set captcha_status, so HAProxy knows to clear the cookie
		cookieB64, err := readKeyFromMessage[string](mes, "crowdsec_captcha_cookie")
		if err != nil && !errors.Is(err, ErrMessageKeyNotFound) {
			s.logger.WithFields(log.Fields{
				"error": err,
				"key":   "crowdsec_captcha_cookie",
			}).Debug("failed to read captcha cookie from message (cookie may not be present, which is expected)")
		}
		if cookieB64 != nil {
			ssl, err := readKeyFromMessage[bool](mes, "ssl")
			if err != nil {
				s.logger.WithFields(log.Fields{
					"error": err,
					"key":   "ssl",
				}).Warn("failed to read ssl flag from message, cookie secure flag will default to false - ensure HAProxy is sending the 'ssl_fc' variable as 'ssl' in crowdsec-http message")
			}

			unsetCookie, err := matchedHost.Captcha.CookieGenerator.GenerateUnsetCookie(ssl)
			if err != nil {
				s.logger.WithFields(log.Fields{
					"host":  matchedHost.Host,
					"ssl":   ssl,
					"error": err,
				}).Error("Failed to generate unset cookie")
				return // Cannot proceed without unset cookie
			}

			s.logger.WithFields(log.Fields{
				"host": matchedHost.Host,
			}).Debug("Allow decision but captcha cookie present, will clear cookie")
			req.Actions.SetVar(action.ScopeTransaction, "captcha_cookie", unsetCookie.String())
			// Note: We deliberately don't set captcha_status here
		}
		// Parse HTTP data for AppSec processing
		httpData = parseHTTPData(s.logger, mes)
	case remediation.Ban:
		//Handle ban
		matchedHost.Ban.InjectKeyValues(&req.Actions)
		// Parse HTTP data for AppSec processing
		httpData = parseHTTPData(s.logger, mes)
	case remediation.Captcha:
		r, httpData = s.handleCaptchaRemediation(req, mes, matchedHost)
		// If remediation changed to fallback, return early
		// If it became Allow, continue for AppSec processing
		if r != remediation.Captcha && r != remediation.Allow {
			return
		}
	}

	// If remediation is ban/captcha we dont need to create a request to send to appsec unless always send is on
	if r > remediation.Unknown && !matchedHost.AppSec.AlwaysSend {
		return
	}
	// !TODO APPSEC STUFF - httpData contains parsed URL, Method, Body, Headers for reuse
	_ = httpData // Reserved for AppSec implementation

	// request, err := http.NewRequest(httpData.Method, httpData.URL, strings.NewReader(httpData.Body))
	// if err != nil {
	// 	log.Printf("failed to create request: %v", err)
	// 	return
	// }
	// request.Header = httpData.Headers
}

// parseHTTPData extracts HTTP request data from the message for reuse in AppSec processing
//
//nolint:unparam // httpData will be used when AppSec is implemented
func parseHTTPData(logger *log.Entry, mes *message.Message) HTTPRequestData {
	var httpData HTTPRequestData

	url, err := readKeyFromMessage[string](mes, "url")
	if err != nil {
		logger.WithFields(log.Fields{
			"error": err,
			"key":   "url",
		}).Debug("failed to read url from message for AppSec processing - ensure HAProxy is sending the 'url' variable in crowdsec-http message")
	}
	httpData.URL = url

	method, err := readKeyFromMessage[string](mes, "method")
	if err != nil {
		logger.WithFields(log.Fields{
			"error": err,
			"key":   "method",
		}).Debug("failed to read method from message for AppSec processing - ensure HAProxy is sending the 'method' variable in crowdsec-http message")
	}
	httpData.Method = method

	headersType, err := readKeyFromMessage[string](mes, "headers")
	if err != nil {
		logger.WithFields(log.Fields{
			"error": err,
			"key":   "headers",
		}).Debug("failed to read headers from message for AppSec processing - ensure HAProxy is sending the 'headers' variable in crowdsec-http message")
	} else if headersType != nil {
		headers, parseErr := readHeaders(*headersType)
		if parseErr != nil {
			logger.WithFields(log.Fields{
				"error": parseErr,
				"key":   "headers",
			}).Debug("failed to parse headers from message for AppSec processing")
		} else {
			httpData.Headers = headers
		}
	}

	body, err := readKeyFromMessage[[]byte](mes, "body")
	if err != nil {
		logger.WithFields(log.Fields{
			"error": err,
			"key":   "body",
		}).Debug("failed to read body from message for AppSec processing - ensure HAProxy is sending the 'body' variable in crowdsec-http message")
	}
	httpData.Body = body

	return httpData
}

// createNewSessionAndCookie creates a new session, generates a cookie, and sets it in the request.
// Returns the session, uuid, and an error if any step fails.
func (s *Spoa) createNewSessionAndCookie(req *request.Request, mes *message.Message, matchedHost *host.Host) (*session.Session, string, error) {
	ssl, err := readKeyFromMessage[bool](mes, "ssl")
	if err != nil {
		s.logger.WithFields(log.Fields{
			"error": err,
			"key":   "ssl",
		}).Warn("failed to read ssl flag from message, cookie secure flag will default to false - ensure HAProxy is sending the 'ssl_fc' variable as 'ssl' in crowdsec-http message")
	}

	// Create a new session using global session manager
	ses, err := s.globalSessions.NewRandomSession()
	if err != nil {
		s.logger.WithFields(log.Fields{
			"host":  matchedHost.Host,
			"error": err,
		}).Error("Failed to create new session")
		return nil, "", err
	}

	cookie, err := matchedHost.Captcha.CookieGenerator.GenerateCookie(ses, ssl)
	if err != nil {
		s.logger.WithFields(log.Fields{
			"host":  matchedHost.Host,
			"ssl":   ssl,
			"error": err,
		}).Error("Failed to generate host cookie")
		return nil, "", err
	}

	// Set initial captcha status to pending
	ses.Set(session.CaptchaStatus, captcha.Pending)
	uuid := ses.UUID

	// Set the captcha cookie - status will be set later based on session state
	req.Actions.SetVar(action.ScopeTransaction, "captcha_cookie", cookie.String())

	return ses, uuid, nil
}

// handleCaptchaRemediation handles all captcha-related logic including cookie validation,
// session management, captcha validation, and status updates.
// Returns the remediation and parsed HTTP request data for reuse in AppSec processing.
func (s *Spoa) handleCaptchaRemediation(req *request.Request, mes *message.Message, matchedHost *host.Host) (remediation.Remediation, HTTPRequestData) {
	if err := matchedHost.Captcha.InjectKeyValues(&req.Actions); err != nil {
		return remediation.FromString(matchedHost.Captcha.FallbackRemediation), HTTPRequestData{}
	}

	cookieB64, err := readKeyFromMessage[string](mes, "crowdsec_captcha_cookie")
	if err != nil && !errors.Is(err, ErrMessageKeyNotFound) {
		s.logger.WithFields(log.Fields{
			"error": err,
			"key":   "crowdsec_captcha_cookie",
		}).Debug("failed to read captcha cookie from message (cookie may not be present, which is expected for new sessions)")
	}
	uuid := ""
	var ses *session.Session

	if cookieB64 != nil {
		var err error
		uuid, err = matchedHost.Captcha.CookieGenerator.ValidateCookie(*cookieB64)
		if err != nil {
			s.logger.WithFields(log.Fields{
				"host":  matchedHost.Host,
				"error": err,
			}).Warn("Failed to validate existing cookie")
			uuid = "" // Reset to generate new cookie
		}
	}

	if uuid == "" {
		// No valid cookie, create new session and cookie
		var err error
		ses, uuid, err = s.createNewSessionAndCookie(req, mes, matchedHost)
		if err != nil {
			// Session creation is critical for captcha to work - without it we can't track captcha status
			// This is a critical failure, so we must fall back to fallback remediation
			s.logger.WithFields(log.Fields{
				"host":  matchedHost.Host,
				"error": err,
			}).Error("Failed to create new session and cookie, falling back to fallback remediation")
			return remediation.FromString(matchedHost.Captcha.FallbackRemediation), HTTPRequestData{}
		}
	}

	if uuid == "" {
		// We should never hit this but safety net
		// As a fallback we set the remediation to the fallback remediation
		s.logger.Error("failed to get uuid from cookie")
		return remediation.FromString(matchedHost.Captcha.FallbackRemediation), HTTPRequestData{}
	}

	// Get the session only if we didn't just create it (i.e., we have an existing cookie)
	if ses == nil {
		ses = s.globalSessions.GetSession(uuid)
		if ses == nil {
			// Session lost from memory (e.g., after reload), create a new session and cookie
			s.logger.WithFields(log.Fields{
				"host":    matchedHost.Host,
				"session": uuid,
			}).Warn("Session not found in memory (likely lost after reload), creating new session and cookie")
			var err error
			ses, uuid, err = s.createNewSessionAndCookie(req, mes, matchedHost)
			if err != nil {
				// Session creation is critical for captcha to work - without it we can't track captcha status
				// This is a critical failure, so we must fall back to fallback remediation
				s.logger.WithFields(log.Fields{
					"host":  matchedHost.Host,
					"error": err,
				}).Error("Failed to create new session after reload, falling back to fallback remediation")
				return remediation.FromString(matchedHost.Captcha.FallbackRemediation), HTTPRequestData{}
			}
		}
	}

	// Get the current captcha status from the session (cache it to avoid redundant fetches)
	captchaStatus := ses.Get(session.CaptchaStatus)
	if captchaStatus == nil {
		captchaStatus = captcha.Pending // Assume pending if not set
	}

	// Set the captcha status in the transaction for HAProxy
	req.Actions.SetVar(action.ScopeTransaction, "captcha_status", captchaStatus)

	// Read URL - this is not critical for showing the captcha page, only for redirect after validation
	url, err := readKeyFromMessage[string](mes, "url")
	if err != nil {
		s.logger.WithFields(log.Fields{
			"error": err,
			"key":   "url",
			"host":  matchedHost.Host,
		}).Warn("failed to read url from message, captcha will still be shown but redirect after validation may not work - ensure HAProxy is sending the 'url' variable in crowdsec-http message")
		// Continue with captcha even without URL - we just won't be able to redirect after validation
	} else if captchaStatus != captcha.Valid && url != nil {
		// Update the incoming url if it is different from the stored url for the session ignore favicon requests
		storedURL := ses.Get(session.URI)
		if storedURL == nil {
			storedURL = ""
		}

		// Check url is not nil before dereferencing
		if (storedURL == "" || *url != storedURL) && !strings.HasSuffix(*url, ".ico") {
			s.logger.WithField("session", uuid).Debugf("updating stored url %s", *url)
			ses.Set(session.URI, *url)
		}
	}

	method, err := readKeyFromMessage[string](mes, "method")
	if err != nil {
		s.logger.WithFields(log.Fields{
			"error": err,
			"key":   "method",
			"host":  matchedHost.Host,
		}).Error("failed to read method from message, cannot validate captcha form submission - ensure HAProxy is sending the 'method' variable in crowdsec-http message")
		return remediation.Captcha, HTTPRequestData{URL: url} // Return partial data
	}

	headersType, err := readKeyFromMessage[string](mes, "headers")
	if err != nil {
		s.logger.WithFields(log.Fields{
			"error": err,
			"key":   "headers",
			"host":  matchedHost.Host,
		}).Error("failed to read headers from message, cannot validate captcha form submission - ensure HAProxy is sending the 'headers' variable in crowdsec-http message")
		return remediation.Captcha, HTTPRequestData{URL: url, Method: method} // Return partial data
	}

	headers, err := readHeaders(*headersType)
	if err != nil {
		s.logger.Errorf("failed to parse headers: %v", err)
	}

	httpData := HTTPRequestData{
		URL:     url,
		Method:  method,
		Headers: headers,
	}

	// Check if the request is a captcha validation request
	if captchaStatus == captcha.Pending && method != nil && *method == http.MethodPost && headers.Get("Content-Type") == "application/x-www-form-urlencoded" {
		body, err := readKeyFromMessage[[]byte](mes, "body")
		if err != nil {
			s.logger.WithFields(log.Fields{
				"error":   err,
				"key":     "body",
				"host":    matchedHost.Host,
				"session": uuid,
			}).Error("failed to read body from message, cannot validate captcha response - ensure HAProxy is sending the 'body' variable in crowdsec-http message for POST requests")
			return remediation.Captcha, httpData // Return data without body
		}

		httpData.Body = body

		// Validate captcha
		isValid, err := matchedHost.Captcha.Validate(context.Background(), uuid, string(*body))
		if err != nil {
			s.logger.WithFields(log.Fields{
				"host":    matchedHost.Host,
				"session": uuid,
				"error":   err,
			}).Error("Failed to validate captcha")
		} else if isValid {
			ses.Set(session.CaptchaStatus, captcha.Valid)
			captchaStatus = captcha.Valid // Update cached value
		}
	}

	// if the session has a valid captcha status we allow the request
	if captchaStatus == captcha.Valid {
		storedURL := ses.Get(session.URI)
		if storedURL != nil && storedURL != "" {
			s.logger.Debug("redirecting to: ", storedURL)
			req.Actions.SetVar(action.ScopeTransaction, "redirect", storedURL)
			// Delete the URI from the session so we dont redirect loop
			ses.Delete(session.URI)
		}
		return remediation.Allow, httpData
	}

	return remediation.Captcha, httpData
}

// getIPRemediation performs IP and geo/country remediation checks
// Returns the final remediation after checking IP, geo, and country
func (s *Spoa) getIPRemediation(req *request.Request, ip netip.Addr) (remediation.Remediation, string) {
	var origin string
	// Check IP directly against dataset
	r, origin, err := s.dataset.CheckIP(ip)
	if err != nil {
		s.logger.WithFields(log.Fields{
			"ip":    ip.String(),
			"error": err,
		}).Error("Failed to get IP remediation")
		return remediation.Allow, "" // Safe default
	}

	// Always try to get and set ISO code if geo database is available
	// This allows upstream services to use the ISO code regardless of remediation status
	if s.geoDatabase.IsValid() {
		record, err := s.geoDatabase.GetCity(ip)
		if err != nil && !errors.Is(err, geo.ErrNotValidConfig) {
			s.logger.WithFields(log.Fields{
				"ip":    ip.String(),
				"error": err,
			}).Warn("Failed to get geo location")
		} else if record != nil {
			iso := geo.GetIsoCodeFromRecord(record)
			if iso != "" {
				// Always set the ISO code variable when available
				req.Actions.SetVar(action.ScopeTransaction, "isocode", iso)

				// If no IP-specific remediation, check country-based remediation
				if r < remediation.Unknown {
					cnR, cnOrigin := s.dataset.CheckCN(iso)
					if cnR > remediation.Unknown {
						r = cnR
						origin = cnOrigin
					}
				}
			}
		}
	}

	return r, origin
}

// Handles checking the IP address against the dataset
func (s *Spoa) handleIPRequest(req *request.Request, mes *message.Message) {
	ipAddrPtr, err := readKeyFromMessage[netip.Addr](mes, "src-ip")
	if err != nil {
		s.logger.WithFields(log.Fields{
			"error": err,
			"key":   "src-ip",
		}).Error("failed to read src-ip from message, cannot check IP remediation - ensure HAProxy is sending the 'src' variable as 'src-ip' in crowdsec-ip message")
		return
	}

	ipAddr := *ipAddrPtr

	// Determine IP type for metrics
	ipTypeLabel := "ipv4"
	if ipAddr.Is6() {
		ipTypeLabel = "ipv6"
	}

	// Count processed requests - use WithLabelValues to avoid map allocation on hot path
	metrics.TotalProcessedRequests.WithLabelValues(ipTypeLabel).Inc()

	// Check IP directly against dataset
	r, origin := s.getIPRemediation(req, ipAddr)

	// Count blocked requests
	if r > remediation.Unknown {
		// Label order: origin, ip_type, remediation (as defined in metrics.go)
		metrics.TotalBlockedRequests.WithLabelValues(origin, ipTypeLabel, r.String()).Inc()
	}

	req.Actions.SetVar(action.ScopeTransaction, "remediation", r.String())
}

func handlerWrapper(s *Spoa) func(req *request.Request) {
	return func(req *request.Request) {
		// The library now handles workgroup tracking internally, no need for manual Add/Done
		for _, messageName := range messageNames {
			mes, err := req.Messages.GetByName(messageName)
			if err != nil {
				continue
			}
			s.logger.Trace("Received message: ", messageName)

			// Track duration for this message type - using WithLabelValues to avoid allocations
			timer := prometheus.NewTimer(metrics.MessageDuration.WithLabelValues(messageName))

			switch messageName {
			case "crowdsec-http":
				s.handleHTTPRequest(req, mes)
			case "crowdsec-ip":
				s.handleIPRequest(req, mes)
			}

			// Observe duration immediately after processing (allocation-free)
			// Note: If handler panics, duration won't be recorded, but panics are extremely rare in this path
			timer.ObserveDuration()
		}
	}
}

// readKeyFromMessage reads a key from a message and returns it as the type T
var (
	ErrMessageKeyNotFound     = errors.New("message key not found")
	ErrMessageKeyTypeMismatch = errors.New("message key type mismatch")
)

func readKeyFromMessage[T string | net.IP | netip.Addr | bool | []byte](msg *message.Message, key string) (*T, error) {
	value, ok := msg.KV.Get(key)
	if !ok || value == nil {
		return nil, fmt.Errorf("%w: %s", ErrMessageKeyNotFound, key)
	}

	var result T

	switch target := any(&result).(type) {
	case *string:
		str, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("%w: key %s has wrong type %T, expected string", ErrMessageKeyTypeMismatch, key, value)
		}
		*target = str
	case *bool:
		boolean, ok := value.(bool)
		if !ok {
			return nil, fmt.Errorf("%w: key %s has wrong type %T, expected bool", ErrMessageKeyTypeMismatch, key, value)
		}
		*target = boolean
	case *[]byte:
		bytes, ok := value.([]byte)
		if !ok {
			return nil, fmt.Errorf("%w: key %s has wrong type %T, expected []byte", ErrMessageKeyTypeMismatch, key, value)
		}
		*target = bytes
	case *net.IP:
		switch v := value.(type) {
		case net.IP:
			*target = v
		case string:
			ip := net.ParseIP(v)
			if ip == nil {
				return nil, fmt.Errorf("%w: key %s contains invalid IP string %q", ErrMessageKeyTypeMismatch, key, v)
			}
			*target = ip
		default:
			return nil, fmt.Errorf("%w: key %s has wrong type %T, expected net.IP or string", ErrMessageKeyTypeMismatch, key, value)
		}
	case *netip.Addr:
		switch v := value.(type) {
		case netip.Addr:
			*target = v
		case net.IP:
			addr, ok := netip.AddrFromSlice(v)
			if !ok {
				return nil, fmt.Errorf("%w: key %s contains invalid net.IP value", ErrMessageKeyTypeMismatch, key)
			}
			*target = addr
		case string:
			addr, err := netip.ParseAddr(v)
			if err != nil {
				return nil, fmt.Errorf("%w: key %s contains invalid IP string %q", ErrMessageKeyTypeMismatch, key, v)
			}
			*target = addr
		default:
			return nil, fmt.Errorf("%w: key %s has wrong type %T, expected netip.Addr, net.IP, or string", ErrMessageKeyTypeMismatch, key, value)
		}
	default:
		return nil, fmt.Errorf("unsupported type for readKeyFromMessage")
	}

	return &result, nil
}

func readHeaders(headers string) (http.Header, error) {
	h := http.Header{}
	hs := strings.Split(headers, "\r\n")

	if len(hs) == 0 {
		return nil, fmt.Errorf("no headers found")
	}

	for _, header := range hs {
		if header == "" {
			continue
		}

		kv := strings.SplitN(header, ":", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("invalid header: %q", header)
		}

		h.Add(strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1]))
	}
	return h, nil
}
