package spoa

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/crowdsecurity/crowdsec-spoa/internal/appsec"
	"github.com/crowdsecurity/crowdsec-spoa/internal/geo"
	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation/captcha"
	"github.com/crowdsecurity/crowdsec-spoa/internal/session"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/dataset"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/host"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/metrics"
	"github.com/crowdsecurity/go-cs-lib/ptr"
	"github.com/dropmorepackets/haproxy-go/pkg/encoding"
	"github.com/dropmorepackets/haproxy-go/spop"
	log "github.com/sirupsen/logrus"
)

var (
	// Maximum buffer sizes to prevent unbounded memory growth from outlier requests
	// If a request exceeds these sizes, we allocate a new buffer instead of reusing the pooled one
	maxHeadersBufferSize = 64 * 1024  // 64KB
	maxBodyBufferSize    = 512 * 1024 // 512KB

	// Message data struct pools for reducing GC pressure
	// These pools reuse both the structs and their embedded buffers
	httpMessageDataPool = sync.Pool{
		New: func() any {
			return &HTTPMessageData{
				// Pre-allocate buffers with reasonable initial capacity
				HeadersCopied: make([]byte, 0, 2048),
				BodyCopied:    make([]byte, 0, 4096),
			}
		},
	}

	ipMessageDataPool = sync.Pool{
		New: func() any {
			return &IPMessageData{}
		},
	}

	// Pre-allocated byte slices for key matching (avoid string conversions)
	// Using bytes.Equal is more efficient than k.NameEquals() which allocates
	keyRemediation = []byte("remediation")
	keySrcIP       = []byte("src-ip")
	// Note: Host and captcha cookie are now extracted from headers, no longer needed as separate KV
	keySSL     = []byte("ssl")
	keyURL     = []byte("url")
	keyMethod  = []byte("method")
	keyPath    = []byte("path")
	keyQuery   = []byte("query")
	keyVersion = []byte("version")
	keyID      = []byte("id")
	keySrcPort = []byte("src-port")
	keyHeaders = []byte("headers")
	keyBody    = []byte("body")

	// Pre-allocated byte slices for message name matching
	messageCrowdsecHTTPBody   = []byte("crowdsec-http-body")
	messageCrowdsecHTTPNoBody = []byte("crowdsec-http-no-body")
	messageCrowdsecTCP        = []byte("crowdsec-tcp")
)

type Spoa struct {
	ListenAddr   net.Listener
	ListenSocket net.Listener
	logger       *log.Entry
	// Direct access to shared data (no IPC needed)
	dataset        *dataset.DataSet
	hostManager    *host.Manager
	geoDatabase    *geo.GeoDatabase
	globalSessions *session.Sessions // Global session manager for all hosts
	globalAppSec   *appsec.AppSec    // Global AppSec config (used when no host matched)
}

type SpoaConfig struct {
	TcpAddr        string
	UnixAddr       string
	Dataset        *dataset.DataSet
	HostManager    *host.Manager
	GeoDatabase    *geo.GeoDatabase
	GlobalSessions *session.Sessions // Global session manager for all hosts
	GlobalAppSec   *appsec.AppSec    // Global AppSec config (used when no host matched)
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
		globalAppSec:   config.GlobalAppSec,
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

	return s, nil
}

// HandleSPOE implements the spop.Handler interface
func (s *Spoa) HandleSPOE(ctx context.Context, writer *encoding.ActionWriter, message *encoding.Message) {
	messageNameBytes := message.NameBytes()

	s.logger.Debugf("Received message: %s", messageNameBytes)

	switch {
	case bytes.Equal(messageNameBytes, messageCrowdsecTCP): //TCP message type always runs so match it first
		// TCP message type uses the same handler
		s.handleTCPRequest(ctx, writer, message)
	case bytes.Equal(messageNameBytes, messageCrowdsecHTTPBody), bytes.Equal(messageNameBytes, messageCrowdsecHTTPNoBody):
		// HTTP message types use the same handler
		// The handler will check if body is present in the message
		s.handleHTTPRequest(ctx, writer, message)
	default:
		// Unknown message type
		s.logger.Debugf("Unknown message type: %s", messageNameBytes)
	}
}

func (s *Spoa) Serve(ctx context.Context) error {
	serverError := make(chan error, 2)

	startServer := func(listener net.Listener) {
		agent := spop.Agent{
			Handler:     s,
			BaseContext: ctx,
		}
		err := agent.Serve(listener)
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

// HTTPMessageData holds all KV entries from crowdsec-http message
// Extracted in a single pass for efficiency
type HTTPMessageData struct {
	Remediation   *string
	SrcIP         *netip.Addr
	SrcPort       *int64
	Host          *string
	CaptchaCookie *string
	SSL           *bool
	URL           *string
	Method        *string
	Path          *string
	Query         *string
	Version       *string
	ID            *string // unique-id from HAProxy
	HeadersCopied []byte  // Copy of headers (reused from struct pool)
	BodyCopied    []byte  // Copy of body (reused from struct pool)
	HeadersParsed http.Header
}

// reset clears all fields in preparation for returning to pool
// Buffers are reset to length 0 but keep their capacity for reuse
func (d *HTTPMessageData) reset() {
	d.Remediation = nil
	d.SrcIP = nil
	d.SrcPort = nil
	d.Host = nil
	d.CaptchaCookie = nil
	d.SSL = nil
	d.URL = nil
	d.Method = nil
	d.Path = nil
	d.Query = nil
	d.Version = nil
	d.ID = nil
	// Reset buffer lengths but keep backing arrays for reuse
	d.HeadersCopied = d.HeadersCopied[:0]
	d.BodyCopied = d.BodyCopied[:0]
	d.HeadersParsed = nil
}

// IPMessageData holds all KV entries from crowdsec-ip message
// Extracted in a single pass for efficiency
type IPMessageData struct {
	SrcIP   netip.Addr
	SrcPort *int64
	ID      *string // unique-id from HAProxy
}

// reset clears all fields in preparation for returning to pool
func (d *IPMessageData) reset() {
	d.SrcIP = netip.Addr{}
	d.SrcPort = nil
	d.ID = nil
}

// extractHTTPMessageData extracts all KV entries from crowdsec-http message in a single pass
// Uses byte slice comparisons to avoid string allocations for key matching
// Returns a pooled struct that should be returned to pool via returnToPool()
func extractHTTPMessageData(mes *encoding.Message) *HTTPMessageData {
	data, ok := httpMessageDataPool.Get().(*HTTPMessageData)
	if !ok {
		// This should never happen, but handle gracefully
		data = &HTTPMessageData{
			HeadersCopied: make([]byte, 0, 2048),
			BodyCopied:    make([]byte, 0, 4096),
		}
	}
	// Note: reset() is called before Put() in the defer block, so no need to reset here
	k := encoding.AcquireKVEntry()
	defer encoding.ReleaseKVEntry(k)

	for mes.KV.Next(k) {
		nameBytes := k.NameBytes()
		switch {
		case bytes.Equal(nameBytes, keyRemediation):
			val := string(k.ValueBytes())
			data.Remediation = ptr.Of(val)
		case bytes.Equal(nameBytes, keySrcIP):
			val := k.ValueAddr()
			data.SrcIP = ptr.Of(val)
		// Note: Host and captcha cookie are now extracted from headers, no longer needed as separate KV
		case bytes.Equal(nameBytes, keySSL):
			val := k.ValueBool()
			data.SSL = ptr.Of(val)
		case bytes.Equal(nameBytes, keyURL):
			val := string(k.ValueBytes())
			data.URL = ptr.Of(val)
		case bytes.Equal(nameBytes, keyMethod):
			val := string(k.ValueBytes())
			data.Method = ptr.Of(val)
		case bytes.Equal(nameBytes, keyPath):
			val := string(k.ValueBytes())
			data.Path = ptr.Of(val)
		case bytes.Equal(nameBytes, keyQuery):
			val := string(k.ValueBytes())
			data.Query = ptr.Of(val)
		case bytes.Equal(nameBytes, keyVersion):
			val := string(k.ValueBytes())
			data.Version = ptr.Of(val)
		case bytes.Equal(nameBytes, keyID):
			val := string(k.ValueBytes())
			data.ID = ptr.Of(val)
		case bytes.Equal(nameBytes, keySrcPort):
			val := k.ValueInt()
			data.SrcPort = ptr.Of(val)
		case bytes.Equal(nameBytes, keyHeaders):
			// Copy borrowed slice immediately - k.ValueBytes() returns memory owned by KV entry
			// which will be overwritten on next iteration, so we must copy now
			headersBytes := k.ValueBytes()
			// Reuse existing buffer if it has enough capacity and isn't too large, otherwise allocate new one
			// Use >= to handle the edge case where capacity exactly equals maxHeadersBufferSize
			if cap(data.HeadersCopied) < len(headersBytes) || cap(data.HeadersCopied) >= maxHeadersBufferSize {
				data.HeadersCopied = make([]byte, len(headersBytes))
			} else {
				// Reuse buffer, reset length (copy will overwrite old data)
				data.HeadersCopied = data.HeadersCopied[:len(headersBytes)]
			}
			copy(data.HeadersCopied, headersBytes)
		case bytes.Equal(nameBytes, keyBody):
			// Copy borrowed slice immediately - k.ValueBytes() returns memory owned by KV entry
			// which will be overwritten on next iteration, so we must copy now
			bodyBytes := k.ValueBytes()
			// Reuse existing buffer if it has enough capacity and isn't too large, otherwise allocate new one
			// Use >= to handle the edge case where capacity exactly equals maxBodyBufferSize
			if cap(data.BodyCopied) < len(bodyBytes) || cap(data.BodyCopied) >= maxBodyBufferSize {
				data.BodyCopied = make([]byte, len(bodyBytes))
			} else {
				// Reuse buffer, reset length (copy will overwrite old data)
				data.BodyCopied = data.BodyCopied[:len(bodyBytes)]
			}
			copy(data.BodyCopied, bodyBytes)
		default:
			// Unknown key, ignore
		}
	}

	// Parse headers if present
	if len(data.HeadersCopied) > 0 {
		headers, err := readHeaders(data.HeadersCopied)
		if err == nil {
			data.HeadersParsed = headers
			// Extract Host from headers if not provided as separate KV pair
			// This avoids needing to send it separately since it's already in headers
			if data.Host == nil {
				if hostHeader := headers.Get("Host"); hostHeader != "" {
					data.Host = ptr.Of(hostHeader)
				}
			}
			// Extract captcha cookie from Cookie header if present
			// This avoids needing to send it as a separate KV pair
			if cookieHeader := headers.Get("Cookie"); cookieHeader != "" {
				if captchaCookie := extractCookieValue(cookieHeader, "crowdsec_captcha_cookie"); captchaCookie != "" {
					data.CaptchaCookie = ptr.Of(captchaCookie)
				}
			}
		}
	}

	return data
}

// extractCookieValue extracts a specific cookie value from a Cookie header string
func extractCookieValue(cookieHeader, cookieName string) string {
	// Cookie header format: "name1=value1; name2=value2; ..."
	prefix := cookieName + "="
	for cookie := range strings.SplitSeq(cookieHeader, ";") {
		if value, found := strings.CutPrefix(strings.TrimSpace(cookie), prefix); found {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// Handles checking the http request which has 2 stages
// First stage is to always check the IP (even if remediation was passed from TCP handler)
//   - Compare with passed remediation, only count metrics if remediation changed
//
// Second stage is to check if AppSec is enabled and then forward to the component if needed
// Body will be checked automatically - if not present in message, it will be nil
func (s *Spoa) handleHTTPRequest(ctx context.Context, writer *encoding.ActionWriter, mes *encoding.Message) {
	// Extract all message data in a single pass
	msgData := extractHTTPMessageData(mes)
	// Return struct (with embedded buffers) to pool when done
	defer func() {
		msgData.reset()
		httpMessageDataPool.Put(msgData)
	}()

	var tcpRemediation remediation.Remediation

	// Get remediation passed from crowdsec-tcp handler (if any)
	if msgData.Remediation != nil {
		tcpRemediation = remediation.FromString(*msgData.Remediation)
	}

	// Always check IP - we cannot trust if src-ip has changed since TCP handler ran
	if msgData.SrcIP == nil {
		s.logger.WithFields(log.Fields{
			"key": "src-ip",
		}).Error("failed to read src-ip from message, cannot check IP remediation")
		// Fall back to TCP remediation if available
		if msgData.Remediation != nil {
			_ = writer.SetString(encoding.VarScopeTransaction, "remediation", tcpRemediation.String())
		}
		return
	}

	// Always check IP remediation
	r, origin := s.getIPRemediation(ctx, writer, *msgData.SrcIP)

	var matchedHost *host.Host
	datasetRemediation := r // Track remediation after dataset check (before AppSec)

	// defer a function that always sets the remediation and counts metrics at end of processing
	defer func() {
		// Handle captcha without matched host - must revert to ban
		if matchedHost == nil && r == remediation.Captcha {
			s.logger.Warn("remediation is captcha, no matching host was found cannot issue captcha remediation reverting to ban")
			r = remediation.Ban
		}

		// Always set the final remediation in the transaction
		_ = writer.SetString(encoding.VarScopeTransaction, "remediation", r.String())

		// Metrics counting logic:
		//
		// Who counts what:
		// - TCP handler: counts processed + blocked when it runs
		// - HTTP handler (here): counts processed only when TCP didn't run
		// - HTTP handler (here): counts dataset-blocked only when dataset escalated
		// - AppSec: counts its own blocks in validateWithAppSec (origin="appsec")
		//
		// This prevents double-counting:
		// - If TCP ran and blocked: TCP already counted, we skip
		// - If TCP ran and allowed, dataset blocks: we count dataset metric
		// - If TCP ran and allowed, only AppSec blocks: AppSec already counted, we skip
		// - If TCP didn't run, dataset blocks: we count processed + dataset metric
		// - If TCP didn't run, only AppSec blocks: we count processed, AppSec counts its block

		tcpRan := msgData.Remediation != nil
		tcpAllowed := tcpRan && tcpRemediation == remediation.Allow
		datasetBlocked := datasetRemediation > remediation.Unknown

		// Get IP type for metrics (compute once)
		ipTypeLabel := "ipv4"
		if msgData.SrcIP != nil && msgData.SrcIP.IsValid() && msgData.SrcIP.Is6() {
			ipTypeLabel = "ipv6"
		}

		// Count processed if TCP didn't run (TCP counts it otherwise)
		if !tcpRan {
			metrics.TotalProcessedRequests.WithLabelValues(ipTypeLabel).Inc()
		}

		// Count dataset-blocked if:
		// 1. Dataset escalated (datasetRemediation > Unknown), AND
		// 2. Either TCP didn't run, OR TCP found Allow
		// (If TCP found bad remediation, it already counted the block)
		if datasetBlocked && (!tcpRan || tcpAllowed) {
			metrics.TotalBlockedRequests.WithLabelValues(origin, ipTypeLabel, datasetRemediation.String()).Inc()
		}
	}()

	if msgData.Host == nil {
		s.logger.Warn("failed to read host header from message, cannot match host configuration - ensure HAProxy is sending the 'host' variable in crowdsec-http message")
		return
	}

	matchedHost = s.hostManager.MatchFirstHost(*msgData.Host)

	// if the host is not found, we can still do AppSec checks if global AppSec is configured
	if matchedHost == nil {
		// Use global AppSec if configured (no always_send check for global, but respect remediation)
		// For global AppSec, we always check unless remediation is already restrictive (no always_send option)
		if s.globalAppSec != nil && s.globalAppSec.IsValid() && r < remediation.Captcha {
			r = s.validateWithAppSec(ctx, msgData, nil, s.globalAppSec, r, s.globalAppSec.TimeoutOrDefault())
		}
		return
	}

	switch r {
	case remediation.Allow:
		// If user has a captcha cookie but decision is Allow, generate unset cookie
		// We don't set captcha_status, so HAProxy knows to clear the cookie
		// Check for both nil and empty string (HAProxy may send empty string when cookie doesn't exist)
		if msgData.CaptchaCookie != nil && *msgData.CaptchaCookie != "" {
			var ssl *bool
			if msgData.SSL != nil {
				ssl = msgData.SSL
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
			_ = writer.SetString(encoding.VarScopeTransaction, "captcha_cookie", unsetCookie.String())
			// Note: We deliberately don't set captcha_status here
		}
	case remediation.Ban:
		//Handle ban
		matchedHost.Ban.InjectKeyValues(writer)
	case remediation.Captcha:
		r = s.handleCaptchaRemediation(ctx, writer, msgData, matchedHost)
		// If remediation changed to fallback, return early
		// If it became Allow, continue for AppSec processing
		if r != remediation.Captcha && r != remediation.Allow {
			return
		}
	}

	// Validate with AppSec - check remediation and always_send logic
	// Use host-specific AppSec if valid, otherwise fall back to global AppSec
	var appSecToUse *appsec.AppSec
	alwaysSend := matchedHost.AppSec.AlwaysSend
	if matchedHost.AppSec.IsValid() {
		appSecToUse = &matchedHost.AppSec
	} else if s.globalAppSec != nil && s.globalAppSec.IsValid() {
		appSecToUse = s.globalAppSec
		s.logger.Debug("Using global AppSec config (host-specific AppSec not configured)")
	}

	requestTimeout := matchedHost.AppSec.TimeoutOrDefault()
	if matchedHost.AppSec.Timeout <= 0 && appSecToUse != nil {
		// Host didn't override timeout, use whichever AppSec client we call (host or global)
		requestTimeout = appSecToUse.TimeoutOrDefault()
	}

	// If remediation is ban/captcha we dont need to create a request to send to appsec unless always send is on
	// Use >= Captcha to make intent explicit: skip AppSec for restrictive remediations (Captcha/Ban)
	if appSecToUse != nil && (r < remediation.Captcha || alwaysSend) {
		r = s.validateWithAppSec(ctx, msgData, matchedHost, appSecToUse, r, requestTimeout)
		// If AppSec returns ban, inject ban values
		if r == remediation.Ban {
			matchedHost.Ban.InjectKeyValues(writer)
		}
	}
}

// validateWithAppSec performs AppSec validation and returns the remediation
// Returns the more restrictive remediation between the current remediation and AppSec result
func (s *Spoa) validateWithAppSec(
	ctx context.Context,
	msgData *HTTPMessageData,
	matchedHost *host.Host,
	appSecToUse *appsec.AppSec,
	currentRemediation remediation.Remediation,
	requestTimeout time.Duration,
) remediation.Remediation {
	appSecReq := msgData.buildAppSecRequest()

	// Create logger with host context
	logger := s.logger
	if appSecReq.Host != "" {
		logger = logger.WithField("host", appSecReq.Host)
	}
	if matchedHost != nil {
		logger = logger.WithField("matched_host", matchedHost.Host)
	}

	// Validate with AppSec - derive context from handler so requests cancel on shutdown
	appSecCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	appSecRemediation, err := appSecToUse.ValidateRequest(appSecCtx, appSecReq)
	if err != nil {
		logger.WithError(err).Warn("AppSec validation failed, using original remediation")
		return currentRemediation
	}

	// Track AppSec block metrics
	if appSecRemediation > remediation.Allow && appSecReq.RemoteIP != "" {
		if ipAddr, parseErr := netip.ParseAddr(appSecReq.RemoteIP); parseErr == nil {
			ipType := "ipv4"
			if ipAddr.Is6() {
				ipType = "ipv6"
			}
			metrics.TotalBlockedRequests.WithLabelValues("appsec", ipType, appSecRemediation.String()).Inc()
		}
	}

	// Return the more restrictive remediation (never downgrade security)
	if appSecRemediation > currentRemediation {
		if appSecRemediation == remediation.Ban && matchedHost == nil {
			logger.Warn("AppSec returned ban but no host matched - remediation set but ban values not injected")
		}
		return appSecRemediation
	}
	return currentRemediation
}

// buildAppSecRequest constructs an AppSecRequest from HTTPMessageData
func (d *HTTPMessageData) buildAppSecRequest() *appsec.AppSecRequest {
	req := &appsec.AppSecRequest{
		Headers: d.HeadersParsed,
	}

	if d.Host != nil {
		req.Host = *d.Host
	}
	if d.SrcIP != nil {
		req.RemoteIP = d.SrcIP.String()
	}
	if d.Method != nil {
		req.Method = *d.Method
	}
	if d.URL != nil {
		req.URL = *d.URL
	}
	if d.Version != nil {
		req.Version = *d.Version
	}
	if d.HeadersParsed != nil {
		req.UserAgent = d.HeadersParsed.Get("User-Agent")
	}
	if len(d.BodyCopied) > 0 {
		// Copy body to avoid issues with pooled buffer
		req.Body = make([]byte, len(d.BodyCopied))
		copy(req.Body, d.BodyCopied)
	}

	return req
}

// getSessionString safely extracts a string value from a session key
func getSessionString(ses *session.Session, key string) string {
	val := ses.Get(key)
	if val == nil {
		return ""
	}
	if s, ok := val.(string); ok {
		return s
	}
	return ""
}

// createNewSessionAndCookie creates a new session, generates a cookie, and sets it in the request.
// Returns the session, uuid, and an error if any step fails.
func (s *Spoa) createNewSessionAndCookie(writer *encoding.ActionWriter, msgData *HTTPMessageData, matchedHost *host.Host) (*session.Session, string, error) {
	ses, err := s.globalSessions.NewRandomSession()
	if err != nil {
		s.logger.WithFields(log.Fields{
			"host":  matchedHost.Host,
			"error": err,
		}).Error("Failed to create new session")
		return nil, "", err
	}

	cookie, err := matchedHost.Captcha.CookieGenerator.GenerateCookie(ses, msgData.SSL)
	if err != nil {
		s.logger.WithFields(log.Fields{
			"host":  matchedHost.Host,
			"ssl":   msgData.SSL,
			"error": err,
		}).Error("Failed to generate host cookie")
		return nil, "", err
	}

	ses.Set(session.CaptchaStatus, captcha.Pending)
	_ = writer.SetString(encoding.VarScopeTransaction, "captcha_cookie", cookie.String())

	return ses, ses.UUID, nil
}

// handleCaptchaRemediation handles all captcha-related logic including cookie validation,
// session management, captcha validation, and status updates.
func (s *Spoa) handleCaptchaRemediation(ctx context.Context, writer *encoding.ActionWriter, msgData *HTTPMessageData, matchedHost *host.Host) remediation.Remediation {
	fallback := remediation.FromString(matchedHost.Captcha.FallbackRemediation)

	if err := matchedHost.Captcha.InjectKeyValues(writer); err != nil {
		return fallback
	}

	// Get or create session
	ses, uuid := s.getOrCreateCaptchaSession(writer, msgData, matchedHost)
	if ses == nil {
		return fallback
	}

	// Get captcha status (defaults to pending if not set)
	captchaStatus := getSessionString(ses, session.CaptchaStatus)
	if captchaStatus == "" {
		captchaStatus = captcha.Pending
	}
	_ = writer.SetString(encoding.VarScopeTransaction, "captcha_status", captchaStatus)

	// Store URL for redirect after validation (skip favicon requests)
	if msgData.URL != nil && captchaStatus != captcha.Valid {
		storedURL := getSessionString(ses, session.URI)
		if (storedURL == "" || *msgData.URL != storedURL) && !strings.HasSuffix(*msgData.URL, ".ico") {
			ses.Set(session.URI, *msgData.URL)
		}
	}

	// Try to validate captcha if this is a form submission
	if captchaStatus == captcha.Pending {
		captchaStatus = s.tryValidateCaptcha(ctx, ses, msgData, matchedHost, uuid)
	}

	// Allow if captcha is valid, with redirect to original URL
	if captchaStatus == captcha.Valid {
		if storedURL := getSessionString(ses, session.URI); storedURL != "" {
			s.logger.Debug("redirecting to: ", storedURL)
			_ = writer.SetString(encoding.VarScopeTransaction, "redirect", storedURL)
			ses.Delete(session.URI)
		}
		return remediation.Allow
	}

	return remediation.Captcha
}

// getOrCreateCaptchaSession retrieves an existing session from cookie or creates a new one
func (s *Spoa) getOrCreateCaptchaSession(writer *encoding.ActionWriter, msgData *HTTPMessageData, matchedHost *host.Host) (*session.Session, string) {
	// Try to get session from existing cookie
	if msgData.CaptchaCookie != nil && *msgData.CaptchaCookie != "" {
		uuid, err := matchedHost.Captcha.CookieGenerator.ValidateCookie(*msgData.CaptchaCookie)
		if err != nil {
			s.logger.WithFields(log.Fields{
				"host":  matchedHost.Host,
				"error": err,
			}).Warn("Failed to validate existing cookie")
		} else if ses := s.globalSessions.GetSession(uuid); ses != nil {
			return ses, uuid
		} else {
			s.logger.WithFields(log.Fields{
				"host":    matchedHost.Host,
				"session": uuid,
			}).Warn("Session not found in memory (likely lost after reload)")
		}
	}

	// Create new session
	ses, uuid, err := s.createNewSessionAndCookie(writer, msgData, matchedHost)
	if err != nil {
		s.logger.WithFields(log.Fields{
			"host":  matchedHost.Host,
			"error": err,
		}).Error("Failed to create captcha session, falling back")
		return nil, ""
	}
	return ses, uuid
}

// tryValidateCaptcha attempts to validate a captcha form submission
// Returns the new captcha status (Valid if successful, Pending otherwise)
func (s *Spoa) tryValidateCaptcha(ctx context.Context, ses *session.Session, msgData *HTTPMessageData, matchedHost *host.Host, uuid string) string {
	// Check if this is a captcha form submission
	if msgData.Method == nil || *msgData.Method != http.MethodPost {
		return captcha.Pending
	}
	if msgData.HeadersParsed == nil || msgData.HeadersParsed.Get("Content-Type") != "application/x-www-form-urlencoded" {
		return captcha.Pending
	}
	if len(msgData.BodyCopied) == 0 {
		s.logger.WithFields(log.Fields{
			"host":    matchedHost.Host,
			"session": uuid,
		}).Error("No body in captcha POST request")
		return captcha.Pending
	}

	isValid, err := matchedHost.Captcha.Validate(ctx, uuid, string(msgData.BodyCopied))
	if err != nil {
		s.logger.WithFields(log.Fields{
			"host":    matchedHost.Host,
			"session": uuid,
			"error":   err,
		}).Error("Failed to validate captcha")
		return captcha.Pending
	}

	if isValid {
		ses.Set(session.CaptchaStatus, captcha.Valid)
		return captcha.Valid
	}
	return captcha.Pending
}

// getIPRemediation performs IP and geo/country remediation checks
// Returns the final remediation after checking IP, geo, and country
func (s *Spoa) getIPRemediation(_ context.Context, writer *encoding.ActionWriter, ip netip.Addr) (remediation.Remediation, string) {
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
				_ = writer.SetString(encoding.VarScopeTransaction, "isocode", iso)

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

// extractIPMessageData extracts all KV entries from crowdsec-ip message in a single pass
// Returns a pooled struct that should be returned to pool via returnToPool()
func extractIPMessageData(mes *encoding.Message) (*IPMessageData, error) {
	data, ok := ipMessageDataPool.Get().(*IPMessageData)
	if !ok {
		// This should never happen, but handle gracefully
		data = &IPMessageData{}
	}
	// Note: reset() is called before Put() in the defer block, so no need to reset here
	k := encoding.AcquireKVEntry()
	defer encoding.ReleaseKVEntry(k)

	foundIP := false
	for mes.KV.Next(k) {
		nameBytes := k.NameBytes()
		switch {
		case bytes.Equal(nameBytes, keySrcIP):
			data.SrcIP = k.ValueAddr()
			foundIP = true
		case bytes.Equal(nameBytes, keySrcPort):
			val := k.ValueInt()
			data.SrcPort = ptr.Of(val)
		case bytes.Equal(nameBytes, keyID):
			val := string(k.ValueBytes())
			data.ID = ptr.Of(val)
		default:
			// Unknown key, ignore
		}
	}

	if !foundIP {
		// Return struct to pool on error
		data.reset()
		ipMessageDataPool.Put(data)
		return nil, fmt.Errorf("src-ip key not found in message")
	}

	return data, nil
}

// handleTCPRequest performs TCP-level IP checking during the on-client-session event.
// It extracts the source IP from the incoming message and checks it against the dataset
// to determine if remediation is required. This function runs early in the connection
// lifecycle, before HTTP-level processing, to enable fast blocking or remediation decisions.
func (s *Spoa) handleTCPRequest(ctx context.Context, writer *encoding.ActionWriter, mes *encoding.Message) {
	msgData, err := extractIPMessageData(mes)
	if err != nil {
		s.logger.WithFields(log.Fields{
			"error": err,
			"key":   "src-ip",
		}).Error("failed to read src-ip from message, cannot check IP remediation - ensure HAProxy is sending the 'src' variable as 'src-ip' in crowdsec-ip message")
		// Note: extractIPMessageData already returns struct to pool on error, so msgData is nil here
		return
	}
	// Return struct to pool when done
	defer func() {
		msgData.reset()
		ipMessageDataPool.Put(msgData)
	}()

	ipAddr := msgData.SrcIP

	// Determine IP type for metrics
	ipTypeLabel := "ipv4"
	if ipAddr.Is6() {
		ipTypeLabel = "ipv6"
	}

	// Count processed requests - use WithLabelValues to avoid map allocation on hot path
	metrics.TotalProcessedRequests.WithLabelValues(ipTypeLabel).Inc()

	// Check IP directly against dataset
	r, origin := s.getIPRemediation(ctx, writer, ipAddr)

	// Count blocked requests
	if r > remediation.Unknown {
		// Label order: origin, ip_type, remediation (as defined in metrics.go)
		metrics.TotalBlockedRequests.WithLabelValues(origin, ipTypeLabel, r.String()).Inc()
	}

	_ = writer.SetString(encoding.VarScopeTransaction, "remediation", r.String())
}

func readHeaders(headers []byte) (http.Header, error) {
	h := http.Header{}
	if len(headers) == 0 {
		return nil, fmt.Errorf("no headers found")
	}

	// Normalize line endings: replace \r\n with \n first, then split by \n
	// HAProxy's req.hdrs can send headers with either \r\n or \n separators
	// We do this in-place to avoid extra allocations
	normalized := bytes.ReplaceAll(headers, []byte("\r\n"), []byte("\n"))

	// Split by \n using bytes.SplitSeq to avoid allocating a slice upfront
	for headerLine := range bytes.SplitSeq(normalized, []byte("\n")) {
		// Trim whitespace from the line
		headerLine = bytes.TrimSpace(headerLine)
		if len(headerLine) == 0 {
			continue
		}

		// Find colon separator in byte slice
		colonIdx := bytes.IndexByte(headerLine, ':')
		if colonIdx == -1 {
			// Skip lines without colon (might be continuation or malformed)
			// Log debug message to aid in debugging HAProxy configuration issues
			log.WithField("header", string(headerLine)).Debug("Skipping malformed header line without colon separator")
			continue
		}

		// Convert only the key and value parts to strings (not the entire header)
		key := strings.TrimSpace(string(headerLine[:colonIdx]))
		value := strings.TrimSpace(string(headerLine[colonIdx+1:]))

		h.Add(key, value)
	}
	return h, nil
}
