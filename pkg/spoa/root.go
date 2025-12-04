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

	"github.com/crowdsecurity/crowdsec-spoa/internal/geo"
	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation/captcha"
	"github.com/crowdsecurity/crowdsec-spoa/internal/session"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/dataset"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/host"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/metrics"
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
		New: func() interface{} {
			return &HTTPMessageData{
				// Pre-allocate buffers with reasonable initial capacity
				HeadersCopied: make([]byte, 0, 2048),
				BodyCopied:    make([]byte, 0, 4096),
			}
		},
	}

	ipMessageDataPool = sync.Pool{
		New: func() interface{} {
			return &IPMessageData{}
		},
	}

	// Pre-allocated byte slices for key matching (avoid string conversions)
	// Using bytes.Equal is more efficient than k.NameEquals() which allocates
	keyRemediation   = []byte("remediation")
	keySrcIP         = []byte("src-ip")
	keyHost          = []byte("host")
	keyCaptchaCookie = []byte("crowdsec_captcha_cookie")
	keySSL           = []byte("ssl")
	keyURL           = []byte("url")
	keyMethod        = []byte("method")
	keyPath          = []byte("path")
	keyQuery         = []byte("query")
	keyVersion       = []byte("version")
	keyID            = []byte("id")
	keySrcPort       = []byte("src-port")
	keyHeaders       = []byte("headers")
	keyBody          = []byte("body")

	// Pre-allocated byte slices for message name matching
	messageCrowdsecHTTP = []byte("crowdsec-http")
	messageCrowdsecIP   = []byte("crowdsec-ip")
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

	return s, nil
}

// HandleSPOE implements the spop.Handler interface
func (s *Spoa) HandleSPOE(ctx context.Context, writer *encoding.ActionWriter, message *encoding.Message) {
	messageNameBytes := message.NameBytes()
	s.logger.Trace("Received message: ", string(messageNameBytes))

	switch {
	case bytes.Equal(messageNameBytes, messageCrowdsecHTTP):
		s.handleHTTPRequest(ctx, writer, message)
	case bytes.Equal(messageNameBytes, messageCrowdsecIP):
		s.handleIPRequest(ctx, writer, message)
	default:
		s.logger.Debugf("Unknown message type: %s", string(messageNameBytes))
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

// HTTPRequestData holds parsed HTTP request data for reuse across handlers
type HTTPRequestData struct {
	URL     *string
	Method  *string
	Body    *[]byte
	Headers http.Header
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

// Helper functions to allocate values on heap explicitly
// These ensure values are heap-allocated rather than relying on escape analysis
func stringPtr(s string) *string {
	return &s
}

func boolPtr(b bool) *bool {
	return &b
}

func int64Ptr(i int64) *int64 {
	return &i
}

func addrPtr(a netip.Addr) *netip.Addr {
	return &a
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
	data.reset() // Clear any previous data
	k := encoding.AcquireKVEntry()
	defer encoding.ReleaseKVEntry(k)

	for mes.KV.Next(k) {
		nameBytes := k.NameBytes()
		switch {
		case bytes.Equal(nameBytes, keyRemediation):
			val := string(k.ValueBytes())
			data.Remediation = stringPtr(val)
		case bytes.Equal(nameBytes, keySrcIP):
			val := k.ValueAddr()
			data.SrcIP = addrPtr(val)
		case bytes.Equal(nameBytes, keyHost):
			val := string(k.ValueBytes())
			data.Host = stringPtr(val)
		case bytes.Equal(nameBytes, keyCaptchaCookie):
			val := string(k.ValueBytes())
			data.CaptchaCookie = stringPtr(val)
		case bytes.Equal(nameBytes, keySSL):
			val := k.ValueBool()
			data.SSL = boolPtr(val)
		case bytes.Equal(nameBytes, keyURL):
			val := string(k.ValueBytes())
			data.URL = stringPtr(val)
		case bytes.Equal(nameBytes, keyMethod):
			val := string(k.ValueBytes())
			data.Method = stringPtr(val)
		case bytes.Equal(nameBytes, keyPath):
			val := string(k.ValueBytes())
			data.Path = stringPtr(val)
		case bytes.Equal(nameBytes, keyQuery):
			val := string(k.ValueBytes())
			data.Query = stringPtr(val)
		case bytes.Equal(nameBytes, keyVersion):
			val := string(k.ValueBytes())
			data.Version = stringPtr(val)
		case bytes.Equal(nameBytes, keyID):
			val := string(k.ValueBytes())
			data.ID = stringPtr(val)
		case bytes.Equal(nameBytes, keySrcPort):
			val := k.ValueInt()
			data.SrcPort = int64Ptr(val)
		case bytes.Equal(nameBytes, keyHeaders):
			// Copy borrowed slice immediately - k.ValueBytes() returns memory owned by KV entry
			// which will be overwritten on next iteration, so we must copy now
			headersBytes := k.ValueBytes()
			// Reuse existing buffer if it has enough capacity and isn't too large, otherwise allocate new one
			if cap(data.HeadersCopied) < len(headersBytes) || cap(data.HeadersCopied) > maxHeadersBufferSize {
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
			if cap(data.BodyCopied) < len(bodyBytes) || cap(data.BodyCopied) > maxBodyBufferSize {
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
		}
	}

	return data
}

// Handles checking the http request which has 2 stages
// First stage is to check the host header and determine if the remediation from handleIpRequest is still valid
// Second stage is to check if AppSec is enabled and then forward to the component if needed
func (s *Spoa) handleHTTPRequest(ctx context.Context, writer *encoding.ActionWriter, mes *encoding.Message) {
	// Extract all message data in a single pass
	msgData := extractHTTPMessageData(mes)
	// Return struct (with embedded buffers) to pool when done
	defer func() {
		msgData.reset()
		httpMessageDataPool.Put(msgData)
	}()

	r := remediation.Allow
	var origin string
	shouldCountMetrics := false

	if msgData.Remediation == nil {
		// IP remediation not found - fallback to checking IP directly
		// This handles cases where crowdsec-ip message didn't fire (e.g., on-client-session not triggered)
		// Also handles upstream proxy mode where no IP check happened
		s.logger.Debug("remediation key not found in message (expected from crowdsec-ip message), checking IP directly as fallback")
		// Get IP from message for both remediation and origin (needed for metrics)
		if msgData.SrcIP != nil {
			r, origin = s.getIPRemediation(ctx, writer, *msgData.SrcIP)
			// Only count metrics if we successfully got IP and checked remediation
			shouldCountMetrics = true
		}
	} else {
		r = remediation.FromString(*msgData.Remediation)
		// Remediation came from IP check, already counted
	}

	var matchedHost *host.Host

	// defer a function that always add the remediation to the request at end of processing
	defer func() {
		if matchedHost == nil && r == remediation.Captcha {
			s.logger.Warn("remediation is captcha, no matching host was found cannot issue captcha remediation reverting to ban")
			r = remediation.Ban
		}
		rString := r.String()
		_ = writer.SetString(encoding.VarScopeTransaction, "remediation", rString)

		// Count metrics if this is the only handler (upstream proxy mode)
		if shouldCountMetrics {
			// Get IP from message for metrics
			ipTypeLabel := "ipv4"
			if msgData.SrcIP != nil && msgData.SrcIP.IsValid() && msgData.SrcIP.Is6() {
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

	if msgData.Host == nil {
		s.logger.Warn("failed to read host header from message, cannot match host configuration - ensure HAProxy is sending the 'host' variable in crowdsec-http message")
		return
	}

	matchedHost = s.hostManager.MatchFirstHost(*msgData.Host)

	// if the host is not found we cannot alter the remediation or do appsec checks
	if matchedHost == nil {
		return
	}

	var httpData HTTPRequestData

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
		// Build HTTP data from extracted message data
		httpData = HTTPRequestData{
			URL:     msgData.URL,
			Method:  msgData.Method,
			Body:    &msgData.BodyCopied,
			Headers: msgData.HeadersParsed,
		}
	case remediation.Ban:
		//Handle ban
		matchedHost.Ban.InjectKeyValues(writer)
		// Build HTTP data from extracted message data
		httpData = HTTPRequestData{
			URL:     msgData.URL,
			Method:  msgData.Method,
			Body:    &msgData.BodyCopied,
			Headers: msgData.HeadersParsed,
		}
	case remediation.Captcha:
		r, httpData = s.handleCaptchaRemediation(ctx, writer, msgData, matchedHost)
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

// createNewSessionAndCookie creates a new session, generates a cookie, and sets it in the request.
// Returns the session, uuid, and an error if any step fails.
func (s *Spoa) createNewSessionAndCookie(_ context.Context, writer *encoding.ActionWriter, msgData *HTTPMessageData, matchedHost *host.Host) (*session.Session, string, error) {
	var ssl *bool
	if msgData.SSL != nil {
		ssl = msgData.SSL
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
	_ = writer.SetString(encoding.VarScopeTransaction, "captcha_cookie", cookie.String())

	return ses, uuid, nil
}

// handleCaptchaRemediation handles all captcha-related logic including cookie validation,
// session management, captcha validation, and status updates.
// Returns the remediation and parsed HTTP request data for reuse in AppSec processing.
func (s *Spoa) handleCaptchaRemediation(ctx context.Context, writer *encoding.ActionWriter, msgData *HTTPMessageData, matchedHost *host.Host) (remediation.Remediation, HTTPRequestData) {
	if err := matchedHost.Captcha.InjectKeyValues(writer); err != nil {
		return remediation.FromString(matchedHost.Captcha.FallbackRemediation), HTTPRequestData{}
	}

	uuid := ""
	var ses *session.Session

	// Check for both nil and empty string (HAProxy may send empty string when cookie doesn't exist)
	if msgData.CaptchaCookie != nil && *msgData.CaptchaCookie != "" {
		var err error
		uuid, err = matchedHost.Captcha.CookieGenerator.ValidateCookie(*msgData.CaptchaCookie)
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
		ses, uuid, err = s.createNewSessionAndCookie(ctx, writer, msgData, matchedHost)
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
			ses, uuid, err = s.createNewSessionAndCookie(ctx, writer, msgData, matchedHost)
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
	captchaStatusVal := ses.Get(session.CaptchaStatus)
	var captchaStatus string
	if captchaStatusVal == nil {
		captchaStatus = captcha.Pending // Assume pending if not set
	} else {
		var ok bool
		captchaStatus, ok = captchaStatusVal.(string)
		if !ok {
			captchaStatus = captcha.Pending // Fallback to pending if type assertion fails
		}
	}

	// Set the captcha status in the transaction for HAProxy
	_ = writer.SetString(encoding.VarScopeTransaction, "captcha_status", captchaStatus)

	// Read URL - this is not critical for showing the captcha page, only for redirect after validation
	if msgData.URL == nil {
		s.logger.WithFields(log.Fields{
			"host": matchedHost.Host,
		}).Warn("failed to read url from message, captcha will still be shown but redirect after validation may not work - ensure HAProxy is sending the 'url' variable in crowdsec-http message")
		// Continue with captcha even without URL - we just won't be able to redirect after validation
	} else if captchaStatus != captcha.Valid {
		// Update the incoming url if it is different from the stored url for the session ignore favicon requests
		storedURLVal := ses.Get(session.URI)
		storedURL := ""
		if storedURLVal != nil {
			var ok bool
			storedURL, ok = storedURLVal.(string)
			if !ok {
				storedURL = ""
			}
		}

		// Check url is not nil before dereferencing
		if (storedURL == "" || *msgData.URL != storedURL) && !strings.HasSuffix(*msgData.URL, ".ico") {
			s.logger.WithField("session", uuid).Debugf("updating stored url %s", *msgData.URL)
			ses.Set(session.URI, *msgData.URL)
		}
	}

	if msgData.Method == nil {
		s.logger.WithFields(log.Fields{
			"host": matchedHost.Host,
		}).Error("failed to read method from message, cannot validate captcha form submission - ensure HAProxy is sending the 'method' variable in crowdsec-http message")
		return remediation.Captcha, HTTPRequestData{URL: msgData.URL} // Return partial data
	}

	httpData := HTTPRequestData{
		URL:     msgData.URL,
		Method:  msgData.Method,
		Headers: msgData.HeadersParsed,
	}

	// Check if the request is a captcha validation request
	if captchaStatus == captcha.Pending && *msgData.Method == http.MethodPost && msgData.HeadersParsed != nil && msgData.HeadersParsed.Get("Content-Type") == "application/x-www-form-urlencoded" {
		if len(msgData.BodyCopied) == 0 {
			s.logger.WithFields(log.Fields{
				"host":    matchedHost.Host,
				"session": uuid,
			}).Error("failed to read body from message, cannot validate captcha response - ensure HAProxy is sending the 'body' variable in crowdsec-http message for POST requests")
			return remediation.Captcha, httpData // Return data without body
		}

		httpData.Body = &msgData.BodyCopied

		// Validate captcha
		isValid, err := matchedHost.Captcha.Validate(ctx, uuid, string(msgData.BodyCopied))
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
		storedURLVal := ses.Get(session.URI)
		if storedURLVal != nil {
			storedURL, ok := storedURLVal.(string)
			if !ok {
				storedURL = ""
			}
			if storedURL != "" {
				s.logger.Debug("redirecting to: ", storedURL)
				_ = writer.SetString(encoding.VarScopeTransaction, "redirect", storedURL)
				// Delete the URI from the session so we dont redirect loop
				ses.Delete(session.URI)
			}
		}
		return remediation.Allow, httpData
	}

	return remediation.Captcha, httpData
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
	data.reset() // Clear any previous data
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
			data.SrcPort = int64Ptr(val)
		case bytes.Equal(nameBytes, keyID):
			val := string(k.ValueBytes())
			data.ID = stringPtr(val)
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

// Handles checking the IP address against the dataset
func (s *Spoa) handleIPRequest(ctx context.Context, writer *encoding.ActionWriter, mes *encoding.Message) {
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

	// Split by \r\n using bytes.Split to avoid converting entire slice to string
	headerLines := bytes.Split(headers, []byte("\r\n"))

	for _, headerLine := range headerLines {
		if len(headerLine) == 0 {
			continue
		}

		// Find colon separator in byte slice
		colonIdx := bytes.IndexByte(headerLine, ':')
		if colonIdx == -1 {
			return nil, fmt.Errorf("invalid header: %q", string(headerLine))
		}

		// Convert only the key and value parts to strings (not the entire header)
		key := strings.TrimSpace(string(headerLine[:colonIdx]))
		value := strings.TrimSpace(string(headerLine[colonIdx+1:]))

		h.Add(key, value)
	}
	return h, nil
}
