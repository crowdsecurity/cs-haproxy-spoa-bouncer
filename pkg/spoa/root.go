package spoa

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
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
	"github.com/crowdsecurity/crowdsec-spoa/pkg/captcha"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/dataset"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/host"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/metrics"
	"github.com/crowdsecurity/go-cs-lib/ptr"
	"github.com/dropmorepackets/haproxy-go/pkg/encoding"
	"github.com/dropmorepackets/haproxy-go/spop"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

const (
	challengePathPrefix         = "/crowdsec-challenge/"
	challengeInternalPathPrefix = "/crowdsec-internal/challenge/"

	// challengeResponseTTL bounds how long a challenge page is held in memory
	// waiting for HAProxy to route the challenged request to the HTTP challenge
	// backend. The browser-visible challenge cookie remains governed by CrowdSec.
	challengeResponseTTL = 30 * time.Second
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
	ListenAddr              net.Listener
	ListenSocket            net.Listener
	ChallengeHTTPListenAddr net.Listener
	challengeHTTPServer     *http.Server
	logger                  *log.Entry
	// Direct access to shared data (no IPC needed)
	dataset      *dataset.DataSet
	hostManager  *host.Manager
	geoDatabase  *geo.GeoDatabase
	globalAppSec *appsec.AppSec // Global AppSec config (used when no host matched)

	// challengeResponses holds full AppSec challenge responses keyed by an
	// HMAC-derived token from HAProxy's unique-id. HAProxy receives only the
	// tokenized URL over SPOE, then streams the body from this bouncer over
	// normal HTTP. Bounded (see challengeCache) so a burst of issued-but-never-
	// fetched challenges can't grow memory without bound.
	challengeResponses *challengeCache
	challengeTokenKey  [32]byte
}

type challengeResponseEntry struct {
	status    int
	body      string
	headers   http.Header
	cookies   []string
	expiresAt time.Time
}

type SpoaConfig struct {
	TcpAddr           string
	UnixAddr          string
	ChallengeHTTPAddr string
	// ChallengeCacheMaxEntries caps how many pending AppSec challenge responses
	// can be held in memory awaiting HAProxy's fetch (see challengeCache).
	// <= 0 falls back to defaultChallengeCacheMaxEntries.
	ChallengeCacheMaxEntries int
	Dataset                  *dataset.DataSet
	HostManager              *host.Manager
	GeoDatabase              *geo.GeoDatabase
	GlobalAppSec             *appsec.AppSec // Global AppSec config (used when no host matched)
	Logger                   *log.Entry     // Parent logger to inherit from
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
		logger:             workerLogger,
		dataset:            config.Dataset,
		hostManager:        config.HostManager,
		geoDatabase:        config.GeoDatabase,
		globalAppSec:       config.GlobalAppSec,
		challengeResponses: newChallengeCache(config.ChallengeCacheMaxEntries),
	}
	if _, err := rand.Read(s.challengeTokenKey[:]); err != nil {
		return nil, fmt.Errorf("failed to initialize challenge token key: %w", err)
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

	if config.ChallengeHTTPAddr != "" {
		addr, err := net.Listen("tcp", config.ChallengeHTTPAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to listen on %s: %w", config.ChallengeHTTPAddr, err)
		}
		s.ChallengeHTTPListenAddr = addr
	}

	return s, nil
}

// HandleSPOE implements the spop.Handler interface
func (s *Spoa) HandleSPOE(ctx context.Context, writer *encoding.ActionWriter, message *encoding.Message) {
	messageNameBytes := message.NameBytes()

	s.logger.Tracef("Received message: %s", messageNameBytes)

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
		s.logger.Tracef("Unknown message type: %s", messageNameBytes)
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

	if s.ChallengeHTTPListenAddr != nil {
		mux := http.NewServeMux()
		mux.HandleFunc(challengePathPrefix, s.handleStoredChallengeHTTP)
		mux.HandleFunc(challengeInternalPathPrefix, s.handleInternalChallengeHTTP)
		s.challengeHTTPServer = &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		}
		s.logger.Infof("Serving challenge HTTP backend on %s", s.ChallengeHTTPListenAddr.Addr().String())
		go func() {
			if err := s.challengeHTTPServer.Serve(s.ChallengeHTTPListenAddr); err != nil && !errors.Is(err, http.ErrServerClosed) {
				serverError <- err
			}
		}()
	}

	if s.ListenAddr == nil && s.ListenSocket == nil && s.ChallengeHTTPListenAddr == nil {
		return nil
	}

	go s.cleanupChallengeResponses(ctx)

	select {
	case err := <-serverError:
		return err
	case <-ctx.Done():
		return nil
	}
}

// cleanupChallengeResponses periodically reclaims challenge responses that were
// never fetched by HAProxy after the SPOE decision completed.
func (s *Spoa) cleanupChallengeResponses(ctx context.Context) {
	ticker := time.NewTicker(challengeResponseTTL)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			s.sweepExpiredChallengeResponses(now)
		}
	}
}

// sweepExpiredChallengeResponses deletes every cached challenge response whose
// expiresAt is before now. Split out from cleanupChallengeResponses so the
// sweep logic itself can be exercised directly in tests against a specific
// time, without waiting on the real challengeResponseTTL ticker.
func (s *Spoa) sweepExpiredChallengeResponses(now time.Time) {
	s.challengeResponses.Range(func(key string, entry *challengeResponseEntry) bool {
		if now.After(entry.expiresAt) {
			s.challengeResponses.Delete(key)
		}
		return true
	})
}

func (s *Spoa) Shutdown(ctx context.Context) error {
	s.logger.Info("Shutting down")

	var closeErrors []error

	// Close TCP listener - the library now handles waiting for handlers internally
	if s.ListenAddr != nil {
		closeErrors = append(closeErrors, s.ListenAddr.Close())
	}

	// Close Unix socket - the library now handles waiting for handlers internally
	if s.ListenSocket != nil {
		closeErrors = append(closeErrors, s.ListenSocket.Close())
	}
	if s.ChallengeHTTPListenAddr != nil {
		closeErrors = append(closeErrors, s.ChallengeHTTPListenAddr.Close())
	}
	if s.challengeHTTPServer != nil {
		closeErrors = append(closeErrors, s.challengeHTTPServer.Shutdown(ctx))
	}

	// The library's workgroup now handles waiting for all frame handlers to complete
	// when the listeners are closed, so we don't need to wait here
	return errors.Join(closeErrors...)
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
	appSecChallengeIssued := false

	// defer a function that always sets the remediation and counts metrics at end of processing
	defer func() {
		// Handle captcha without matched host - must revert to ban
		if matchedHost == nil && r == remediation.Captcha {
			s.logger.Warn("remediation is captcha, no matching host was found cannot issue captcha remediation reverting to ban")
			r = remediation.Ban
		}

		// Dataset-level "challenge" decisions do not carry AppSec challenge
		// body/cookie data and cannot be served by HAProxy without a challenge_url.
		// Only AppSec-issued challenges that successfully injected the URL are
		// allowed to remain as challenge remediations.
		if r == remediation.Challenge && !appSecChallengeIssued {
			s.logger.Warn("challenge remediation without AppSec challenge data cannot be served, reverting to ban")
			r = remediation.Ban
			if matchedHost != nil {
				matchedHost.Ban.InjectKeyValues(writer)
			}
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
		// 2. Final remediation is still restrictive (user didn't solve captcha), AND
		// 3. Either TCP didn't run, OR TCP found Allow
		// (If TCP found bad remediation, it already counted the block)
		if datasetBlocked && r > remediation.Allow && (!tcpRan || tcpAllowed) {
			metrics.TotalBlockedRequests.WithLabelValues(origin, ipTypeLabel, datasetRemediation.String()).Inc()
		}
	}()

	if msgData.Host == nil {
		s.logger.Warn("failed to read host header from message, cannot match host configuration - ensure HAProxy is sending the 'host' variable in crowdsec-http message")
	} else {
		matchedHost = s.hostManager.MatchFirstHost(*msgData.Host)
	}

	// If no host matched, we can still do AppSec checks with global config
	if matchedHost == nil {
		appSec, timeout, alwaysSend := s.getAppSecConfig(nil)
		if appSec != nil && shouldRunAppSec(r, alwaysSend) {
			var issued bool
			r, issued = s.validateWithAppSec(ctx, writer, msgData, nil, appSec, r, timeout)
			appSecChallengeIssued = appSecChallengeIssued || issued
		}
		return
	}

	switch r {
	case remediation.Allow:
		// If user has a captcha cookie but decision is Allow, clear it
		if msgData.CaptchaCookie != nil && *msgData.CaptchaCookie != "" {
			unsetCookie := matchedHost.Captcha.GenerateUnsetCookie(msgData.SSL)
			s.logger.WithField("host", matchedHost.Host).Debug("Allow decision but captcha cookie present, will clear cookie")
			_ = writer.SetString(encoding.VarScopeTransaction, "captcha_cookie", unsetCookie.String())
		}
	case remediation.Ban:
		//Handle ban
		matchedHost.Ban.InjectKeyValues(writer)
	case remediation.Captcha:
		r = s.handleCaptchaRemediation(ctx, writer, msgData, matchedHost)
	}

	// Validate with AppSec if configured
	appSec, timeout, alwaysSend := s.getAppSecConfig(matchedHost)
	if appSec != nil && shouldRunAppSec(r, alwaysSend) {
		var issued bool
		r, issued = s.validateWithAppSec(ctx, writer, msgData, matchedHost, appSec, r, timeout)
		appSecChallengeIssued = appSecChallengeIssued || issued
		if r == remediation.Ban {
			matchedHost.Ban.InjectKeyValues(writer)
		}
	}
}

// getAppSecConfig returns the AppSec configuration to use based on host and global settings.
// Returns the AppSec instance, timeout, and whether always_send is enabled.
// If no AppSec is configured, returns nil.
func (s *Spoa) getAppSecConfig(matchedHost *host.Host) (appSec *appsec.AppSec, timeout time.Duration, alwaysSend bool) {
	// Try host-specific AppSec first
	if matchedHost != nil && matchedHost.AppSec.IsValid() {
		return &matchedHost.AppSec, matchedHost.AppSec.TimeoutOrDefault(), matchedHost.AppSec.AlwaysSend
	}
	// Fall back to global AppSec
	if s.globalAppSec != nil && s.globalAppSec.IsValid() {
		return s.globalAppSec, s.globalAppSec.TimeoutOrDefault(), false
	}
	return nil, 0, false
}

// shouldRunAppSec determines if AppSec validation should run based on current remediation.
// AppSec runs if remediation is not yet restrictive (< Captcha) OR if always_send is enabled.
func shouldRunAppSec(r remediation.Remediation, alwaysSend bool) bool {
	return r < remediation.Captcha || alwaysSend
}

// validateWithAppSec performs AppSec validation and returns the remediation plus
// whether an AppSec challenge response was successfully injected for HAProxy.
func (s *Spoa) validateWithAppSec(
	ctx context.Context,
	writer *encoding.ActionWriter,
	msgData *HTTPMessageData,
	matchedHost *host.Host,
	appSecToUse *appsec.AppSec,
	currentRemediation remediation.Remediation,
	requestTimeout time.Duration,
) (remediation.Remediation, bool) {
	appSecReq := msgData.buildAppSecRequest()

	logger := s.logger
	if appSecReq.Host != "" {
		logger = logger.WithField("host", appSecReq.Host)
	}
	if matchedHost != nil {
		logger = logger.WithField("matched_host", matchedHost.Host)
	}

	appSecCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	appSecRemediation, challengeData, err := appSecToUse.ValidateRequest(appSecCtx, appSecReq)
	if err != nil {
		logger.WithError(err).Warn("AppSec validation failed, using original remediation")
		return currentRemediation, false
	}

	logger.WithField("remediation", appSecRemediation.String()).Debug("AppSec validation result")

	if appSecRemediation > remediation.Allow && appSecReq.RemoteIP != "" {
		if ipAddr, parseErr := netip.ParseAddr(appSecReq.RemoteIP); parseErr == nil {
			ipType := "ipv4"
			if ipAddr.Is6() {
				ipType = "ipv6"
			}
			metrics.TotalBlockedRequests.WithLabelValues("appsec", ipType, appSecRemediation.String()).Inc()
		}
	}

	if appSecRemediation > currentRemediation {
		if appSecRemediation == remediation.Ban && matchedHost == nil {
			logger.Warn("AppSec returned ban but no host matched - remediation set but ban values not injected")
		}
		if appSecRemediation == remediation.Challenge && challengeData != nil {
			if s.ChallengeHTTPListenAddr == nil {
				logger.Error("cannot serve AppSec challenge: challenge_http_listen is not configured, falling back to ban")
				return remediation.Ban, false
			}
			if msgData.ID == nil || *msgData.ID == "" {
				logger.Error("cannot serve AppSec challenge: HAProxy sent no unique request id (configure unique-id-format), falling back to ban")
				return remediation.Ban, false
			}
			if !s.injectChallengeKeyValues(writer, challengeData, *msgData.ID) {
				return remediation.Ban, false
			}
			return appSecRemediation, true
		}
		return appSecRemediation, false
	}
	return currentRemediation, false
}

func (s *Spoa) injectChallengeKeyValues(writer *encoding.ActionWriter, challengeData *appsec.AppSecChallengeData, requestID string) bool {
	status := challengeData.StatusCode
	if status <= 0 {
		status = http.StatusOK
	}

	body := challengeData.Body
	headers := challengeData.Headers
	if body == "" {
		body = fallbackChallengeBody
		headers = cloneChallengeHeaders(headers)
		if !hasChallengeHeader(headers, "Content-Type") {
			headers["Content-Type"] = []string{"text/html; charset=utf-8"}
		}
		if !hasChallengeHeader(headers, "Cache-Control") {
			headers["Cache-Control"] = []string{"no-cache, no-store"}
		}
	}

	token := s.challengeTokenFromRequestID(requestID)

	s.challengeResponses.Store(token, &challengeResponseEntry{
		status:    status,
		body:      body,
		headers:   cloneHTTPHeader(headers),
		cookies:   append([]string(nil), challengeData.Cookies...),
		expiresAt: time.Now().Add(challengeResponseTTL),
	})

	_ = writer.SetString(encoding.VarScopeTransaction, "challenge_url", challengePathPrefix+token)
	return true
}

const fallbackChallengeBody = `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>CrowdSec Challenge</title>
    <style>
      body { margin: 0; font-family: system-ui, sans-serif; color: #111827; background: #f9fafb; }
      main { max-width: 42rem; margin: 15vh auto; padding: 2rem; }
      h1 { font-size: 1.5rem; margin: 0 0 0.75rem; }
      p { line-height: 1.5; margin: 0; color: #374151; }
    </style>
  </head>
  <body>
    <main>
      <h1>Request challenged by CrowdSec</h1>
      <p>The request matched an AppSec rule and was returned as a challenge, but CrowdSec did not provide a challenge page body.</p>
    </main>
  </body>
</html>
`

func cloneChallengeHeaders(headers map[string][]string) map[string][]string {
	clone := make(map[string][]string, len(headers)+2)
	for k, values := range headers {
		clone[k] = append([]string(nil), values...)
	}
	return clone
}

func hasChallengeHeader(headers map[string][]string, name string) bool {
	for k := range headers {
		if strings.EqualFold(k, name) {
			return true
		}
	}
	return false
}

func (s *Spoa) challengeTokenFromRequestID(requestID string) string {
	mac := hmac.New(sha256.New, s.challengeTokenKey[:])
	_, _ = mac.Write([]byte(requestID))
	return hex.EncodeToString(mac.Sum(nil)[:16])
}

func cloneHTTPHeader(headers map[string][]string) http.Header {
	clone := make(http.Header, len(headers))
	for k, values := range headers {
		clone[k] = append([]string(nil), values...)
	}
	return clone
}

func (s *Spoa) handleStoredChallengeHTTP(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, challengePathPrefix)
	if token == "" || strings.Contains(token, "/") {
		http.NotFound(w, r)
		return
	}

	entry, ok := s.challengeResponses.LoadAndDelete(token)
	if !ok || time.Now().After(entry.expiresAt) {
		http.NotFound(w, r)
		return
	}

	for name, values := range entry.headers {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	for _, cookie := range entry.cookies {
		w.Header().Add("Set-Cookie", cookie)
	}
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	}
	if w.Header().Get("Cache-Control") == "" {
		w.Header().Set("Cache-Control", "no-cache, no-store")
	}

	status := entry.status
	if status <= 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write([]byte(entry.body))
}

func (s *Spoa) handleInternalChallengeHTTP(w http.ResponseWriter, r *http.Request) {
	var matchedHost *host.Host
	if r.Host != "" && s.hostManager != nil {
		matchedHost = s.hostManager.MatchFirstHost(r.Host)
	}

	appSecToUse, timeout, _ := s.getAppSecConfig(matchedHost)
	if appSecToUse == nil || !appSecToUse.IsValid() {
		http.NotFound(w, r)
		return
	}

	// This endpoint is reached without going through the normal SPOE
	// crowdsec-http-body/no-body flow (HAProxy routes crowdsec_challenge_backend_path
	// requests here directly, bypassing send-spoe-group - see haproxy*.cfg), so it
	// never gets the IP/dataset ban check that every other request goes through.
	// Re-run that cheap, local check here before relaying anything to AppSec, so an
	// already-banned/captcha'd IP can't use this path as a side channel into the
	// AppSec engine. This intentionally does NOT run the full validateWithAppSec
	// pipeline (that would mint a *new* challenge_url token here, which is wrong:
	// this endpoint relays an already-issued challenge's follow-up asset/
	// verification traffic, not a fresh top-level decision).
	remoteIP := trustedChallengeClientIP(r)
	if ip, parseErr := netip.ParseAddr(remoteIP); parseErr == nil {
		if rem, _ := s.getIPRemediation(r.Context(), nil, ip); rem >= remediation.Captcha {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, int64(maxBodyBufferSize)))
	_ = r.Body.Close()
	if err != nil {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}

	req := &appsec.AppSecRequest{
		Host:      r.Host,
		Method:    r.Method,
		URL:       r.URL.RequestURI(),
		RemoteIP:  remoteIP,
		UserAgent: r.UserAgent(),
		Version:   r.Proto,
		Headers:   r.Header.Clone(),
		Body:      body,
	}

	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	remediationResult, challengeData, err := appSecToUse.ValidateRequest(ctx, req)
	if err != nil {
		s.logger.WithError(err).Warn("AppSec internal challenge request failed")
		http.Error(w, "challenge backend error", http.StatusBadGateway)
		return
	}

	if remediationResult != remediation.Challenge || challengeData == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	writeChallengeData(w, challengeData)
}

func writeChallengeData(w http.ResponseWriter, challengeData *appsec.AppSecChallengeData) {
	for name, values := range challengeData.Headers {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	for _, cookie := range challengeData.Cookies {
		w.Header().Add("Set-Cookie", cookie)
	}
	if w.Header().Get("Cache-Control") == "" {
		w.Header().Set("Cache-Control", "no-cache, no-store")
	}
	status := challengeData.StatusCode
	if status <= 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write([]byte(challengeData.Body))
}

// trustedChallengeClientIP returns the client IP for a request routed to the
// challenge HTTP backend. It deliberately does NOT trust client-supplied
// X-Forwarded-For/X-Real-IP headers: this endpoint bypasses the normal SPOE
// flow (see crowdsec_challenge_backend_path in haproxy*.cfg), so nothing else
// validates those headers here, and HAProxy's "option forwardfor" appends
// rather than replaces an existing X-Forwarded-For - meaning a client-supplied
// value would win over HAProxy's own if naively read with Header.Get. Instead,
// haproxy*.cfg overwrites a single dedicated header (X-Crowdsec-Real-Src) with
// HAProxy's own verified %[src] immediately before routing to this backend,
// the same trust model crowdsec.cfg uses for src-ip=src in the normal flow.
func trustedChallengeClientIP(r *http.Request) string {
	if trusted := r.Header.Get("X-Crowdsec-Real-Src"); trusted != "" {
		return trusted
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
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
		// No copy needed - BodyCopied remains valid until handler returns
		// (pool return happens in defer after ValidateRequest completes synchronously)
		req.Body = d.BodyCopied
	}

	return req
}

// handleCaptchaRemediation handles captcha verification using stateless JWT tokens.
// Flow: get/create token → if passed, allow → if pending, try validate → show captcha
func (s *Spoa) handleCaptchaRemediation(ctx context.Context, writer *encoding.ActionWriter, msgData *HTTPMessageData, matchedHost *host.Host) remediation.Remediation {
	fallback := remediation.FromString(matchedHost.Captcha.FallbackRemediation)

	if err := matchedHost.Captcha.InjectKeyValues(writer); err != nil {
		s.logger.WithField("host", matchedHost.Host).WithError(err).Error("Invalid captcha configuration")
		return fallback
	}

	// Get existing token or create new one
	tok := s.getOrCreateCaptchaToken(writer, msgData, matchedHost)
	if tok == nil {
		return fallback
	}

	// If token is passed, return allow
	if tok.IsPassed() {
		_ = writer.SetString(encoding.VarScopeTransaction, "captcha_status", captcha.Valid)
		return remediation.Allow
	}

	// Token is pending - set status and check for validation attempt
	_ = writer.SetString(encoding.VarScopeTransaction, "captcha_status", captcha.Pending)

	if msgData.isCaptchaSubmission(matchedHost) {
		if s.validateAndUpdateCaptcha(ctx, writer, msgData, matchedHost, tok) {
			_ = writer.SetString(encoding.VarScopeTransaction, "redirect", "1")
			return remediation.Allow
		}
	}

	return remediation.Captcha
}

// getOrCreateCaptchaToken returns an existing valid token from cookie or creates a new one
func (s *Spoa) getOrCreateCaptchaToken(writer *encoding.ActionWriter, msgData *HTTPMessageData, matchedHost *host.Host) *captcha.Token {
	// Try existing cookie first
	if msgData.CaptchaCookie != nil && *msgData.CaptchaCookie != "" {
		if tok, err := matchedHost.Captcha.ValidateCookie(*msgData.CaptchaCookie); err == nil {
			return tok
		}
	}

	// Create new pending token
	tok, err := matchedHost.Captcha.NewPendingToken()
	if err != nil {
		s.logger.WithField("host", matchedHost.Host).WithError(err).Error("Failed to create captcha token")
		return nil
	}

	// Generate and set cookie
	cookie, err := matchedHost.Captcha.GenerateCookie(tok, msgData.SSL)
	if err != nil {
		s.logger.WithField("host", matchedHost.Host).WithError(err).Error("Failed to generate captcha cookie")
		return nil
	}
	_ = writer.SetString(encoding.VarScopeTransaction, "captcha_cookie", cookie.String())

	return &tok
}

// isCaptchaSubmission checks if this request is a captcha form submission
func (d *HTTPMessageData) isCaptchaSubmission(matchedHost *host.Host) bool {
	if d.Method == nil || *d.Method != http.MethodPost {
		return false
	}
	if d.HeadersParsed == nil || len(d.BodyCopied) == 0 {
		return false
	}
	contentType := strings.ToLower(d.HeadersParsed.Get("Content-Type"))
	if !strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
		return false
	}
	return matchedHost.Captcha.IsCaptchaSubmission(string(d.BodyCopied))
}

// validateAndUpdateCaptcha validates the captcha submission and updates the token/cookie if successful
func (s *Spoa) validateAndUpdateCaptcha(ctx context.Context, writer *encoding.ActionWriter, msgData *HTTPMessageData, matchedHost *host.Host, tok *captcha.Token) bool {
	timer := prometheus.NewTimer(metrics.CaptchaValidationDuration)
	isValid, err := matchedHost.Captcha.Validate(ctx, tok.UUID, string(msgData.BodyCopied))
	timer.ObserveDuration()

	if err != nil || !isValid {
		return false
	}

	// Success - create passed token and update cookie
	newTok := matchedHost.Captcha.NewPassedToken(tok)
	_ = writer.SetString(encoding.VarScopeTransaction, "captcha_status", captcha.Valid)

	if cookie, err := matchedHost.Captcha.GenerateCookie(newTok, msgData.SSL); err == nil {
		_ = writer.SetString(encoding.VarScopeTransaction, "captcha_cookie", cookie.String())
	}

	return true
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
		// Track geo lookup duration
		geoTimer := prometheus.NewTimer(metrics.GeoLookupDuration)
		record, err := s.geoDatabase.GetCity(ip)
		geoTimer.ObserveDuration()

		if err != nil && !errors.Is(err, geo.ErrNotValidConfig) {
			s.logger.WithFields(log.Fields{
				"ip":    ip.String(),
				"error": err,
			}).Warn("Failed to get geo location")
		} else if record != nil {
			iso := geo.GetIsoCodeFromRecord(record)
			if iso != "" {
				// Always set the ISO code variable when available.
				setIsoCodeVar(writer, iso)

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

// setIsoCodeVar sets the isocode SPOE transaction variable when a writer is
// available. writer is nil when getIPRemediation is called from a plain
// net/http handler (e.g. handleInternalChallengeHTTP) that has no SPOE
// transaction to write a variable to.
func setIsoCodeVar(writer *encoding.ActionWriter, iso string) {
	if writer != nil {
		_ = writer.SetString(encoding.VarScopeTransaction, "isocode", iso)
	}
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
