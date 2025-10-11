package spoa

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
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
	"github.com/crowdsecurity/go-cs-lib/ptr"
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
	HAWaitGroup  *sync.WaitGroup
	logger       *log.Entry
	// Direct access to shared data (no IPC needed)
	dataset     *dataset.DataSet
	hostManager *host.Manager
	geoDatabase *geo.GeoDatabase
}

type SpoaConfig struct {
	TcpAddr     string
	UnixAddr    string
	Name        string
	LogLevel    *log.Level
	Dataset     *dataset.DataSet
	HostManager *host.Manager
	GeoDatabase *geo.GeoDatabase
	Logger      *log.Entry // Parent logger to inherit from
}

func New(config *SpoaConfig) (*Spoa, error) {
	// Use provided logger or fallback to standard logger
	var workerLogger *log.Entry
	if config.Logger != nil {
		workerLogger = config.Logger.WithField("worker", config.Name)
	} else {
		workerLogger = log.WithField("worker", config.Name)
	}

	// Apply log level if specified (for compatibility)
	if config.LogLevel != nil {
		workerLogger.Logger.SetLevel(*config.LogLevel)
	}

	s := &Spoa{
		HAWaitGroup: &sync.WaitGroup{},
		logger:      workerLogger,
		dataset:     config.Dataset,
		hostManager: config.HostManager,
		geoDatabase: config.GeoDatabase,
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
		// To set this: chmod g+s /run/crowdsec-spoa && chgrp haproxy /run/crowdsec-spoa
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

func (s *Spoa) ServeTCP(ctx context.Context) error {
	if s.ListenAddr == nil {
		return nil
	}
	s.logger.Infof("Serving TCP server on %s", s.ListenAddr.Addr().String())

	errorChan := make(chan error, 1)

	go func() {
		defer close(errorChan)
		err := s.Server.Serve(s.ListenAddr)
		switch {
		case errors.Is(err, net.ErrClosed):
			// Server closed normally during shutdown
			break
		case err != nil:
			errorChan <- err
		}
	}()

	select {
	case err := <-errorChan:
		return err
	case <-ctx.Done():
		return nil
	}
}

func (s *Spoa) ServeUnix(ctx context.Context) error {
	if s.ListenSocket == nil {
		return nil
	}

	s.logger.Infof("Serving Unix server on %s", s.ListenSocket.Addr().String())

	errorChan := make(chan error, 1)

	go func() {
		defer close(errorChan)
		err := s.Server.Serve(s.ListenSocket)
		switch {
		case errors.Is(err, net.ErrClosed):
			// Server closed normally during shutdown
			break
		case err != nil:
			errorChan <- err
		}
	}()

	select {
	case err := <-errorChan:
		return err
	case <-ctx.Done():
		return nil
	}
}

func (s *Spoa) Shutdown(ctx context.Context) error {
	s.logger.Info("Shutting down")

	doneChan := make(chan struct{})

	// Close TCP listener
	if s.ListenAddr != nil {
		s.ListenAddr.Close()
	}

	// Initially  we didn't close the unix socket as we wanted to persist permissions
	if s.ListenSocket != nil {
		s.ListenSocket.Close()
	}

	go func() {
		s.HAWaitGroup.Wait()
		close(doneChan)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-doneChan:
		return nil
	}
}

// Handles checking the http request which has 2 stages
// First stage is to check the host header and determine if the remediation from handleIpRequest is still valid
// Second stage is to check if AppSec is enabled and then forward to the component if needed
func (s *Spoa) handleHTTPRequest(req *request.Request, mes *message.Message) {
	r := remediation.Allow
	var origin string
	shouldCountMetrics := false

	rstring, err := readKeyFromMessage[string](mes, "remediation")

	if err == nil {
		s.logger.Debug("remediation: ", *rstring)
		r = remediation.FromString(*rstring)
		// Remediation came from IP check, already counted
	} else {
		s.logger.Info("ip remediation was not found in message, defaulting to allow")
		// No IP check happened (e.g., upstream proxy mode), we need to count metrics
		shouldCountMetrics = true
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
			ipStr := ""
			if srcIP, err := readKeyFromMessage[net.IP](mes, "src-ip"); err == nil {
				ipStr = srcIP.String()
			}

			ipTypeLabel := "ipv4"
			if strings.Contains(ipStr, ":") {
				ipTypeLabel = "ipv6"
			}

			// Count processed request
			metrics.TotalProcessedRequests.With(prometheus.Labels{"ip_type": ipTypeLabel}).Inc()

			// Count blocked request if remediation applied
			if r > remediation.Unknown {
				metrics.TotalBlockedRequests.With(prometheus.Labels{
					"ip_type":     ipTypeLabel,
					"origin":      origin,
					"remediation": r.String(),
				}).Inc()
			}
		}
	}()

	if err != nil {
		return
	}

	matchedHost = s.hostManager.MatchFirstHost(*hoststring)

	// if the host is not found we cannot alter the remediation or do appsec checks
	if matchedHost == nil {
		return
	}

	var url *string
	var method *string
	var body *[]byte
	var headers http.Header

	switch r {
	case remediation.Allow:
		// If user has a captcha cookie but decision is Allow, generate unset cookie
		// We don't set captcha_status, so HAProxy knows to clear the cookie
		cookieB64, _ := readKeyFromMessage[string](mes, "crowdsec_captcha_cookie")
		if cookieB64 != nil {
			ssl, err := readKeyFromMessage[bool](mes, "ssl")
			if err != nil {
				s.logger.Error(err)
			}

			unsetCookie, err := matchedHost.Captcha.CookieGenerator.GenerateUnsetCookie(ptr.Of(*ssl))
			if err != nil {
				s.logger.WithFields(log.Fields{
					"host":  *hoststring,
					"ssl":   ssl,
					"error": err,
				}).Error("Failed to generate unset cookie")
				return // Cannot proceed without unset cookie
			}

			s.logger.WithFields(log.Fields{
				"host": *hoststring,
			}).Debug("Allow decision but captcha cookie present, will clear cookie")
			req.Actions.SetVar(action.ScopeTransaction, "captcha_cookie", unsetCookie.String())
			// Note: We deliberately don't set captcha_status here
		}
	case remediation.Ban:
		//Handle ban
		matchedHost.Ban.InjectKeyValues(&req.Actions)
	case remediation.Captcha:
		if err := matchedHost.Captcha.InjectKeyValues(&req.Actions); err != nil {
			r = remediation.FromString(matchedHost.Captcha.FallbackRemediation)
			return
		}

		cookieB64, _ := readKeyFromMessage[string](mes, "crowdsec_captcha_cookie")
		uuid := ""

		if cookieB64 != nil {
			uuid, err = matchedHost.Captcha.CookieGenerator.ValidateCookie(*cookieB64)
			if err != nil {
				s.logger.WithFields(log.Fields{
					"host":  *hoststring,
					"error": err,
				}).Warn("Failed to validate existing cookie")
				uuid = "" // Reset to generate new cookie
			}
		}

		if uuid == "" {
			ssl, err := readKeyFromMessage[bool](mes, "ssl")

			if err != nil {
				s.logger.Error(err)
			}

			// Create a new session
			ses, err := matchedHost.Captcha.Sessions.NewRandomSession()
			if err != nil {
				s.logger.WithFields(log.Fields{
					"host":  *hoststring,
					"error": err,
				}).Error("Failed to create new session")
				return // Cannot proceed without session
			}

			cookie, err := matchedHost.Captcha.CookieGenerator.GenerateCookie(ses, ssl)
			if err != nil {
				s.logger.WithFields(log.Fields{
					"host":  *hoststring,
					"ssl":   ssl,
					"error": err,
				}).Error("Failed to generate host cookie")
				return // Cannot proceed without cookie
			}

			// Set initial captcha status to pending
			ses.Set(session.CaptchaStatus, captcha.Pending)
			uuid = ses.UUID

			// Set the captcha cookie - status will be set later based on session state
			req.Actions.SetVar(action.ScopeTransaction, "captcha_cookie", cookie.String())
		}

		if uuid == "" {
			// We should never hit this but safety net
			// As a fallback we set the remediation to the fallback remediation
			s.logger.Error("failed to get uuid from cookie")
			r = remediation.FromString(matchedHost.Captcha.FallbackRemediation)
			return
		}

		url, err = readKeyFromMessage[string](mes, "url")

		if err != nil {
			s.logger.Errorf("failed to read url: %v", err)
			return
		}

		// Get the session
		ses := matchedHost.Captcha.Sessions.GetSession(uuid)
		if ses == nil {
			s.logger.WithFields(log.Fields{
				"host":    *hoststring,
				"session": uuid,
			}).Warn("Session not found, cannot proceed with captcha")
			r = remediation.FromString(matchedHost.Captcha.FallbackRemediation)
			return
		}

		// Get the current captcha status from the session
		val := ses.Get(session.CaptchaStatus)
		if val == nil {
			val = captcha.Pending // Assume pending if not set
		}

		// Set the captcha status in the transaction for HAProxy
		req.Actions.SetVar(action.ScopeTransaction, "captcha_status", val)
		if val != captcha.Valid {
			// Update the incoming url if it is different from the stored url for the session ignore favicon requests
			storedURL := ses.Get(session.URI)
			if storedURL == nil {
				storedURL = ""
			}

			if (storedURL == "" || url != nil && *url != storedURL) && !strings.HasSuffix(*url, ".ico") {
				s.logger.WithField("session", uuid).Debugf("updating stored url %s", *url)
				ses.Set(session.URI, *url)
			}
		}

		method, err = readKeyFromMessage[string](mes, "method")
		if err != nil {
			s.logger.Errorf("failed to read method: %v", err)
			return
		}

		headersType, err := readKeyFromMessage[string](mes, "headers")

		if err != nil {
			s.logger.Errorf("failed to read headers: %v", err)
			return
		}

		headers, err = readHeaders(*headersType)

		if err != nil {
			s.logger.Errorf("failed to parse headers: %v", err)
		}

		// Check if the request is a captcha validation request
		captchaStatus := ses.Get(session.CaptchaStatus)
		if captchaStatus == nil {
			captchaStatus = "" // Assume not pending if not set
		}

		if captchaStatus == captcha.Pending && method != nil && *method == http.MethodPost && headers.Get("Content-Type") == "application/x-www-form-urlencoded" {
			body, err = readKeyFromMessage[[]byte](mes, "body")

			if err != nil {
				s.logger.Errorf("failed to read body: %v", err)
				return
			}

			// Validate captcha
			isValid, err := matchedHost.Captcha.Validate(context.Background(), uuid, string(*body))
			if err != nil {
				s.logger.WithFields(log.Fields{
					"host":    *hoststring,
					"session": uuid,
					"error":   err,
				}).Error("Failed to validate captcha")
			} else if isValid {
				ses.Set(session.CaptchaStatus, captcha.Valid)
			}
		}

		// if the session has a valid captcha status we allow the request
		finalStatus := ses.Get(session.CaptchaStatus)
		if finalStatus == captcha.Valid {
			r = remediation.Allow
			// The captcha_status was already set above with the actual session status
			storedURL := ses.Get(session.URI)
			if storedURL != nil && storedURL != "" {
				s.logger.Debug("redirecting to: ", storedURL)
				req.Actions.SetVar(action.ScopeTransaction, "redirect", storedURL)
				// Delete the URI from the session so we dont redirect loop
				ses.Delete(session.URI)
			}
		}
	}

	// If remediation is ban/captcha we dont need to create a request to send to appsec unless always send is on
	if r > remediation.Unknown && !matchedHost.AppSec.AlwaysSend {
		return
	}
	// !TODO APPSEC STUFF

	// headers, err := readHeaders(*headersType)
	// if err != nil {
	// 	log.Printf("failed to parse headers: %v", err)
	// }

	// request, err := http.NewRequest(method, url, strings.NewReader(body))
	// if err != nil {
	// 	log.Printf("failed to create request: %v", err)
	// 	return
	// }
	// request.Header = headers
}

// Handles checking the IP address against the dataset
func (s *Spoa) handleIPRequest(req *request.Request, mes *message.Message) {
	var r remediation.Remediation

	ipType, err := readKeyFromMessage[net.IP](mes, "src-ip")

	if err != nil {
		s.logger.Error(err)
		return
	}

	ipStr := ipType.String()

	// Determine IP type for metrics
	ipTypeLabel := "ipv4"
	if strings.Contains(ipStr, ":") {
		ipTypeLabel = "ipv6"
	}

	// Count processed requests
	metrics.TotalProcessedRequests.With(prometheus.Labels{"ip_type": ipTypeLabel}).Inc()

	// Check IP directly against dataset
	r, origin, err := s.dataset.CheckIP(ipStr)
	if err != nil {
		s.logger.WithFields(log.Fields{
			"ip":    ipStr,
			"error": err,
		}).Error("Failed to get IP remediation")
		r = remediation.Allow // Safe default
	}

	// If no IP-specific remediation, check country-based
	if r < remediation.Unknown && s.geoDatabase.IsValid() {
		ipAddr := net.ParseIP(ipStr)
		if ipAddr != nil {
			record, err := s.geoDatabase.GetCity(&ipAddr)
			if err != nil && !errors.Is(err, geo.ErrNotValidConfig) {
				s.logger.WithFields(log.Fields{
					"ip":    ipStr,
					"error": err,
				}).Warn("Failed to get geo location")
			} else if record != nil {
				iso := geo.GetIsoCodeFromRecord(record)
				if iso != "" {
					cnR, cnOrigin := s.dataset.CheckCN(iso)
					if cnR > remediation.Unknown {
						r = cnR
						origin = cnOrigin
					}
					req.Actions.SetVar(action.ScopeTransaction, "isocode", iso)
				}
			}
		}
	}

	// Count blocked requests
	if r > remediation.Unknown {
		metrics.TotalBlockedRequests.With(prometheus.Labels{
			"ip_type":     ipTypeLabel,
			"origin":      origin,
			"remediation": r.String(),
		}).Inc()
	}

	req.Actions.SetVar(action.ScopeTransaction, "remediation", r.String())
}

func handlerWrapper(s *Spoa) func(req *request.Request) {
	return func(req *request.Request) {
		s.HAWaitGroup.Add(1)
		defer s.HAWaitGroup.Done()

		for _, messageName := range messageNames {
			mes, err := req.Messages.GetByName(messageName)
			if err != nil {
				continue
			}
			s.logger.Trace("Received message: ", messageName)
			switch messageName {
			case "crowdsec-http":
				s.handleHTTPRequest(req, mes)
			case "crowdsec-ip":
				s.handleIPRequest(req, mes)
			}
		}
	}
}

// readKeyFromMessage reads a key from a message and returns it as the type T
func readKeyFromMessage[T string | net.IP | bool | []byte](msg *message.Message, key string) (*T, error) {
	value, ok := msg.KV.Get(key)
	if !ok {
		return nil, fmt.Errorf("key %s not found", key)
	}
	s, ok := value.(T)
	if !ok {
		return nil, fmt.Errorf("key %s has wrong type", key)
	}
	return &s, nil
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
