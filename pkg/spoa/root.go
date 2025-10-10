package spoa

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"

	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation/captcha"
	"github.com/crowdsecurity/crowdsec-spoa/internal/session"
	"github.com/crowdsecurity/crowdsec-spoa/internal/worker"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/host"
	"github.com/negasus/haproxy-spoe-go/action"
	"github.com/negasus/haproxy-spoe-go/agent"
	"github.com/negasus/haproxy-spoe-go/message"
	"github.com/negasus/haproxy-spoe-go/request"
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
	cancel       context.CancelFunc
	logger       *log.Entry
	workerClient *worker.WorkerClient
}

func New(tcpAddr, unixAddr string) (*Spoa, error) {
	clog := log.New()
	socket, ok := os.LookupEnv("WORKERSOCKET")

	if !ok {
		return nil, fmt.Errorf("failed to get socket from environment")
	}

	name, _ := os.LookupEnv("WORKERNAME") // worker name set by parent process
	logLevel, err := log.ParseLevel(os.Getenv("LOG_LEVEL"))

	if err != nil {
		logLevel = clog.Level
	}

	clog.SetLevel(logLevel)

	client, err := worker.NewWorkerClient(socket, name)
	if err != nil {
		return nil, fmt.Errorf("failed to create worker client: %w", err)
	}

	s := &Spoa{
		HAWaitGroup:  &sync.WaitGroup{},
		logger:       clog.WithField("worker", name),
		workerClient: client,
	}

	if tcpAddr != "" {
		addr, err := net.Listen("tcp", tcpAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to listen on %s: %w", tcpAddr, err)
		}
		s.ListenAddr = addr
	}

	if unixAddr != "" {
		// Get current process uid/gid usually worker node
		uid := os.Getuid()
		gid := os.Getgid()

		// Get existing socket stat
		fileInfo, err := os.Stat(unixAddr)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("failed to stat socket %s: %w", unixAddr, err)
			}
		} else {
			stat, ok := fileInfo.Sys().(*syscall.Stat_t)
			if !ok {
				return nil, fmt.Errorf("failed to get socket stat")
			}
			// Set gid to existing socket
			gid = int(stat.Gid)
		}

		// Remove existing socket
		if err := os.Remove(unixAddr); err != nil {
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("failed to remove socket %s: %w", unixAddr, err)
			}
		}

		// Set umask to 0o777
		origUmask := syscall.Umask(0o777)

		// Create new socket
		addr, err := net.Listen("unix", unixAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to listen on %s: %w", unixAddr, err)
		}

		// Reset umask
		syscall.Umask(origUmask)

		// Change socket owner and permissions
		if err := os.Chown(unixAddr, uid, gid); err != nil {
			return nil, fmt.Errorf("failed to change owner of socket %s: %w", unixAddr, err)
		}
		if err := os.Chmod(unixAddr, 0o660); err != nil {
			return nil, fmt.Errorf("failed to change permissions of socket %s: %w", unixAddr, err)
		}

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
		if err := s.Server.Serve(s.ListenAddr); err != nil {
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
		if err := s.Server.Serve(s.ListenAddr); err != nil {
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
		s.cancel()
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

// extractHTTPRequestData extracts method, url, headers, and body from the HAProxy message
func (s *Spoa) extractHTTPRequestData(mes *message.Message) (*string, *string, http.Header, *[]byte, error) {
	method, err := readKeyFromMessage[string](mes, "method")
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to read method: %w", err)
	}

	url, err := readKeyFromMessage[string](mes, "url")
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to read url: %w", err)
	}

	// Extract headers for AppSec validation
	headersType, err := readKeyFromMessage[string](mes, "headers")
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to read headers: %w", err)
	}

	headers, err := readHeaders(*headersType)
	if err != nil {
		log.Printf("failed to parse headers: %v", err)
		// Don't return error here, continue with empty headers
		headers = make(http.Header)
	}

	// Extract body if present
	var body *[]byte
	msgBody, err := readKeyFromMessage[[]byte](mes, "body")
	if err == nil && msgBody != nil {
		body = msgBody
	}

	return method, url, headers, body, nil
}

// handleAppSecValidation handles AppSec validation logic
func (s *Spoa) handleAppSecValidation(mes *message.Message, host *host.Host, method, url *string, headers http.Header, body *[]byte) remediation.Remediation {
	// Extract additional information for AppSec validation
	var remoteIP string
	var userAgent string
	var version string

	// Get remote IP from the request
	if srcIP, err := readKeyFromMessage[net.IP](mes, "src-ip"); err == nil {
		remoteIP = srcIP.String()
	}

	// Extract User-Agent for AppSec validation
	if headers != nil {
		userAgent = headers.Get("User-Agent")
	}

	// Extract HTTP version from the message
	if msgVersion, err := readKeyFromMessage[string](mes, "version"); err == nil && msgVersion != nil {
		version = *msgVersion
	}

	// Prepare body for AppSec validation
	if body == nil {
		msgBody, err := readKeyFromMessage[[]byte](mes, "body")
		if err == nil && msgBody != nil {
			body = msgBody
		}
	}

	appSecRemediation, err := s.workerClient.ValHostAppSec(
		host.Host,
		*method,
		*url,
		headers,
		*body,
		remoteIP,
		userAgent,
		version,
	)

	if err != nil {
		log.WithFields(log.Fields{
			"host":  host.Host,
			"error": err,
		}).Error("AppSec validation failed, allowing request")
		return remediation.Allow
	}

	log.WithFields(log.Fields{
		"host":        host.Host,
		"method":      *method,
		"url":         *url,
		"remediation": appSecRemediation.String(),
	}).Debug("AppSec validation completed")

	return appSecRemediation
}

// Handles checking the http request which has 2 stages
// First stage is to check the host header and determine if the remediation from handleIpRequest is still valid
// Second stage is to check if AppSec is enabled and then forward to the component if needed
func (s *Spoa) handleHTTPRequest(req *request.Request, mes *message.Message) {
	r := remediation.Allow

	rstring, err := readKeyFromMessage[string](mes, "remediation")

	if err == nil {
		log.Debug("remediation: ", *rstring)
		r = remediation.FromString(*rstring)
	} else {
		log.Info("ip remediation was not found in message, defaulting to allow")
	}

	hoststring, err := readKeyFromMessage[string](mes, "host")

	var host *host.Host

	// defer a function that always add the remediation to the request at end of processing
	defer func() {
		if host == nil && r == remediation.Captcha {
			log.Warn("remediation is captcha, no matching host was found cannot issue captcha remediation reverting to ban")
			r = remediation.Ban
		}
		rString := r.String()
		req.Actions.SetVar(action.ScopeTransaction, "remediation", rString)
	}()

	if err != nil {
		return
	}

	host, err = s.workerClient.GetHost(*hoststring)

	// if the host is not found we cannot alter the remediation or do appsec checks
	if host == nil || err != nil {
		return
	}

	// Extract HTTP request data
	method, url, headers, body, err := s.extractHTTPRequestData(mes)
	if err != nil {
		log.Printf("failed to extract HTTP request data: %v", err)
		return
	}

	switch r {
	case remediation.Allow:
		// If user has a captcha cookie but decision is Allow, generate unset cookie
		// We don't set captcha_status, so HAProxy knows to clear the cookie
		cookieB64, _ := readKeyFromMessage[string](mes, "crowdsec_captcha_cookie")
		if cookieB64 != nil {
			ssl, err := readKeyFromMessage[bool](mes, "ssl")
			if err != nil {
				log.Error(err)
			}

			unsetCookie, err := s.workerClient.GetHostUnsetCookie(*hoststring, fmt.Sprint(*ssl))
			if err != nil {
				log.WithFields(log.Fields{
					"host":  *hoststring,
					"ssl":   ssl,
					"error": err,
				}).Error("Failed to generate unset cookie")
				return // Cannot proceed without unset cookie
			}

			log.WithFields(log.Fields{
				"host": *hoststring,
			}).Debug("Allow decision but captcha cookie present, will clear cookie")
			req.Actions.SetVar(action.ScopeTransaction, "captcha_cookie", unsetCookie.String())
			// Note: We deliberately don't set captcha_status here
		}
	case remediation.Ban:
		//Handle ban
		host.Ban.InjectKeyValues(&req.Actions)
	case remediation.Captcha:
		if err := host.Captcha.InjectKeyValues(&req.Actions); err != nil {
			r = remediation.FromString(host.Captcha.FallbackRemediation)
			return
		}

		cookieB64, _ := readKeyFromMessage[string](mes, "crowdsec_captcha_cookie")
		uuid := ""

		if cookieB64 != nil {
			uuid, err = s.workerClient.ValHostCookie(*hoststring, *cookieB64)
			if err != nil {
				log.WithFields(log.Fields{
					"host":  *hoststring,
					"error": err,
				}).Warn("Failed to validate existing cookie")
				uuid = "" // Reset to generate new cookie
			}
		}

		if uuid == "" {
			ssl, err := readKeyFromMessage[bool](mes, "ssl")

			if err != nil {
				log.Error(err)
			}

			cookie, err := s.workerClient.GetHostCookie(*hoststring, fmt.Sprint(*ssl))
			if err != nil {
				log.WithFields(log.Fields{
					"host":  *hoststring,
					"ssl":   ssl,
					"error": err,
				}).Error("Failed to generate host cookie")
				return // Cannot proceed without cookie
			}

			uuid, err = s.workerClient.ValHostCookie(*hoststring, cookie.Value)
			if err != nil {
				log.WithFields(log.Fields{
					"host":   *hoststring,
					"cookie": cookie.Value,
					"error":  err,
				}).Error("Failed to validate new cookie")
				return // Cannot proceed without valid cookie
			}

			// Set the captcha cookie - status will be set later based on session state
			req.Actions.SetVar(action.ScopeTransaction, "captcha_cookie", cookie.String())
		}

		if uuid == "" {
			// We should never hit this but safety net
			// As a fallback we set the remediation to the fallback remediation
			log.Error("failed to get uuid from cookie")
			r = remediation.FromString(host.Captcha.FallbackRemediation)
			return
		}

		// Get the current captcha status from the session
		val, err := s.workerClient.GetHostSessionKey(*hoststring, uuid, session.CaptchaStatus)
		if err != nil {
			log.WithFields(log.Fields{
				"host":    *hoststring,
				"session": uuid,
				"error":   err,
			}).Warn("Failed to get captcha status, assuming pending")
			val = captcha.Pending // Assume pending if we can't get status
		}

		// Set the captcha status in the transaction for HAProxy
		req.Actions.SetVar(action.ScopeTransaction, "captcha_status", val)
		if val != captcha.Valid {
			// Update the incoming url if it is different from the stored url for the session ignore favicon requests
			storedURL, err := s.workerClient.GetHostSessionKey(*hoststring, uuid, session.URI)
			if err != nil {
				log.WithFields(log.Fields{
					"host":    *hoststring,
					"session": uuid,
					"error":   err,
				}).Warn("Failed to get stored URL, assuming empty")
				storedURL = "" // Assume empty if we can't get it
			}

			if (storedURL == "" || url != nil && *url != storedURL) && !strings.HasSuffix(*url, ".ico") {
				log.WithField("session", uuid).Debugf("updating stored url %s", *url)
				_, err2 := s.workerClient.SetHostSessionKey(*hoststring, uuid, session.URI, *url)
				if err2 != nil {
					log.WithFields(log.Fields{
						"host":    *hoststring,
						"session": uuid,
						"url":     *url,
						"error":   err2,
					}).Error("Failed to set host session URI")
				}
			}
		}

		// Headers are already extracted above for AppSec validation

		// Check if the request is a captcha validation request
		captchaStatus, err := s.workerClient.GetHostSessionKey(*hoststring, uuid, session.CaptchaStatus)
		if err != nil {
			log.WithFields(log.Fields{
				"host":    *hoststring,
				"session": uuid,
				"error":   err,
			}).Warn("Failed to get captcha status for validation check")
			captchaStatus = "" // Assume not pending if we can't get status
		}

		if captchaStatus == captcha.Pending && method != nil && *method == http.MethodPost && headers.Get("Content-Type") == "application/x-www-form-urlencoded" {
			body, err = readKeyFromMessage[[]byte](mes, "body")

			if err != nil {
				log.Printf("failed to read body: %v", err)
				return
			}

			isValid, err := s.workerClient.ValHostCaptcha(*hoststring, uuid, string(*body))
			if err != nil {
				log.WithFields(log.Fields{
					"host":    *hoststring,
					"session": uuid,
					"error":   err,
				}).Error("Failed to validate captcha")
			} else if isValid {
				_, err := s.workerClient.SetHostSessionKey(*hoststring, uuid, session.CaptchaStatus, captcha.Valid)
				if err != nil {
					log.WithFields(log.Fields{
						"host":    *hoststring,
						"session": uuid,
						"error":   err,
					}).Error("Failed to set captcha status to valid")
				}
			}
		}

		// if the session has a valid captcha status we allow the request
		finalStatus, err := s.workerClient.GetHostSessionKey(*hoststring, uuid, session.CaptchaStatus)
		if err != nil {
			log.WithFields(log.Fields{
				"host":    *hoststring,
				"session": uuid,
				"error":   err,
			}).Warn("Failed to get final captcha status")
		} else if finalStatus == captcha.Valid {
			r = remediation.Allow
			// The captcha_status was already set above with the actual session status
			storedURL, err := s.workerClient.GetHostSessionKey(*hoststring, uuid, session.URI)
			if err != nil {
				log.WithFields(log.Fields{
					"host":    *hoststring,
					"session": uuid,
					"error":   err,
				}).Warn("Failed to get stored URL for redirect")
			} else if storedURL != "" {
				log.Debug("redirecting to: ", storedURL)
				req.Actions.SetVar(action.ScopeTransaction, "redirect", storedURL)
				// Delete the URI from the session so we dont redirect loop
				_, err := s.workerClient.DeleteHostSessionKey(*hoststring, uuid, session.URI)
				if err != nil {
					log.WithFields(log.Fields{
						"host":    *hoststring,
						"session": uuid,
						"error":   err,
					}).Warn("Failed to delete stored URL after redirect")
				}
			}
		}
	}

	// If remediation is ban/captcha we dont need to create a request to send to appsec unless always send is on
	if r > remediation.Unknown && !host.AppSec.AlwaysSend {
		return
	}

	// AppSec validation
	// Always attempt AppSec validation - the API will handle whether AppSec is enabled or not
	appSecRemediation := s.handleAppSecValidation(mes, host, method, url, headers, body)

	// Update remediation based on AppSec result
	// AppSec can override the original remediation
	if appSecRemediation > r {
		r = appSecRemediation
	}
}

// Handles checking the IP address against the dataset
func (s *Spoa) handleIPRequest(req *request.Request, mes *message.Message) {
	var r remediation.Remediation

	ipType, err := readKeyFromMessage[net.IP](mes, "src-ip")

	if err != nil {
		log.Error(err)
		return
	}

	ipStr := ipType.String()

	r, err = s.workerClient.GetIP(ipStr)
	if err != nil {
		log.WithFields(log.Fields{
			"ip":    ipStr,
			"error": err,
		}).Error("Failed to get IP remediation")
		r = remediation.Allow // Safe default
	}

	if r < remediation.Unknown {
		iso, err := s.workerClient.GetGeoIso(ipStr)
		if err != nil {
			log.WithFields(log.Fields{
				"ip":    ipStr,
				"error": err,
			}).Warn("Failed to get geo ISO, skipping country check")
		} else if iso != "" {
			cnR, err := s.workerClient.GetCN(iso, ipStr)
			if err != nil {
				log.WithFields(log.Fields{
					"ip":           ipStr,
					"country_code": iso,
					"error":        err,
				}).Warn("Failed to get country remediation")
			} else {
				r = cnR
			}
			req.Actions.SetVar(action.ScopeTransaction, "isocode", iso)
		}
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
