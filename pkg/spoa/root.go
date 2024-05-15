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
	message_names = []string{"crowdsec-http", "crowdsec-ip"}
)

type Spoa struct {
	ListenAddr   net.Listener
	ListenSocket net.Listener
	Server       *agent.Agent
	HAWaitGroup  *sync.WaitGroup
	ctx          context.Context
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

	ctx, cancel := context.WithCancel(context.Background())
	s := &Spoa{
		HAWaitGroup:  &sync.WaitGroup{},
		ctx:          ctx,
		cancel:       cancel,
		logger:       clog.WithField("worker", name),
		workerClient: worker.NewWorkerClient(socket),
	}

	if tcpAddr != "" {
		addr, err := net.Listen("tcp", tcpAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to listen on %s: %v", tcpAddr, err)
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
				return nil, fmt.Errorf("failed to stat socket %s: %v", unixAddr, err)
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
				return nil, fmt.Errorf("failed to remove socket %s: %v", unixAddr, err)
			}
		}

		// Set umask to 0o777
		origUmask := syscall.Umask(0o777)

		// Create new socket
		addr, err := net.Listen("unix", unixAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to listen on %s: %v", unixAddr, err)
		}

		// Reset umask
		syscall.Umask(origUmask)

		// Change socket owner and permissions
		os.Chown(unixAddr, uid, gid)
		os.Chmod(unixAddr, 0o660)

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
	// We don't close the unix socket as we want to persist permissions

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
		log.Printf("ip remediation was not found in message, defaulting to allow")
	}

	// hoststring, err := readKeyFromMessage[string](mes, "host")

	var host *host.Host

	// defer a function that always add the remediation to the request at end of processing
	defer func() {
		if host == nil && r == remediation.Captcha {
			log.Info("host was not found in the message cannot issue captcha remediation reverting to ban")
			r = remediation.Ban
		}
		rString := r.String()
		req.Actions.SetVar(action.ScopeTransaction, "remediation", rString)
	}()

	if err != nil {
		return
	}

	//host = s.cfg.Hosts.MatchFirstHost(*hoststring)

	// if the host is not found we cannot alter the remediation or do appsec checks
	if host == nil {
		return
	}

	var url *string
	var method *string
	var body *[]byte
	var headers http.Header

	switch r {
	case remediation.Allow:
		// !TODO Check if cookie is sent and session is valid if not valid then issue an unset cookie
	case remediation.Ban:
		//Handle ban
		host.Ban.InjectKeyValues(&req.Actions)
	case remediation.Captcha:
		if err := host.Captcha.InjectKeyValues(&req.Actions); err != nil {
			r = remediation.FromString(host.Captcha.FallbackRemediation)
		}

		cookieB64, cookieErr := readKeyFromMessage[string](mes, "crowdsec_captcha_cookie")
		var s *session.Session

		if cookieB64 != nil {
			sessionValue, err := host.Captcha.CookieGenerator.ValidateCookie(*cookieB64)
			if err == nil {
				s = host.Captcha.Sessions.GetSession(sessionValue)

				// if we cant find the session from the cookie provided we set it to nil
				if s == nil {
					cookieB64 = nil
				}
			}
		}

		// if cookieB64 return an error or session is nil we create a new session
		if cookieErr != nil || s == nil {
			s, err = host.Captcha.Sessions.NewRandomSession()
			if err != nil {
				// should we revert back to ban?
				log.Error(err)
				return
			}
			s.Set(session.CAPTCHA_STATUS, captcha.Pending)
		}

		method, err = readKeyFromMessage[string](mes, "method")
		if err != nil {
			log.Printf("failed to read method: %v", err)
			return
		}

		headersType, err := readKeyFromMessage[string](mes, "headers")

		if err != nil {
			log.Printf("failed to read headers: %v", err)
			return
		}

		headers, err = readHeaders(*headersType)

		if err != nil {
			log.Printf("failed to parse headers: %v", err)
		}

		// Check if the request is a captcha validation request
		if s.Get(session.CAPTCHA_STATUS) != captcha.Valid && method != nil && *method == http.MethodPost && headers.Get("Content-Type") == "application/x-www-form-urlencoded" {
			body, err = readKeyFromMessage[[]byte](mes, "body")

			if err != nil {
				log.Printf("failed to read body: %v", err)
				return
			}
			host.Captcha.Validate(s, string(*body))
		}

		url, err = readKeyFromMessage[string](mes, "url")

		if err != nil {
			log.Printf("failed to read url: %v", err)
			return
		}

		// if captcha is not valid then update the url in the session
		if s.Get(session.CAPTCHA_STATUS) != captcha.Valid {
			// Update the incoming url if it is different from the stored url for the session ignore favicon requests
			if storedUrl := s.Get(session.URI); (storedUrl == nil || url != nil && *url != storedUrl.(string)) && !strings.HasSuffix(*url, ".ico") {
				log.WithField("session", s.Uuid).Debugf("updating stored url %s", *url)
				s.Set(session.URI, *url)
			} // !TODO we should ignore static files also
		}

		// if original cookie is not found or we set it to nil we send a new cookie to haproxy
		if cookieB64 == nil {
			ssl, err := readKeyFromMessage[bool](mes, "ssl")

			if err != nil {
				log.Error(err)
			}
			cookie, err := host.Captcha.CookieGenerator.GenerateCookie(s, ssl)
			if err != nil {
				// should we revert back to ban?
				log.Error(err)
				return
			}

			req.Actions.SetVar(action.ScopeTransaction, "captcha_cookie", cookie.String())
		}

		// if the session has a valid captcha status we allow the request
		if s.Get(session.CAPTCHA_STATUS) == captcha.Valid {
			r = remediation.Allow
			storedUrl := s.Get(session.URI)
			// On first valid captcha we redirect to the stored url
			if storedUrl != nil {
				if uriString, ok := storedUrl.(string); ok {
					log.Debug("redirecting to: ", uriString)
					req.Actions.SetVar(action.ScopeTransaction, "redirect", uriString)
					// Delete the URI from the session so we dont redirect loop
					s.Delete(session.URI)
				}
			}
		}
	}

	// If remediation is ban/captcha we dont need to create a request to send to appsec unless always send is on
	if r > remediation.Unknown && !host.AppSec.AlwaysSend {
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
	ipType, err := readKeyFromMessage[net.IP](mes, "src-ip")

	if err != nil {
		log.Error(err)
		return
	}

	r := remediation.Allow
	r = remediation.FromString(s.workerClient.GetIP(ipType.String()))

	if r < remediation.Unknown {
		iso := s.workerClient.GetGeoIso(ipType.String())
		if iso != "" {
			r = remediation.FromString(s.workerClient.GetCN(iso))
			req.Actions.SetVar(action.ScopeTransaction, "isocode", iso)
		}
	}

	req.Actions.SetVar(action.ScopeTransaction, "remediation", r.String())
}

func handlerWrapper(s *Spoa) func(req *request.Request) {
	return func(req *request.Request) {
		s.HAWaitGroup.Add(1)
		defer s.HAWaitGroup.Done()

		if s.ctx.Err() != nil {
			log.Warn("context is done, skipping request")
			return
		}

		for _, messageName := range message_names {
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
