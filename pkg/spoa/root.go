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

	"github.com/crowdsecurity/crowdsec-spoa/internal/appsec"
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

const (
	crowdsecAppsecIPHeader   = "X-Crowdsec-Appsec-Ip"
	crowdsecAppsecURIHeader  = "X-Crowdsec-Appsec-Uri"
	crowdsecAppsecHostHeader = "X-Crowdsec-Appsec-Host"
	crowdsecAppsecVerbHeader = "X-Crowdsec-Appsec-Verb"
	crowdsecAppsecHeader     = "X-Crowdsec-Appsec-Api-Key"
	crowdsecAppsecUserAgent  = "X-Crowdsec-Appsec-User-Agent"
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
	appsec       *appsec.AppsecConfig
}

func New(workerConfig worker.WorkerConfig) (*Spoa, error) {
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

	client, err := worker.NewWorkerClient(socket)
	if err != nil {
		return nil, fmt.Errorf("failed to create worker client: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	s := &Spoa{
		HAWaitGroup:  &sync.WaitGroup{},
		ctx:          ctx,
		cancel:       cancel,
		logger:       clog.WithField("worker", name),
		workerClient: client,
		appsec:       workerConfig.AppSecConfig,
	}

	if workerConfig.TcpAddr != "" {
		addr, err := net.Listen("tcp", workerConfig.TcpAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to listen on %s: %v", workerConfig.TcpAddr, err)
		}
		s.ListenAddr = addr
	}

	if workerConfig.UnixAddr != "" {
		// Get current process uid/gid usually worker node
		uid := os.Getuid()
		gid := os.Getgid()

		// Get existing socket stat
		fileInfo, err := os.Stat(workerConfig.UnixAddr)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("failed to stat socket %s: %v", workerConfig.UnixAddr, err)
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
		if err := os.Remove(workerConfig.UnixAddr); err != nil {
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("failed to remove socket %s: %v", workerConfig.UnixAddr, err)
			}
		}

		// Set umask to 0o777
		origUmask := syscall.Umask(0o777)

		// Create new socket
		addr, err := net.Listen("unix", workerConfig.UnixAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to listen on %s: %v", workerConfig.UnixAddr, err)
		}

		// Reset umask
		syscall.Umask(origUmask)

		// Change socket owner and permissions
		os.Chown(workerConfig.UnixAddr, uid, gid)
		os.Chmod(workerConfig.UnixAddr, 0o660)

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

	var url *string
	var method *string
	var body *[]byte
	var headers http.Header

	// If remediation is ban/captcha we dont need to create a request to send to appsec unless always send is on
	if r > remediation.Unknown && !s.appsec.Enabled { //&& !host.AppSec.AlwaysSend {
		return
	}

	if s.appsec.Enabled {
		id, err := readKeyFromMessage[string](mes, "unique-id")

		if err != nil {
			log.Printf("failed to read headers: %v", err)
			return
		}

		if s.appsec.AppsecRequests[*id] == nil { //should already exists but safety net
			s.appsec.AppsecRequests[*id] = &appsec.AppsecRequest{}
		}

		h := headers.Clone()
		s.appsec.AppsecRequests[*id].AddHeaders(&h)
		userAgent := headers.Get("User-Agent")
		s.appsec.AppsecRequests[*id].AddHeaders(&http.Header{
			crowdsecAppsecUserAgent:  []string{userAgent},
			crowdsecAppsecURIHeader:  []string{*url},
			crowdsecAppsecHostHeader: []string{*hoststring},
			crowdsecAppsecVerbHeader: []string{*method},
			crowdsecAppsecHeader:     []string{s.appsec.ApiKey},
		})

		s.appsec.AppsecRequests[*id].SetBody(*body)
		s.appsec.AppsecRequests[*id].SetMethod(*method)
		client := &http.Client{}
		resp, err := client.Do(s.appsec.AppsecRequests[*id].GenerateHTTPRequest())
		if err != nil {
			log.Fatalf("sending request failed: %v", err)
		}
		switch resp.StatusCode {
		case http.StatusOK:
			log.Tracef("request was allowed %v", id)
		case http.StatusForbidden:
			log.Tracef("request was denied %v", id)
			r = remediation.Ban
		default:
			log.Errorf("unexpected status code %d", resp.StatusCode)
		}
		defer resp.Body.Close()

	}

	switch r {
	case remediation.Allow:
		// !TODO Check if cookie is sent and session is valid if not valid then issue an unset cookie
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
			uuid, _ = s.workerClient.ValHostCookie(*hoststring, *cookieB64)
		}

		if uuid == "" {
			ssl, err := readKeyFromMessage[bool](mes, "ssl")

			if err != nil {
				log.Error(err)
			}

			cookie, _ := s.workerClient.GetHostCookie(*hoststring, fmt.Sprint(*ssl))

			uuid, _ = s.workerClient.ValHostCookie(*hoststring, cookie.Value)

			req.Actions.SetVar(action.ScopeTransaction, "captcha_cookie", cookie.String())
		}

		if uuid == "" {
			// We should never hit this but safety net
			// As a fallback we set the remediation to the fallback remediation
			log.Error("failed to get uuid from cookie")
			r = remediation.FromString(host.Captcha.FallbackRemediation)
			return
		}

		url, err = readKeyFromMessage[string](mes, "url")

		if err != nil {
			log.Printf("failed to read url: %v", err)
			return
		}

		// if captcha is not valid then update the url in the session
		if val, _ := s.workerClient.GetHostSessionKey(*hoststring, uuid, session.CAPTCHA_STATUS); val != captcha.Valid {
			// Update the incoming url if it is different from the stored url for the session ignore favicon requests
			storedUrl, err := s.workerClient.GetHostSessionKey(*hoststring, uuid, session.URI)
			if err != nil {
				log.Error(err)
			}

			if err == nil && (storedUrl == "" || url != nil && *url != storedUrl) && !strings.HasSuffix(*url, ".ico") {
				log.WithField("session", uuid).Debugf("updating stored url %s", *url)
				s.workerClient.SetHostSessionKey(*hoststring, uuid, session.URI, *url)
			}
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
		if val, _ := s.workerClient.GetHostSessionKey(*hoststring, uuid, session.CAPTCHA_STATUS); val == captcha.Pending && method != nil && *method == http.MethodPost && headers.Get("Content-Type") == "application/x-www-form-urlencoded" {
			body, err = readKeyFromMessage[[]byte](mes, "body")

			if err != nil {
				log.Printf("failed to read body: %v", err)
				return
			}
			if val, _ := s.workerClient.ValHostCaptcha(*hoststring, uuid, string(*body)); val {
				s.workerClient.SetHostSessionKey(*hoststring, uuid, session.CAPTCHA_STATUS, captcha.Valid)
			}
		}

		// if the session has a valid captcha status we allow the request
		if val, _ := s.workerClient.GetHostSessionKey(*hoststring, uuid, session.CAPTCHA_STATUS); val == captcha.Valid {
			r = remediation.Allow
			storedUrl, _ := s.workerClient.GetHostSessionKey(*hoststring, uuid, session.URI)
			// On first valid captcha we redirect to the stored url
			if storedUrl != "" {
				log.Debug("redirecting to: ", storedUrl)
				req.Actions.SetVar(action.ScopeTransaction, "redirect", storedUrl)
				// Delete the URI from the session so we dont redirect loop
				s.workerClient.DeleteHostSessionKey(*hoststring, uuid, session.URI)
			}
		}
	}

}

// Handles checking the IP address against the dataset
func (s *Spoa) handleIPRequest(req *request.Request, mes *message.Message) {
	ipType, err := readKeyFromMessage[net.IP](mes, "src-ip")

	if err != nil {
		log.Error(err)
		return
	}

	r := remediation.Allow
	ipStr := ipType.String()

	r, _ = s.workerClient.GetIP(ipStr)

	if r < remediation.Unknown {
		iso, _ := s.workerClient.GetGeoIso(ipStr)
		if iso != "" {
			r, _ = s.workerClient.GetCN(iso)
			req.Actions.SetVar(action.ScopeTransaction, "isocode", iso)
		}
	}

	req.Actions.SetVar(action.ScopeTransaction, "remediation", r.String())
	if s.appsec.Enabled {

		id, err := readKeyFromMessage[string](mes, "unique-id")
		if err != nil {
			log.Error(err)
			return
		}
		if s.appsec.AppsecRequests[*id] == nil {
			s.appsec.AppsecRequests[*id] = &appsec.AppsecRequest{}
		}
		s.appsec.AppsecRequests[*id].AddHeaders(&http.Header{
			"X-Crowdsec-Appsec-Ip": []string{ipStr}},
		)
		s.appsec.AppsecRequests[*id].ValidateTCP()
	}
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
