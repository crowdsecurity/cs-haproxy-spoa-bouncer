package spoa

import (
	"context"
	"errors"
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

	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
)

const (
	crowdsec_http_message              = "crowdsec-http"
	crowdsec_ip_message                = "crowdsec-ip"
	crowdsec_appsec_small_body_message = "crowdsec-appsec-small-body"
	crowdsec_appsec_large_body_message = "crowdsec-appsec-large-body"
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

		if r <= remediation.Unknown || host.AppSec.AlwaysSend {
			req.Actions.SetVar(action.ScopeTransaction, "send_to_appsec", true)
		}
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

	// If remediation is ban/captcha we dont need to create a request to send to appsec unless always send is on
	if r > remediation.Unknown && !host.AppSec.AlwaysSend {
		return
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
			r, _ = s.workerClient.GetCN(iso, ipStr)
			req.Actions.SetVar(action.ScopeTransaction, "isocode", iso)
		}
	}

	req.Actions.SetVar(action.ScopeTransaction, "remediation", r.String())
}

func (s *Spoa) handleAppsecRequest(req *request.Request, mes *message.Message) {
	// !TODO APPSEC STUFF
	//Probably better to do this in the worker ? But this means we need to send everything to the worker :(

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

	clientIP, err := readKeyFromMessage[net.IP](mes, "src-ip")
	if err != nil {
		log.Errorf("failed to read client ip: %v", err)
		return
	}

	method, err := readKeyFromMessage[string](mes, "method")
	if err != nil {
		log.Errorf("failed to read method: %v", err)
		return
	}

	headers, err := readKeyFromMessage[string](mes, "headers")
	if err != nil {
		log.Errorf("failed to read headers: %v", err)
		return
	}

	body, err := readKeyFromMessage[[]byte](mes, "body")
	if err != nil && !errors.Is(err, errkeyNotFound) {
		log.Errorf("failed to read body: %v", err)
		return
	}

	path, err := readKeyFromMessage[string](mes, "path")
	if err != nil {
		log.Errorf("failed to read path: %v", err)
		return
	}

	query, err := readKeyFromMessage[string](mes, "query")
	if err != nil {
		log.Errorf("failed to read query: %v", err)
		return
	}

	log.Infof("method: %s, headers: %s, body: %s | path: %s | query: %s", *method, *headers, *body, *path, *query)

	//FIXME: do this properly
	appsecClient := &csbouncer.AppSec{}
	appsecConfig := &csbouncer.AppSecConfig{
		Url: "http://host.docker.internal:7422",
	}
	appsecClient.APIKey = "WK3mH5KsS1ZnnCErAOqqkgbwMuN27yuzVqT7k8nuX2Y"
	appsecClient.AppSecConfig = appsecConfig
	err = appsecClient.Init()

	if err != nil {
		log.Errorf("failed to init appsec client: %v", err)
		return
	}

	requestUrl := *path
	if query != nil {
		requestUrl += "?" + *query
	}

	appsecRequest, err := http.NewRequest(*method, requestUrl, strings.NewReader(string(*body)))

	if err != nil {
		log.Errorf("failed to create appsec request: %v", err)
		return
	}

	/*appsecRequest.Method = *method
	appsecRequest.Header = http.Header{}

	appsecRequest.URL.Path = *path
	appsecRequest.URL.RawQuery = *query*/

	appsecResponse, err := appsecClient.ForwardWithIP(appsecRequest, clientIP.String())

	if err != nil {
		log.Errorf("failed to forward request to appsec: %v", err)
		return
	}

	log.Infof("appsec response: %+v", appsecResponse)
}

func handlerWrapper(s *Spoa) func(req *request.Request) {
	return func(req *request.Request) {
		s.HAWaitGroup.Add(1)
		defer s.HAWaitGroup.Done()

		if s.ctx.Err() != nil {
			log.Warn("context is done, skipping request")
			return
		}

		msgCount := req.Messages.Len()

		for i := 0; i < msgCount; i++ {
			mes, err := req.Messages.GetByIndex(i)
			if err != nil {
				s.logger.Errorf("failed to get message by index: %s", err)
				continue
			}
			s.logger.Infof("Received message: %s", mes.Name)
			switch mes.Name {
			case crowdsec_http_message:
				s.handleHTTPRequest(req, mes)
			case crowdsec_ip_message:
				s.handleIPRequest(req, mes)
			case crowdsec_appsec_small_body_message, crowdsec_appsec_large_body_message:
				s.handleAppsecRequest(req, mes)
			default:
				s.logger.Warn("unknown message type: ", mes.Name)
			}
		}
	}
}

var errkeyNotFound = fmt.Errorf("key not found")
var errkeyWrongType = fmt.Errorf("key has wrong type")

// readKeyFromMessage reads a key from a message and returns it as the type T
func readKeyFromMessage[T string | net.IP | bool | []byte](msg *message.Message, key string) (*T, error) {
	value, ok := msg.KV.Get(key)
	if !ok {
		return nil, errkeyNotFound
	}
	s, ok := value.(T)
	if !ok {
		log.Errorf("key %s has wrong type (expected %T, found %T)", key, *new(T), value)
		return nil, errkeyWrongType
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
