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

	"github.com/crowdsecurity/crowdsec-spoa/pkg/cfg"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/dataset"
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
	DataSet      *dataset.DataSet
	ctx          context.Context
	cancel       context.CancelFunc
	cfg          *cfg.BouncerConfig
}

func New(cfg *cfg.BouncerConfig, dataset *dataset.DataSet) (*Spoa, error) {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Spoa{
		DataSet:     dataset,
		HAWaitGroup: &sync.WaitGroup{},
		ctx:         ctx,
		cancel:      cancel,
		cfg:         cfg,
	}

	if cfg.ListenAddr != "" {
		addr, err := net.Listen("tcp", cfg.ListenAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to listen on %s: %v", cfg.ListenAddr, err)
		}
		s.ListenAddr = addr
	}

	if cfg.ListenSocket != "" {
		// Get current gid
		gid := os.Getgid()
		// Get existing socket stat
		fileInfo, err := os.Stat(cfg.ListenSocket)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("failed to stat socket %s: %v", cfg.ListenSocket, err)
			}
		} else {
			stat, ok := fileInfo.Sys().(*syscall.Stat_t)
			if !ok {
				return nil, fmt.Errorf("failed to get socket stat")
			}
			// Set gid to existing socket
			gid = int(stat.Gid)
		}

		if err := os.Remove(cfg.ListenSocket); err != nil {
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("failed to remove socket %s: %v", cfg.ListenSocket, err)
			}
		}

		origUmask := syscall.Umask(0o777)

		addr, err := net.Listen("unix", cfg.ListenSocket)
		if err != nil {
			return nil, fmt.Errorf("failed to listen on %s: %v", cfg.ListenSocket, err)
		}

		syscall.Umask(origUmask)

		os.Chown(cfg.ListenSocket, 0, gid)
		os.Chmod(cfg.ListenSocket, 0o660)

		s.ListenSocket = addr
	}

	s.Server = agent.New(handlerWrapper(s), log.StandardLogger())

	return s, nil
}

func (s *Spoa) ServeTCP(ctx context.Context) error {
	if s.ListenAddr == nil {
		return nil
	}
	log.Infof("Serving TCP server on %s", s.ListenAddr.Addr().String())

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
	log.Infof("Serving Unix server on %s", s.ListenSocket.Addr().String())

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
	log.Info("Shutting down SPOA")

	doneChan := make(chan struct{})

	if s.ListenAddr != nil {
		s.ListenAddr.Close()
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

// Handles checking the http request which has 2 stages
// First stage is to check the host header and determine if the remdiation from handleIpRequest is still valid
// Second stage is to check if AppSec is enabled and then forward to the component if needed
func (s *Spoa) handleHTTPRequest(req *request.Request, mes *message.Message) {
	remediation := dataset.Allow

	rstring, err := readKeyFromMessage[string](mes, "remediation")

	if err == nil {
		log.Debug("remediation: ", *rstring)
		remediation = dataset.RemedationFromString(*rstring)
	} else {
		log.Printf("ip remediation was not found in message, defaulting to allow")
	}

	hoststring, err := readKeyFromMessage[string](mes, "host")

	var host *host.Host

	// defer a function that always add the remediation to the request at end of processing
	defer func() {
		if host == nil && remediation == dataset.Captcha {
			log.Info("host was not found in the message cannot issue captcha remediation reverting to ban")
			remediation = dataset.Ban
		}
		rString := remediation.String()
		req.Actions.SetVar(action.ScopeTransaction, "remediation", rString)
	}()

	if err != nil {
		return
	}

	host = s.cfg.Hosts.MatchFirstHost(*hoststring)

	// if the host is not found we cannot alter the remediation or do appsec checks
	if host == nil {
		return
	}

	switch remediation {
	case dataset.Ban:
		//Handle ban
		host.Ban.InjectKeyValues(&req.Actions)
	case dataset.Captcha:
		// Handle captcha
		// Check if IP is within grace period
		// host.Captcha.CheckGrace(&ip)
		// We have to compile the request back together then check
		// If within grace, revert to allow
		// if not within grace we inject the key values
		if err := host.Captcha.InjectKeyValues(&req.Actions); err != nil {
			remediation = dataset.RemedationFromString(host.Captcha.FallbackRemediation)
		}
	}

	// If remediation is ban/captcha we dont need to create a request to send to appsec unless always send is on
	if remediation > dataset.Unknown && !host.AppSec.AlwaysSend {
		return
	}

	headersType, err := readKeyFromMessage[string](mes, "headers")

	if err != nil {
		log.Printf("failed to read headers: %v", err)
		return
	}

	headers, err := readHeaders(*headersType)
	if err != nil {
		log.Printf("failed to parse headers: %v", err)
	}

	var body string
	var method string
	var url string

	methodString, err := readKeyFromMessage[string](mes, "method")
	if err != nil {
		log.Printf("failed to read method: %v", err)
		return
	}
	method = strings.ToUpper(*methodString)

	bodyString, err := readKeyFromMessage[string](mes, "body")

	if err != nil {
		log.Printf("failed to read body: %v", err)
		return
	}
	body = *bodyString

	urlString, err := readKeyFromMessage[string](mes, "url")

	if err != nil {
		log.Printf("failed to read url: %v", err)
		return
	}
	url = *urlString

	request, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		log.Printf("failed to create request: %v", err)
		return
	}
	request.Header = headers
}

// Handles checking the IP address against the dataset
// !TODO add country code check
func (s *Spoa) handleIPRequest(req *request.Request, mes *message.Message) {
	ipType, err := readKeyFromMessage[net.IP](mes, "src-ip")

	if err != nil {
		log.Error(err)
		return
	}

	remediation := s.DataSet.CheckIP(ipType)

	req.Actions.SetVar(action.ScopeTransaction, "remediation", remediation.String())
}

func handlerWrapper(spoad *Spoa) func(req *request.Request) {
	return func(req *request.Request) {
		spoad.HAWaitGroup.Add(1)
		defer spoad.HAWaitGroup.Done()

		if spoad.ctx.Err() != nil {
			log.Warn("context is done, skipping request")
			return
		}

		for _, messageName := range message_names {
			mes, err := req.Messages.GetByName(messageName)
			if err != nil {
				continue
			}
			log.Debug("Received message: ", messageName)
			switch messageName {
			case "crowdsec-http":
				spoad.handleHTTPRequest(req, mes)
			case "crowdsec-ip":
				spoad.handleIPRequest(req, mes)
			}
		}
	}
}

// readKeyFromMessage reads a key from a message and returns it as the type T
func readKeyFromMessage[T string | net.IP](msg *message.Message, key string) (*T, error) {
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
