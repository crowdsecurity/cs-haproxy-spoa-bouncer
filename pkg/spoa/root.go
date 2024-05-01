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
	"github.com/negasus/haproxy-spoe-go/action"
	"github.com/negasus/haproxy-spoe-go/agent"
	"github.com/negasus/haproxy-spoe-go/request"
	log "github.com/sirupsen/logrus"
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

func handlerWrapper(spoad *Spoa) func(req *request.Request) {
	return func(req *request.Request) {
		spoad.HAWaitGroup.Add(1)
		defer spoad.HAWaitGroup.Done()

		if spoad.ctx.Err() != nil {
			log.Warn("context is done, skipping request")
			return
		}

		log.Printf("handle request EngineID: '%s', StreamID: '%d', FrameID: '%d' with %d messages\n", req.EngineID, req.StreamID, req.FrameID, req.Messages.Len())

		messageName := "crowdsec-req"

		mes, err := req.Messages.GetByName(messageName)
		if err != nil {
			log.Printf("message %s not found: %v", messageName, err)
			return
		}

		ipValue, ok := mes.KV.Get("src-ip")
		if !ok {
			log.Printf("var 'ip' not found in message")
			return
		}

		ip, ok := ipValue.(net.IP)
		if !ok {
			log.Printf("var 'ip' has wrong type. expect IP addr")
			return
		}

		remediation := spoad.DataSet.CheckIP(&ip)
		hString, ok := mes.KV.Get("headers")
		if !ok {
			log.Printf("var 'headers' not found in message")
			return
		}
		headers, err := readHeaders(hString.(string))
		if err != nil {
			log.Printf("failed to parse headers: %v", err)
			return
		}
		host := spoad.cfg.Hosts.MatchFirstHost(headers.Get("Host"))
		if host == nil {
			log.Printf("host not found")
			return
		}
		if remediation > 0 {
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
					remediation = dataset.Ban // fallback to ban currently but we configure on host level
				}
			}
			req.Actions.SetVar(action.ScopeTransaction, "remediation", remediation)
		}

		// Check if remediation is allow || we invent a configuration option to check request against appsec
		var body string
		var method string
		var url string
		if method, ok := mes.KV.Get("method"); ok {
			if _, ok := method.(string); ok {
				method = strings.ToUpper(method.(string))
			}
		}
		if body, ok := mes.KV.Get("body"); ok {
			if _, ok := body.(string); ok {
				body = body.(string)
			}
		}
		if url, ok := mes.KV.Get("url"); ok {
			if _, ok := url.(string); ok {
				url = url.(string)
			}
		}
		request, err := http.NewRequest(method, url, strings.NewReader(body))
		if err != nil {
			log.Printf("failed to create request: %v", err)
			return
		}
		request.Header = headers
	}
}

func readHeaders(headers string) (http.Header, error) {
	h := http.Header{}
	hs := strings.Split(headers, "\r\n")

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
