package spoa

import (
	"context"
	"fmt"
	"net"
	"os"
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
}

func New(cfg *cfg.BouncerConfig, dataset *dataset.DataSet) (*Spoa, error) {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Spoa{
		DataSet:     dataset,
		HAWaitGroup: &sync.WaitGroup{},
		ctx:         ctx,
		cancel:      cancel,
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

		blocked := "allow"
		if remediation := spoad.DataSet.CheckIP(&ip); remediation > 0 {
			blocked = remediation.String()
		}

		log.Printf("IP: %s, send score '%s'", ip.String(), blocked)

		req.Actions.SetVar(action.ScopeTransaction, "ip_score", blocked)
	}
}
