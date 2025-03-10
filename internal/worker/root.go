package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/crowdsecurity/crowdsec-spoa/internal/appsec"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/server"
	log "github.com/sirupsen/logrus"
)

type Worker struct {
	Name         string               `yaml:"name"`
	LogLevel     *log.Level           `yaml:"log_level"`
	ListenAddr   string               `yaml:"listen_addr"`
	ListenSocket string               `yaml:"listen_socket"`
	AppSecConfig *appsec.AppsecConfig `yaml:"appsec_config"`
	Uid          int                  `yaml:"-"` // Set by the worker manager
	Gid          int                  `yaml:"-"` // Set by the worker manager
	Command      *exec.Cmd            `yaml:"-"`
	SocketPath   string               `yaml:"-"` // Set by combining the socket dir and the worker name
}

func (w *Worker) Run(socket string) error {
	args := []string{
		"-worker",
	}

	config, err := json.Marshal(*w)
	if err != nil {
		return fmt.Errorf("failed to marshal appsec config: %w", err)
	}

	args = append(args, "-config", string(config))
	command := exec.Command(os.Args[0], args...)

	command.Env = []string{
		"WORKERNAME=" + w.Name,
		"WORKERSOCKET=" + socket,
	}

	if w.LogLevel != nil {
		command.Env = append(command.Env, "LOG_LEVEL="+w.LogLevel.String())
	}

	command.SysProcAttr = &syscall.SysProcAttr{}
	command.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(w.Uid), Gid: uint32(w.Gid)}
	// !TODO worker should have there own log files
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	// !TODO worker should have there own log files
	w.Command = command
	if err := command.Run(); err != nil {
		return fmt.Errorf("failed to start worker: %w", err)
	}
	return nil
}

type Manager struct {
	Workers    []*Worker           `yaml:"-"`
	CreateChan chan *Worker        `yaml:"-"`
	Ctx        context.Context     `yaml:"-"`
	Cancel     *context.CancelFunc `yaml:"-"`
	Server     *server.Server      `yaml:"-"`
	WorkerUid  int                 `yaml:"-"`
	WorkerGid  int                 `yaml:"-"`
}

func NewManager(ctx context.Context, cancel *context.CancelFunc, s *server.Server, uid, gid int) *Manager {
	return &Manager{
		CreateChan: make(chan *Worker),
		Workers:    make([]*Worker, 0),
		Ctx:        ctx,
		Cancel:     cancel,
		Server:     s,
		WorkerUid:  uid,
		WorkerGid:  gid,
	}
}

func (m *Manager) Run() error {
	for {
		select {
		case w := <-m.CreateChan:
			m.AddWorker(w)
		case <-m.Ctx.Done():
			m.Stop()
			return nil
		}
	}
}

func (m *Manager) AddWorker(w *Worker) {
	w.Uid = m.WorkerUid
	w.Gid = m.WorkerGid
	socketString, err := m.Server.NewWorkerListener(w.Name, w.Gid)
	if err != nil {
		log.Errorf("failed to create worker listener: %s", err)
		return
	}
	go func() {
		err := w.Run(socketString)
		if err != nil {
			log.Errorf("worker failed with: %s", err)
		}
		defer (*m.Cancel)()
	}()
	m.Workers = append(m.Workers, w)
}

func (m *Manager) Stop() {
	for _, w := range m.Workers {
		w.Command.Process.Signal(os.Interrupt)
	}
}
