package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/crowdsecurity/crowdsec-spoa/pkg/server"
	log "github.com/sirupsen/logrus"
)

type Worker struct {
	Name     string     `yaml:"name" json:"name"`
	Config   string     `yaml:"config"  json:"config"`
	LogLevel *log.Level `yaml:"log_level" json:"log_level"`

	UID        int       `yaml:"-" json:"-"` // Set by the worker manager
	GID        int       `yaml:"-" json:"-"` // Set by the worker manager
	Command    *exec.Cmd `yaml:"-" json:"-"`
	SocketPath string    `yaml:"-" json:"-"` // Set by combining the socket dir and the worker name
}

type WorkerConfig struct {
	ListenAddr   string `yaml:"listen_addr"`
	ListenSocket string `yaml:"listen_socket"`
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
	log.Infof("Starting worker %s with cmd %s %v", w.Name, os.Args[0], args)

	command.SysProcAttr = &syscall.SysProcAttr{}
	command.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(w.UID), Gid: uint32(w.GID)}
	//Needed to allow to run the bouncer as non-root
	command.SysProcAttr.Credential.NoSetGroups = true

	// !TODO worker should have there own log files
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	// !TODO worker should have there own log files
	w.Command = command

	if err := command.Run(); err != nil {
		log.Errorf("worker %s exited with error: %s", w.Name, err)
		w.Command = nil
	}

	log.Infof("Worker %s exited", w.Name)
	return nil
}

type Manager struct {
	Workers    []*Worker       `yaml:"-"`
	CreateChan chan *Worker    `yaml:"-"`
	Ctx        context.Context `yaml:"-"`
	Server     *server.Server  `yaml:"-"`
	WorkerUID  int             `yaml:"-"`
	WorkerGID  int             `yaml:"-"`
}

func NewManager(ctx context.Context, s *server.Server, uid, gid int) *Manager {
	return &Manager{
		CreateChan: make(chan *Worker),
		Workers:    make([]*Worker, 0),
		Ctx:        ctx,
		Server:     s,
		WorkerUID:  uid,
		WorkerGID:  gid,
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
	w.UID = m.WorkerUID
	w.GID = m.WorkerGID
	socketString, err := m.Server.NewWorkerListener(w.Name, w.GID)
	if err != nil {
		log.Errorf("failed to create worker listener: %s", err)
		return
	}

	go func() {
		err := w.Run(socketString)
		if err != nil {
			m.Stop()
		}
	}()

	m.Workers = append(m.Workers, w)
}

func (m *Manager) Stop() {
	for _, w := range m.Workers {
		if w.Command != nil {
			err := w.Command.Process.Signal(os.Interrupt)
			if err != nil {
				log.Errorf("failed to stop worker %s: %s", w.Name, err)
			} else {
				log.Infof("stopped worker %s", w.Name)
			}
		}
	}
}
