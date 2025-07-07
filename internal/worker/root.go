package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/crowdsecurity/crowdsec-spoa/pkg/server"
	log "github.com/sirupsen/logrus"
)

type Worker struct {
	Name       string     `yaml:"name" json:"name"`
	LogLevel   *log.Level `yaml:"log_level" json:"log_level"`
	TcpAddr    string     `yaml:"listen_addr" json:"listen_addr"`
	UnixAddr   string     `yaml:"listen_socket" json:"listen_socket"`
	Config     string     `yaml:"-"  json:"-"`
	UID        int        `yaml:"-" json:"-"` // Set by the worker manager
	GID        int        `yaml:"-" json:"-"` // Set by the worker manager
	Command    *exec.Cmd  `yaml:"-" json:"-"`
	SocketPath string     `yaml:"-" json:"-"` // Set by combining the socket dir and the worker name
}

func (w *Worker) Run(socket string) error {
	args := []string{}

	config, err := json.Marshal(*w)
	if err != nil {
		return fmt.Errorf("failed to marshal appsec config: %w", err)
	}

	args = append(args, "--worker-config", string(config))
	command := exec.Command(os.Args[0], args...)

	command.Env = []string{
		"WORKERNAME=" + w.Name,
		"WORKERSOCKET=" + socket,
	}

	if w.LogLevel != nil {
		command.Env = append(command.Env, "LOG_LEVEL="+w.LogLevel.String())
	}
	log.Infof("Starting worker %s with cmd %s %v", w.Name, os.Args[0], strings.Join(args, " "))

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
		log.Infof("Worker %s exited with error: %s", w.Name, err)
		w.Command = nil
		return fmt.Errorf("worker %s exited with error: %w", w.Name, err)
	}

	log.Infof("Worker %s exited", w.Name)
	return nil
}

type Manager struct {
	Workers    []*Worker      `yaml:"-"`
	RetChan    chan error     `yaml:"-"`
	CreateChan chan *Worker   `yaml:"-"`
	Server     *server.Server `yaml:"-"`
	WorkerUID  int            `yaml:"-"`
	WorkerGID  int            `yaml:"-"`
}

func NewManager(s *server.Server, uid, gid int) *Manager {
	return &Manager{
		CreateChan: make(chan *Worker),
		RetChan:    make(chan error),
		Workers:    make([]*Worker, 0),
		Server:     s,
		WorkerUID:  uid,
		WorkerGID:  gid,
	}
}

func (m *Manager) Run(ctx context.Context) error {
	for {
		select {
		case w := <-m.CreateChan:
			m.AddWorker(w)
		case <-ctx.Done():
			m.Stop()
			log.Info("Worker manager returned due to context cancellation")
			return nil
		case err := <-m.RetChan:
			if err != nil {
				log.Errorf("Worker manager received error: %s", err)
				return err
			}
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
			m.RetChan <- fmt.Errorf("worker %s failed: %w", w.Name, err)
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
