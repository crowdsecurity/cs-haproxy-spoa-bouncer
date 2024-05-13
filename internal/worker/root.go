package worker

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	log "github.com/sirupsen/logrus"
)

type Worker struct {
	Name         string     `yaml:"name"`
	ListenAddr   string     `yaml:"listen_addr"`
	ListenSocket string     `yaml:"listen_socket"`
	LogLevel     *log.Level `yaml:"log_level"`
	Uid          int        `yaml:"-"`
	Gid          int        `yaml:"-"`
	Command      *exec.Cmd  `yaml:"-"`
}

func (w *Worker) Run() error {
	args := []string{
		"-worker",
	}
	if w.ListenAddr != "" {
		args = append(args, "-tcp", w.ListenAddr)
	}
	if w.ListenSocket != "" {
		args = append(args, "-unix", w.ListenSocket)
	}
	command := exec.Command(os.Args[0], args...)

	command.Env = []string{
		"WORKERNAME=" + w.Name,
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
	Workers    []*Worker       `yaml:"workers"`
	CreateChan chan *Worker    `yaml:"-"`
	Ctx        context.Context `yaml:"-"`
}

func NewManager(ctx context.Context) *Manager {
	return &Manager{
		CreateChan: make(chan *Worker),
		Workers:    make([]*Worker, 0),
		Ctx:        ctx,
	}
}

func (m *Manager) Run() {
	for {
		select {
		case w := <-m.CreateChan:
			m.AddWorker(w)
		case <-m.Ctx.Done():
			m.Stop()
			return
		}
	}
}

func (m *Manager) AddWorker(w *Worker) {
	go w.Run()
	m.Workers = append(m.Workers, w)
}

func (m *Manager) Stop() {
	for _, w := range m.Workers {
		w.Command.Process.Signal(os.Interrupt)
	}
}
