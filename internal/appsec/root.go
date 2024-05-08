package appsec

import (
	"context"

	"github.com/crowdsecurity/crowdsec-spoa/internal/session"
	log "github.com/sirupsen/logrus"
)

type AppSec struct {
	AlwaysSend    bool             `yaml:"always_send"`
	logger        *log.Entry       `yaml:"-"`
	GracePeriod   int              `yaml:"grace_period"`
	GraceSessions session.Sessions `yaml:"-"`
}

func (a *AppSec) Init(logger *log.Entry, ctx context.Context) error {
	a.InitLogger(logger)
	go a.GraceSessions.GarbageCollect(ctx)
	return nil
}

func (a *AppSec) InitLogger(logger *log.Entry) {
	a.logger = logger.WithField("type", "appsec")
}
