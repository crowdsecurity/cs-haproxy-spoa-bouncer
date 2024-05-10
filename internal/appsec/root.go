package appsec

import (
	"context"

	log "github.com/sirupsen/logrus"
)

type AppSec struct {
	AlwaysSend bool       `yaml:"always_send"`
	logger     *log.Entry `yaml:"-"`
}

func (a *AppSec) Init(logger *log.Entry, ctx context.Context) error {
	a.InitLogger(logger)
	return nil
}

func (a *AppSec) InitLogger(logger *log.Entry) {
	a.logger = logger.WithField("type", "appsec")
}
