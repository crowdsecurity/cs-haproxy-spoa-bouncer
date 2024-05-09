package ban

import (
	"github.com/negasus/haproxy-spoe-go/action"
	log "github.com/sirupsen/logrus"
)

type Ban struct {
	ContactUsUrl string     `yaml:"contact_us_url"`
	logger       *log.Entry `yaml:"-"`
}

func (b *Ban) Init(logger *log.Entry) error {
	b.InitLogger(logger)
	return nil
}

func (b *Ban) InitLogger(logger *log.Entry) {
	b.logger = logger.WithField("module", "ban")
}

func (b *Ban) InjectKeyValues(actions *action.Actions) {
	actions.SetVar(action.ScopeTransaction, "contact_us_url", b.ContactUsUrl)
}
