package ban

import (
	"github.com/dropmorepackets/haproxy-go/pkg/encoding"
	log "github.com/sirupsen/logrus"
)

type Ban struct {
	ContactUsURL string     `yaml:"contact_us_url"`
	logger       *log.Entry `yaml:"-"`
}

func (b *Ban) Init(logger *log.Entry) error {
	b.InitLogger(logger)
	return nil
}

func (b *Ban) InitLogger(logger *log.Entry) {
	b.logger = logger.WithField("module", "ban")
}

func (b *Ban) InjectKeyValues(writer *encoding.ActionWriter) {
	_ = writer.SetString(encoding.VarScopeTransaction, "contact_us_url", b.ContactUsURL)
}
