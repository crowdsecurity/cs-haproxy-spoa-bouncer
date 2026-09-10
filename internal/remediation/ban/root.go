package ban

import (
	"html"
	"net/url"

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
	contactURL := b.ContactUsURL
	if contactURL != "" {
		u, err := url.Parse(contactURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "mailto") {
			contactURL = ""
		}
	}
	_ = writer.SetString(encoding.VarScopeTransaction, "contact_us_url", html.EscapeString(contactURL))
}
