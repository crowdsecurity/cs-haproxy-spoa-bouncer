package ban

import (
	"os"
	"text/template"

	log "github.com/sirupsen/logrus"
)

type Ban struct {
	TemplatePath string             `yaml:"template_path"`
	ContactUsUrl string             `yaml:"contact_us_url"`
	template     *template.Template `yaml:"-"`
	logger       *log.Entry         `yaml:"-"`
}

func (b *Ban) Init(logger *log.Entry) error {
	b.InitLogger(logger)
	return nil
}

func (b *Ban) InitLogger(logger *log.Entry) {
	b.logger = logger.WithField("type", "ban")
}

func (b *Ban) InitTemplate() error {

	b.logger.Debug("Initializing template")
	// check if user provided a custom template
	if b.TemplatePath != "" {
		byt, err := os.ReadFile(b.TemplatePath)
		if err != nil {
			return err
		}
		b.template, err = template.New("ban").Parse(string(byt))
		if err != nil {
			return err
		}
	}

	// if template is nil the user did not provide a template
	if b.template == nil {
		var err error
		b.template, err = template.New("ban").Parse(DefaultBanTemplate)
		if err != nil {
			return err
		}
	}

	return nil
}

func (b *Ban) Render(wr *os.File) error {
	if b.template == nil {
		b.logger.Debug("No template to render")
		return nil
	}

	b.logger.Debugf("Rendering ban page to %s", wr.Name())

	return b.template.ExecuteTemplate(wr, "ban", map[string]string{
		"ContactUsUrl": b.ContactUsUrl,
	})
}
