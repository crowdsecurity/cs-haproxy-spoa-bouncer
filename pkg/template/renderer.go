package template

import (
	"fmt"
	"io"
	"text/template"
)

// TemplateData holds the data for template rendering
type TemplateData struct {
	// Ban template fields
	ContactUsURL string

	// Captcha template fields
	CaptchaSiteKey     string
	CaptchaFrontendKey string
	CaptchaFrontendJS  string
}

// Renderer handles template rendering using Go's native text/template package
type Renderer struct {
	tmpl *template.Template
}

// NewRenderer creates a new template renderer with the given template content
func NewRenderer(templateContent string) (*Renderer, error) {
	tmpl, err := template.New("template").Parse(templateContent)
	if err != nil {
		return nil, fmt.Errorf("failed to parse template: %w", err)
	}

	return &Renderer{
		tmpl: tmpl,
	}, nil
}

// Render renders the template with the given data directly to the provided io.Writer
func (r *Renderer) Render(w io.Writer, data TemplateData) error {
	if err := r.tmpl.Execute(w, data); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	return nil
}
