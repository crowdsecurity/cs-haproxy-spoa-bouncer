package template

import (
	"fmt"
	"html/template"
	"io"
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

// Renderer handles template rendering using Go's native html/template package
// html/template provides automatic HTML escaping to prevent XSS attacks
type Renderer struct {
	tmpl *template.Template
}

// NewRenderer creates a new template renderer with the given template content
func NewRenderer(name, templateContent string) (*Renderer, error) {
	if name == "" {
		name = "template"
	}
	tmpl, err := template.New(name).Parse(templateContent)
	if err != nil {
		return nil, fmt.Errorf("failed to parse template %q: %w", name, err)
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
