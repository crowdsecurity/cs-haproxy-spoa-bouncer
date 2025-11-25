package httptemplate

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation/captcha"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/cfg"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/host"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/template"
	log "github.com/sirupsen/logrus"
)

// Server represents the HTTP template server
type Server struct {
	config          *cfg.HTTPTemplateServerConfig
	logger          *log.Entry
	server          *http.Server
	banRenderer     *template.Renderer
	captchaRenderer *template.Renderer
	hostManager     *host.Manager
}

// NewServer creates a new HTTP template server
func NewServer(config *cfg.HTTPTemplateServerConfig, hostManager *host.Manager, logger *log.Entry) (*Server, error) {
	if config == nil {
		return nil, fmt.Errorf("http template server config is nil")
	}

	if !config.Enabled {
		return nil, fmt.Errorf("http template server is not enabled")
	}

	s := &Server{
		config:      config,
		logger:      logger.WithField("component", "http_template_server"),
		hostManager: hostManager,
	}

	// Load ban template
	banTemplatePath := config.BanTemplate
	if banTemplatePath == "" {
		banTemplatePath = "/var/lib/crowdsec-haproxy-spoa-bouncer/html/ban.tmpl"
	}
	var err error
	s.banRenderer, err = s.loadTemplate("ban", banTemplatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load ban template: %w", err)
	}

	// Load captcha template
	captchaTemplatePath := config.CaptchaTemplate
	if captchaTemplatePath == "" {
		captchaTemplatePath = "/var/lib/crowdsec-haproxy-spoa-bouncer/html/captcha.tmpl"
	}
	s.captchaRenderer, err = s.loadTemplate("captcha", captchaTemplatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load captcha template: %w", err)
	}

	// Setup HTTP routes
	mux := http.NewServeMux()
	// Catch-all route that handles both ban and captcha based on header
	// This allows HAProxy to route to any path without needing to set-path
	mux.HandleFunc("/", s.handleRender)

	// Create HTTP server
	listenAddr := net.JoinHostPort(config.ListenAddress, config.ListenPort)
	s.server = &http.Server{
		Addr:         listenAddr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return s, nil
}

// loadTemplate loads a template from a file path and returns a renderer
func (s *Server) loadTemplate(name, path string) (*template.Renderer, error) {
	// Use the provided path directly - it should be absolute or configured by the user
	templatePath := path
	if !filepath.IsAbs(path) {
		// If relative path provided, make it relative to the standard template directory
		const templateDir = "/var/lib/crowdsec-haproxy-spoa-bouncer/html"
		templatePath = filepath.Join(templateDir, path)
	}

	content, err := os.ReadFile(templatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read template file %s: %w", templatePath, err)
	}

	renderer, err := template.NewRenderer(name, string(content))
	if err != nil {
		return nil, fmt.Errorf("failed to create renderer: %w", err)
	}

	s.logger.WithField("template", name).WithField("path", templatePath).Info("loaded template")
	return renderer, nil
}

// handleRender is the main endpoint that handles both ban and captcha rendering
// It reads the remediation type from X-Crowdsec-Remediation header (set by HAProxy)
// It looks up host configuration using the Host header to get ban/captcha settings
// Security: HAProxy must delete any user-provided headers and set them from transaction variables
func (s *Server) handleRender(w http.ResponseWriter, r *http.Request) {
	// Get remediation from header (set by HAProxy from transaction variables)
	// HAProxy configuration should use del-header before set-header to ensure user values are ignored
	remediation := r.Header.Get("X-Crowdsec-Remediation")
	if remediation == "" {
		s.logger.Warn("X-Crowdsec-Remediation header not found, returning 400")
		http.Error(w, "Bad Request: Missing X-Crowdsec-Remediation header", http.StatusBadRequest)
		return
	}

	// Get hostname from Host header (HAProxy forwards the original Host header)
	hostname := r.Host
	if hostname == "" {
		s.logger.Warn("Host header not found, cannot match host configuration")
		http.Error(w, "Bad Request: Missing Host header", http.StatusBadRequest)
		return
	}

	// Look up host configuration
	matchedHost := s.hostManager.MatchFirstHost(hostname)
	if matchedHost == nil {
		s.logger.WithField("hostname", hostname).Warn("no matching host configuration found")
		// If captcha and no host, we can't proceed (same logic as SPOA)
		if remediation == "captcha" {
			s.logger.Warn("captcha remediation but no host found, cannot render captcha")
			http.Error(w, "Internal Server Error: No host configuration for captcha", http.StatusInternalServerError)
			return
		}
		// For ban, we can still render with empty data
		matchedHost = nil
	}

	// Build template data from host configuration
	data := s.buildTemplateData(remediation, matchedHost)

	// Log for security monitoring
	s.logger.WithFields(log.Fields{
		"remediation": remediation,
		"hostname":    hostname,
		"remote_addr": r.RemoteAddr,
		"host_found":  matchedHost != nil,
	}).Debug("handling render request")

	var renderer *template.Renderer
	var statusCode int

	switch remediation {
	case "ban":
		renderer = s.banRenderer
		statusCode = http.StatusForbidden
	case "captcha":
		// matchedHost nil check already done above at line 137-140
		renderer = s.captchaRenderer
		statusCode = http.StatusOK
	case "allow":
		// Allow should be handled by HAProxy redirect, but if it reaches here, return 200
		s.logger.Warn("handleRender called for 'allow' remediation - this should be handled by HAProxy redirect")
		http.Error(w, "Bad Request: Allow remediation should use HAProxy redirect", http.StatusBadRequest)
		return
	default:
		s.logger.WithField("remediation", remediation).Warn("unknown remediation type")
		http.Error(w, fmt.Sprintf("Bad Request: Unknown remediation type: %s", remediation), http.StatusBadRequest)
		return
	}

	// Set headers
	w.Header().Set("Cache-Control", "no-cache, no-store")

	// For HEAD requests or .ico file requests, always return 403 for ban and captcha remediations
	if r.Method == http.MethodHead || strings.HasSuffix(strings.ToLower(r.URL.Path), ".ico") {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// Check if client accepts HTML
	if !s.acceptsHTML(r) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		if _, err := w.Write([]byte("Forbidden")); err != nil {
			s.logger.WithError(err).Error("failed to write response")
		}
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(statusCode)

	// Render template directly to response writer
	if err := renderer.Render(w, data); err != nil {
		s.logger.WithError(err).Error("failed to render template")
		// Headers already sent, can't send error response
		return
	}
}

// buildTemplateData builds template data from host configuration
// If matchedHost is nil, returns empty data (for ban without host config)
func (s *Server) buildTemplateData(remediation string, matchedHost *host.Host) template.TemplateData {
	data := template.TemplateData{}

	if matchedHost == nil {
		// No host configuration - return empty data
		// This is acceptable for ban remediation but not for captcha
		return data
	}

	// Extract ban configuration
	data.ContactUsURL = matchedHost.Ban.ContactUsURL

	// Extract captcha configuration
	if remediation == "captcha" && matchedHost.Captcha.Provider != "" {
		data.CaptchaSiteKey = matchedHost.Captcha.SiteKey
		data.CaptchaFrontendKey, data.CaptchaFrontendJS = captcha.GetProviderInfo(matchedHost.Captcha.Provider)
	}

	return data
}

// acceptsHTML checks if the request accepts HTML content
func (s *Server) acceptsHTML(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	if accept == "" {
		return true // Default to HTML if no Accept header
	}
	return strings.Contains(accept, "text/html") || strings.Contains(accept, "*/*")
}

// Serve starts the HTTP server
func (s *Server) Serve(ctx context.Context) error {
	listenAddr := s.server.Addr
	protocol := "HTTP"
	if s.config.TLS.Enabled {
		protocol = "HTTPS"
	}

	s.logger.WithFields(log.Fields{
		"address":  listenAddr,
		"protocol": protocol,
	}).Info("starting HTTP template server")

	serverError := make(chan error, 1)

	go func() {
		var err error
		if s.config.TLS.Enabled {
			err = s.server.ListenAndServeTLS(s.config.TLS.CertFile, s.config.TLS.KeyFile)
		} else {
			err = s.server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			serverError <- err
		}
	}()

	select {
	case err := <-serverError:
		return fmt.Errorf("HTTP template server error: %w", err)
	case <-ctx.Done():
		return nil
	}
}

// Shutdown gracefully shuts down the HTTP server
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("shutting down HTTP template server")
	return s.server.Shutdown(ctx)
}
