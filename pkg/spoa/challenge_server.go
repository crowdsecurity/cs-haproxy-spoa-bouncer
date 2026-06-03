package spoa

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec-spoa/internal/appsec"
	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
	log "github.com/sirupsen/logrus"
)

const (
	// ChallengeRealIPHeader is the header HAProxy adds to identify the real
	// client IP when routing a challenge request to the challenge server.
	ChallengeRealIPHeader = "X-Crowdsec-Real-Ip"
)

// ChallengeServer is a plain HTTP server that HAProxy routes to when the SPOE
// agent returns remediation=challenge. It re-sends the request to the AppSec
// engine, unwraps the JSON response, and writes the challenge page (HTML, JS,
// or submit JSON) directly back to the client.
//
// This avoids the 64 KB SPOE frame-size limit: the large challenge body never
// passes through the SPOE protocol; it travels through a normal HTTP connection
// between HAProxy, this server, and the AppSec engine.
type ChallengeServer struct {
	appSec *appsec.AppSec
	listen string
	logger *log.Entry
}

func newChallengeServer(appSec *appsec.AppSec, addr string, logger *log.Entry) *ChallengeServer {
	return &ChallengeServer{
		appSec: appSec,
		listen: addr,
		logger: logger.WithField("component", "challenge_server"),
	}
}

func (cs *ChallengeServer) Serve(ctx context.Context) error {
	srv := &http.Server{
		Addr:         cs.listen,
		Handler:      cs,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	go func() {
		<-ctx.Done()
		_ = srv.Shutdown(context.Background())
	}()

	cs.logger.Infof("Challenge HTTP server listening on %s", cs.listen)

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("challenge server: %w", err)
	}

	return nil
}

// ServeHTTP handles a request forwarded by HAProxy when remediation=challenge.
// It builds an AppSec request from the incoming request, calls the AppSec
// engine, and writes the challenge response (body + headers + cookies) back.
func (cs *ChallengeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	clientIP := r.Header.Get(ChallengeRealIPHeader)
	if clientIP == "" {
		// Fall back to the connection's remote address (strips port)
		if idx := strings.LastIndex(r.RemoteAddr, ":"); idx != -1 {
			clientIP = r.RemoteAddr[:idx]
		} else {
			clientIP = r.RemoteAddr
		}
	}

	// Read the request body (needed for the submit path POST)
	var body []byte
	if r.Body != nil {
		var err error
		body, err = io.ReadAll(io.LimitReader(r.Body, 10<<20)) // 10 MB limit
		if err != nil {
			cs.logger.WithError(err).Warn("challenge server: failed to read request body")
		}
	}

	// Reconstruct the URL for the AppSec header
	reqURL := r.URL.RequestURI()

	// Forward the original client headers to AppSec (minus hop-by-hop and our own headers)
	headers := r.Header.Clone()
	headers.Del(ChallengeRealIPHeader)
	headers.Del("X-Forwarded-For")

	appSecReq := &appsec.AppSecRequest{
		Host:      r.Host,
		Method:    r.Method,
		URL:       reqURL,
		RemoteIP:  clientIP,
		UserAgent: r.UserAgent(),
		Headers:   headers,
		Body:      body,
	}

	appSecCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	rem, challengeData, err := cs.appSec.ValidateRequest(appSecCtx, appSecReq)
	if err != nil {
		cs.logger.WithError(err).Error("challenge server: AppSec request failed")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if rem != remediation.Challenge || challengeData == nil {
		// AppSec didn't return a challenge (e.g. allow after valid cookie).
		// Return 200 with an empty body; HAProxy will handle the pass-through.
		w.WriteHeader(http.StatusOK)
		return
	}

	// Write response headers from AppSec
	if challengeData.ContentType != "" {
		w.Header().Set("Content-Type", challengeData.ContentType)
	}
	if challengeData.CSP != "" {
		w.Header().Set("Content-Security-Policy", challengeData.CSP)
	}
	if challengeData.CacheControl != "" {
		w.Header().Set("Cache-Control", challengeData.CacheControl)
	}
	for _, cookie := range challengeData.Cookies {
		w.Header().Add("Set-Cookie", cookie)
	}

	status := challengeData.StatusCode
	if status <= 0 {
		status = http.StatusOK
	}

	w.WriteHeader(status)
	if challengeData.Body != "" {
		_, _ = io.Copy(w, bytes.NewBufferString(challengeData.Body))
	}
}
