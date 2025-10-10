package admin

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/crowdsecurity/crowdsec-spoa/internal/geo"
	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation/captcha"
	"github.com/crowdsecurity/crowdsec-spoa/internal/session"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/host"
	"github.com/crowdsecurity/go-cs-lib/ptr"
	log "github.com/sirupsen/logrus"
)

func (s *Server) handleAdminGetIP(args []string) *APIResponse {
	if resp := argsCheckResponse(args, 1, 1); resp != nil {
		return resp
	}

	log.Infof("Checking IP %s", args[0])

	r, _, err := s.dataset.CheckIP(args[0])
	if err != nil {
		return NewAPIError(ErrCodeInvalidIP, "IP check failed", err.Error())
	}

	return NewAPIResponse(r.String())
}

func (s *Server) handleAdminGetCN(args []string) *APIResponse {
	if resp := argsCheckResponse(args, 1, 2); resp != nil {
		return resp
	}
	if args[0] == "" {
		return NewAPIError(ErrCodeInvalidArgument, "Country code cannot be empty", "")
	}
	r, _ := s.dataset.CheckCN(args[0])

	return NewAPIResponse(r.String())
}

func (s *Server) handleAdminGetGeoIso(args []string) *APIResponse {
	if resp := argsCheckResponse(args, 1, 1); resp != nil {
		return resp
	}

	if !s.geoDatabase.IsValid() {
		return NewAPIError(ErrCodeGeoDBUnavailable, "GeoIP database not available", "")
	}

	log.Tracef("Checking geo:iso IP %s", args[0])
	val := net.ParseIP(args[0])
	if val == nil {
		return NewAPIError(ErrCodeInvalidIP, "Invalid IP address", args[0])
	}

	record, err := s.geoDatabase.GetCity(&val)
	if err != nil && !errors.Is(err, geo.ErrNotValidConfig) {
		return NewAPIError(ErrCodeDatabaseError, "GeoIP lookup failed", err.Error())
	}

	if record == nil {
		return NewAPIResponse("")
	}

	return NewAPIResponse(geo.GetIsoCodeFromRecord(record))
}

func (s *Server) handleAdminGetHosts(args []string) *APIResponse {
	// Admin can list all hosts if no args provided
	if len(args) == 0 {
		return NewAPIResponse(s.hostManager.String())
	}

	if resp := argsCheckResponse(args, 1, 1); resp != nil {
		return resp
	}

	h := s.hostManager.MatchFirstHost(args[0])
	if h == nil {
		return NewAPIError(ErrCodeHostNotFound, "Host not found", args[0])
	}

	// return a serializable host response to avoid gob encoding issues
	hostResponse := &HostResponse{
		Host:                       h.Host,
		CaptchaSiteKey:             h.Captcha.SiteKey,
		CaptchaProvider:            h.Captcha.Provider,
		CaptchaFallbackRemediation: h.Captcha.FallbackRemediation,
		BanContactUsURL:            h.Ban.ContactUsURL,
		AppSecAlwaysSend:           h.AppSec.AlwaysSend,
	}
	return NewAPIResponse(hostResponse)
}

func (s *Server) handleAdminValHostCookie(args []string) *APIResponse {
	if resp := argsCheckResponse(args, 2, 2); resp != nil {
		return resp
	}

	h := s.hostManager.MatchFirstHost(args[0])
	if h == nil {
		return NewAPIError(ErrCodeHostNotFound, "Host not found", args[0])
	}

	uuid, err := h.Captcha.CookieGenerator.ValidateCookie(args[1])
	if err != nil {
		return NewAPIError(ErrCodeInvalidCookie, "Cookie validation failed", err.Error())
	}

	sess := h.Captcha.Sessions.GetSession(uuid)
	if sess == nil {
		return NewAPIError(ErrCodeSessionNotFound, "Session not found", uuid)
	}

	return NewAPIResponse(uuid)
}

func (s *Server) handleAdminValHostCaptcha(ctx context.Context, args []string) *APIResponse {
	if resp := argsCheckResponse(args, 3, 3); resp != nil {
		return resp
	}

	h := s.hostManager.MatchFirstHost(args[0])
	if h == nil {
		return NewAPIError(ErrCodeHostNotFound, "Host not found", args[0])
	}

	isValid, err := h.Captcha.Validate(ctx, args[1], args[2])
	if err != nil {
		return NewAPIError(ErrCodeCaptchaValidationFailed, "Captcha validation failed", err.Error())
	}
	return NewAPIResponse(isValid)
}

func (s *Server) handleAdminDelHostSession(args []string) *APIResponse {
	if resp := argsCheckResponse(args, 3, 3); resp != nil {
		return resp
	}

	h := s.hostManager.MatchFirstHost(args[0])
	if h == nil {
		return NewAPIError(ErrCodeHostNotFound, "Host not found", args[0])
	}

	ses := h.Captcha.Sessions.GetSession(args[1])
	if ses == nil {
		return NewAPIError(ErrCodeSessionNotFound, "Session not found", args[1])
	}

	ses.Delete(args[2])
	return NewAPIResponse(true)
}

func (s *Server) handleAdminDelHosts(args []string) *APIResponse {
	if resp := argsCheckResponse(args, 1, 1); resp != nil {
		return resp
	}

	h := s.hostManager.MatchFirstHost(args[0])
	if h == nil {
		return NewAPIError(ErrCodeHostNotFound, "Host not found", args[0])
	}

	s.hostManager.Chan <- host.HostOp{
		Host: h,
		Op:   host.OpRemove,
	}

	return NewAPIResponse(true)
}

func (s *Server) handleAdminSetHostSession(args []string) *APIResponse {
	if resp := argsCheckResponse(args, 4, 4); resp != nil {
		return resp
	}

	h := s.hostManager.MatchFirstHost(args[0])
	if h == nil {
		return NewAPIError(ErrCodeHostNotFound, "Host not found", args[0])
	}

	ses := h.Captcha.Sessions.GetSession(args[1])
	if ses == nil {
		return NewAPIError(ErrCodeSessionNotFound, "Session not found", args[1])
	}

	ses.Set(args[2], args[3])
	return NewAPIResponse(true)
}

func (s *Server) handleAdminGetHostSession(args []string) *APIResponse {
	if resp := argsCheckResponse(args, 3, 3); resp != nil {
		return resp
	}

	h := s.hostManager.MatchFirstHost(args[0])
	if h == nil {
		return NewAPIError(ErrCodeHostNotFound, "Host not found", args[0])
	}

	ses := h.Captcha.Sessions.GetSession(args[1])
	if ses == nil {
		return NewAPIError(ErrCodeSessionNotFound, "Session not found", args[1])
	}

	val := ses.Get(args[2])
	if val == nil {
		val = ""
	}

	return NewAPIResponse(val)
}

func (s *Server) handleAdminGetHostCookie(args []string) *APIResponse {
	if resp := argsCheckResponse(args, 2, 2); resp != nil {
		return resp
	}

	h := s.hostManager.MatchFirstHost(args[0])
	if h == nil {
		return NewAPIError(ErrCodeHostNotFound, "Host not found", args[0])
	}

	ses, err := h.Captcha.Sessions.NewRandomSession()
	if err != nil {
		return NewAPIError(ErrCodeServerError, "Failed to create session", err.Error())
	}

	cookie, err := h.Captcha.CookieGenerator.GenerateCookie(ses, ptr.Of(args[1] == "true"))
	if err != nil {
		return NewAPIError(ErrCodeServerError, "Failed to generate cookie", err.Error())
	}

	ses.Set(session.CaptchaStatus, captcha.Pending)
	return NewAPIResponse(cookie)
}

// argsCheckResponse validates argument count
func argsCheckResponse(args []string, minArgs, maxArgs int) *APIResponse {
	if len(args) < minArgs {
		return NewAPIError(ErrCodeInvalidArgument, fmt.Sprintf("Not enough arguments, expected at least %d", minArgs), "")
	}
	if len(args) > maxArgs {
		return NewAPIError(ErrCodeInvalidArgument, fmt.Sprintf("Too many arguments, expected at most %d", maxArgs), "")
	}
	return nil
}
