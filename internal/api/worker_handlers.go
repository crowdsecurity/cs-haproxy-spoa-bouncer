package api

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"

	"github.com/crowdsecurity/crowdsec-spoa/internal/api/messages"
	"github.com/crowdsecurity/crowdsec-spoa/internal/api/types"
	"github.com/crowdsecurity/crowdsec-spoa/internal/geo"
	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation/captcha"
	"github.com/crowdsecurity/crowdsec-spoa/internal/session"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/metrics"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/server"
	"github.com/crowdsecurity/go-cs-lib/ptr"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

// handleWorkerConnectionEncoded handles worker connections using encoded messages
func (a *API) handleWorkerConnectionEncoded(ctx context.Context, sc server.SocketConn) {
	defer func() {
		err := sc.Conn.Close()
		if err != nil {
			log.Error("Error closing connection:", err)
		}
	}()

	for {
		var req messages.WorkerRequest
		if err := sc.Decoder.Decode(&req); err != nil {
			if errors.Is(err, io.EOF) {
				// Client closed the connection gracefully
				break
			}
			log.Error("Decode error:", err)
			continue
		}

		log.Debugf("Received encoded command: %s", req.Command)

		response := a.handleTypedRequest(ctx, req)

		log.Tracef("Command %s returned %+v", req.Command, response)

		// Send the response back
		if err := sc.Encoder.Encode(response); err != nil {
			log.Error("Error encoding response:", err)
		}
	}
}

// handleTypedRequest processes typed requests based on the command
func (a *API) handleTypedRequest(ctx context.Context, req messages.WorkerRequest) *types.APIResponse {
	switch req.Command {
	case messages.GetIP:
		data, ok := req.Data.(messages.IPRequest)
		if !ok {
			return types.NewAPIError(types.ErrCodeInvalidRequest, "Invalid request data for GetIP", "")
		}
		return a.handleGetIP(data)

	case messages.GetCN:
		data, ok := req.Data.(messages.CNRequest)
		if !ok {
			return types.NewAPIError(types.ErrCodeInvalidRequest, "Invalid request data for GetCN", "")
		}
		return a.handleGetCN(data)

	case messages.GetGeoIso:
		data, ok := req.Data.(messages.GeoRequest)
		if !ok {
			return types.NewAPIError(types.ErrCodeInvalidRequest, "Invalid request data for GetGeoIso", "")
		}
		return a.handleGetGeoIso(data)

	case messages.GetHosts:
		data, ok := req.Data.(messages.HostsRequest)
		if !ok {
			return types.NewAPIError(types.ErrCodeInvalidRequest, "Invalid request data for GetHosts", "")
		}
		return a.handleGetHosts(data)

	case messages.GetHostCookie:
		data, ok := req.Data.(messages.HostCookieRequest)
		if !ok {
			return types.NewAPIError(types.ErrCodeInvalidRequest, "Invalid request data for GetHostCookie", "")
		}
		return a.handleGetHostCookie(data)

	case messages.GetHostSession:
		data, ok := req.Data.(messages.HostSessionRequest)
		if !ok {
			return types.NewAPIError(types.ErrCodeInvalidRequest, "Invalid request data for GetHostSession", "")
		}
		return a.handleGetHostSession(data)

	case messages.ValHostCookie:
		data, ok := req.Data.(messages.HostCookieValidationRequest)
		if !ok {
			return types.NewAPIError(types.ErrCodeInvalidRequest, "Invalid request data for ValHostCookie", "")
		}
		return a.handleValHostCookie(data)

	case messages.ValHostCaptcha:
		data, ok := req.Data.(messages.HostCaptchaValidationRequest)
		if !ok {
			return types.NewAPIError(types.ErrCodeInvalidRequest, "Invalid request data for ValHostCaptcha", "")
		}
		return a.handleValHostCaptcha(ctx, data)

	case messages.SetHostSession:
		data, ok := req.Data.(messages.HostSessionRequest)
		if !ok {
			return types.NewAPIError(types.ErrCodeInvalidRequest, "Invalid request data for SetHostSession", "")
		}
		return a.handleSetHostSession(data)

	case messages.DelHostSession:
		data, ok := req.Data.(messages.HostSessionRequest)
		if !ok {
			return types.NewAPIError(types.ErrCodeInvalidRequest, "Invalid request data for DelHostSession", "")
		}
		return a.handleDelHostSession(data)

	case messages.ValHostAppSec:
		data, ok := req.Data.(messages.AppSecRequest)
		if !ok {
			return types.NewAPIError(types.ErrCodeInvalidRequest, "Invalid request data for ValHostAppSec", "")
		}
		return a.handleValHostAppSec(&data)

	default:
		return types.NewAPIError(types.ErrCodeNotFound, "Unknown command", string(req.Command))
	}
}

// Type-safe handler methods

func (a *API) handleGetIP(req messages.IPRequest) *types.APIResponse {
	log.Infof("Checking IP %s", req.IP)

	r, origin, err := a.Dataset.CheckIP(req.IP)
	if err != nil {
		return types.NewAPIError(types.ErrCodeInvalidIP, "IP check failed", err.Error())
	}

	// Only count processed requests (worker connections only use this handler)
	ipType := "ipv4"
	if strings.Contains(req.IP, ":") {
		ipType = "ipv6"
	}

	metrics.TotalProcessedRequests.With(prometheus.Labels{"ip_type": ipType}).Inc()

	if r > remediation.Unknown {
		metrics.TotalBlockedRequests.With(prometheus.Labels{"ip_type": ipType, "origin": origin, "remediation": r.String()}).Inc()
	}

	return types.NewAPIResponse(r)
}

func (a *API) handleGetCN(req messages.CNRequest) *types.APIResponse {
	if req.CountryCode == "" {
		return types.NewAPIError(types.ErrCodeInvalidArgument, "Country code cannot be empty", "")
	}

	r, origin := a.Dataset.CheckCN(req.CountryCode)

	if r > remediation.Unknown {
		ipType := "ipv4"
		if strings.Contains(req.IP, ":") {
			ipType = "ipv6"
		}
		metrics.TotalBlockedRequests.With(prometheus.Labels{"ip_type": ipType, "origin": origin, "remediation": r.String()}).Inc()
	}

	return types.NewAPIResponse(r)
}

func (a *API) handleGetGeoIso(req messages.GeoRequest) *types.APIResponse {
	if !a.GeoDatabase.IsValid() {
		return types.NewAPIError(types.ErrCodeGeoDBUnavailable, "GeoIP database not available", "")
	}

	log.Tracef("Checking geo:iso IP %s", req.IP)
	val := net.ParseIP(req.IP)
	if val == nil {
		return types.NewAPIError(types.ErrCodeInvalidIP, "Invalid IP address", req.IP)
	}

	record, err := a.GeoDatabase.GetCity(&val)
	if err != nil && !errors.Is(err, geo.ErrNotValidConfig) {
		return types.NewAPIError(types.ErrCodeDatabaseError, "GeoIP lookup failed", err.Error())
	}

	if record == nil {
		return types.NewAPIResponse("")
	}

	return types.NewAPIResponse(geo.GetIsoCodeFromRecord(record))
}

func (a *API) handleGetHosts(req messages.HostsRequest) *types.APIResponse {
	// Workers cannot list all hosts, only get specific hosts
	if req.Host == "" {
		return types.NewAPIError(types.ErrCodePermissionDenied, "Permission denied", "workers cannot list all hosts")
	}

	h := a.HostManager.MatchFirstHost(req.Host)
	if h == nil {
		return types.NewAPIError(types.ErrCodeHostNotFound, "Host not found", req.Host)
	}

	// return a serializable host response to avoid gob encoding issues
	hostResponse := &types.HostResponse{
		Host:                       h.Host,
		CaptchaSiteKey:             h.Captcha.SiteKey,
		CaptchaProvider:            h.Captcha.Provider,
		CaptchaFallbackRemediation: h.Captcha.FallbackRemediation,
		BanContactUsURL:            h.Ban.ContactUsURL,
		AppSecAlwaysSend:           h.AppSec.AlwaysSend,
	}
	return types.NewAPIResponse(hostResponse)
}

func (a *API) handleGetHostCookie(req messages.HostCookieRequest) *types.APIResponse {
	h := a.HostManager.MatchFirstHost(req.Host)
	if h == nil {
		return types.NewAPIError(types.ErrCodeHostNotFound, "Host not found", req.Host)
	}

	ses, err := h.Captcha.Sessions.NewRandomSession()
	if err != nil {
		return types.NewAPIError(types.ErrCodeServerError, "Failed to create session", err.Error())
	}

	cookie, err := h.Captcha.CookieGenerator.GenerateCookie(ses, ptr.Of(req.SSL))
	if err != nil {
		return types.NewAPIError(types.ErrCodeServerError, "Failed to generate cookie", err.Error())
	}

	ses.Set(session.CaptchaStatus, captcha.Pending)
	return types.NewAPIResponse(cookie)
}

func (a *API) handleGetHostSession(req messages.HostSessionRequest) *types.APIResponse {
	h := a.HostManager.MatchFirstHost(req.Host)
	if h == nil {
		return types.NewAPIError(types.ErrCodeHostNotFound, "Host not found", req.Host)
	}

	ses := h.Captcha.Sessions.GetSession(req.UUID)
	if ses == nil {
		return types.NewAPIError(types.ErrCodeSessionNotFound, "Session not found", req.UUID)
	}

	val := ses.Get(req.Key)
	if val == nil {
		val = ""
	}

	return types.NewAPIResponse(val)
}

func (a *API) handleValHostCookie(req messages.HostCookieValidationRequest) *types.APIResponse {
	h := a.HostManager.MatchFirstHost(req.Host)
	if h == nil {
		return types.NewAPIError(types.ErrCodeHostNotFound, "Host not found", req.Host)
	}

	uuid, err := h.Captcha.CookieGenerator.ValidateCookie(req.Cookie)
	if err != nil {
		return types.NewAPIError(types.ErrCodeInvalidCookie, "Cookie validation failed", err.Error())
	}

	sess := h.Captcha.Sessions.GetSession(uuid)
	if sess == nil {
		return types.NewAPIError(types.ErrCodeSessionNotFound, "Session not found", uuid)
	}

	return types.NewAPIResponse(uuid)
}

func (a *API) handleValHostCaptcha(ctx context.Context, req messages.HostCaptchaValidationRequest) *types.APIResponse {
	h := a.HostManager.MatchFirstHost(req.Host)
	if h == nil {
		return types.NewAPIError(types.ErrCodeHostNotFound, "Host not found", req.Host)
	}

	isValid, err := h.Captcha.Validate(ctx, req.UUID, req.Response)
	if err != nil {
		return types.NewAPIError(types.ErrCodeCaptchaValidationFailed, "Captcha validation failed", err.Error())
	}
	return types.NewAPIResponse(isValid)
}

func (a *API) handleSetHostSession(req messages.HostSessionRequest) *types.APIResponse {
	h := a.HostManager.MatchFirstHost(req.Host)
	if h == nil {
		return types.NewAPIError(types.ErrCodeHostNotFound, "Host not found", req.Host)
	}

	ses := h.Captcha.Sessions.GetSession(req.UUID)
	if ses == nil {
		return types.NewAPIError(types.ErrCodeSessionNotFound, "Session not found", req.UUID)
	}

	ses.Set(req.Key, req.Value)
	return types.NewAPIResponse(true)
}

func (a *API) handleDelHostSession(req messages.HostSessionRequest) *types.APIResponse {
	h := a.HostManager.MatchFirstHost(req.Host)
	if h == nil {
		return types.NewAPIError(types.ErrCodeHostNotFound, "Host not found", req.Host)
	}

	ses := h.Captcha.Sessions.GetSession(req.UUID)
	if ses == nil {
		return types.NewAPIError(types.ErrCodeSessionNotFound, "Session not found", req.UUID)
	}

	ses.Delete(req.Key)
	return types.NewAPIResponse(true)
}

func (a *API) handleValHostAppSec(req *messages.AppSecRequest) *types.APIResponse {
	// Future AppSec implementation
	// This is where we'll integrate with the AppSec engine
	// For now, return allow
	log.Debugf("AppSec request for host %s, method %s, URL %s", req.Host, req.Method, req.URL)

	// TODO: Implement AppSec validation logic
	// - Parse HTTP request from req.Method, req.URL, req.Headers, req.Body
	// - Send to AppSec engine for analysis
	// - Return appropriate remediation based on analysis

	return types.NewAPIResponse(remediation.Allow)
}
