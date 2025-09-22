package api

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/crowdsecurity/crowdsec-spoa/internal/api/messages"
	"github.com/crowdsecurity/crowdsec-spoa/internal/api/types"
	"github.com/crowdsecurity/crowdsec-spoa/internal/geo"
	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation/captcha"
	"github.com/crowdsecurity/crowdsec-spoa/internal/session"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/host"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/server"
	"github.com/crowdsecurity/go-cs-lib/ptr"
	log "github.com/sirupsen/logrus"
)

// Admin handler methods for string-based protocol

func (a *API) handleAdminValHostCookie(args []string) *types.APIResponse {
	if resp := ArgsCheckResponse(args, 2, 2); resp != nil {
		return resp
	}

	h := a.HostManager.MatchFirstHost(args[0])
	if h == nil {
		return types.NewAPIError(types.ErrCodeHostNotFound, "Host not found", args[0])
	}

	uuid, err := h.Captcha.CookieGenerator.ValidateCookie(args[1])
	if err != nil {
		return types.NewAPIError(types.ErrCodeInvalidCookie, "Cookie validation failed", err.Error())
	}

	sess := h.Captcha.Sessions.GetSession(uuid)
	if sess == nil {
		return types.NewAPIError(types.ErrCodeSessionNotFound, "Session not found", uuid)
	}

	return types.NewAPIResponse(uuid)
}

func (a *API) handleAdminValHostCaptcha(ctx context.Context, args []string) *types.APIResponse {
	if resp := ArgsCheckResponse(args, 3, 3); resp != nil {
		return resp
	}

	h := a.HostManager.MatchFirstHost(args[0])
	if h == nil {
		return types.NewAPIError(types.ErrCodeHostNotFound, "Host not found", args[0])
	}

	isValid, err := h.Captcha.Validate(ctx, args[1], args[2])
	if err != nil {
		return types.NewAPIError(types.ErrCodeCaptchaValidationFailed, "Captcha validation failed", err.Error())
	}
	return types.NewAPIResponse(isValid)
}

func (a *API) handleAdminDelHostSession(args []string) *types.APIResponse {
	if resp := ArgsCheckResponse(args, 3, 3); resp != nil {
		return resp
	}

	h := a.HostManager.MatchFirstHost(args[0])
	if h == nil {
		return types.NewAPIError(types.ErrCodeHostNotFound, "Host not found", args[0])
	}

	ses := h.Captcha.Sessions.GetSession(args[1])
	if ses == nil {
		return types.NewAPIError(types.ErrCodeSessionNotFound, "Session not found", args[1])
	}

	ses.Delete(args[2])
	return types.NewAPIResponse(true)
}

func (a *API) handleAdminDelHosts(args []string) *types.APIResponse {
	// Only admins can delete hosts (no permission check needed since only admin socket uses this)
	if resp := ArgsCheckResponse(args, 1, 1); resp != nil {
		return resp
	}

	h := a.HostManager.MatchFirstHost(args[0])
	if h == nil {
		return types.NewAPIError(types.ErrCodeHostNotFound, "Host not found", args[0])
	}

	a.HostManager.Chan <- host.HostOp{
		Host: h,
		Op:   host.OpRemove,
	}

	return types.NewAPIResponse(true)
}

func (a *API) handleAdminSetHostSession(args []string) *types.APIResponse {
	if resp := ArgsCheckResponse(args, 4, 4); resp != nil {
		return resp
	}

	h := a.HostManager.MatchFirstHost(args[0])
	if h == nil {
		return types.NewAPIError(types.ErrCodeHostNotFound, "Host not found", args[0])
	}

	ses := h.Captcha.Sessions.GetSession(args[1])
	if ses == nil {
		return types.NewAPIError(types.ErrCodeSessionNotFound, "Session not found", args[1])
	}

	ses.Set(args[2], args[3])
	return types.NewAPIResponse(true)
}

func (a *API) handleAdminGetHostSession(args []string) *types.APIResponse {
	if resp := ArgsCheckResponse(args, 3, 3); resp != nil {
		return resp
	}

	h := a.HostManager.MatchFirstHost(args[0])
	if h == nil {
		return types.NewAPIError(types.ErrCodeHostNotFound, "Host not found", args[0])
	}

	ses := h.Captcha.Sessions.GetSession(args[1])
	if ses == nil {
		return types.NewAPIError(types.ErrCodeSessionNotFound, "Session not found", args[1])
	}

	val := ses.Get(args[2])
	if val == nil {
		val = ""
	}

	return types.NewAPIResponse(val)
}

func (a *API) handleAdminGetHostCookie(args []string) *types.APIResponse {
	if resp := ArgsCheckResponse(args, 2, 2); resp != nil {
		return resp
	}

	h := a.HostManager.MatchFirstHost(args[0])
	if h == nil {
		return types.NewAPIError(types.ErrCodeHostNotFound, "Host not found", args[0])
	}

	ses, err := h.Captcha.Sessions.NewRandomSession()
	if err != nil {
		return types.NewAPIError(types.ErrCodeServerError, "Failed to create session", err.Error())
	}

	cookie, err := h.Captcha.CookieGenerator.GenerateCookie(ses, ptr.Of(args[1] == "true"))
	if err != nil {
		return types.NewAPIError(types.ErrCodeServerError, "Failed to generate cookie", err.Error())
	}

	ses.Set(session.CaptchaStatus, captcha.Pending)
	return types.NewAPIResponse(cookie)
}

func (a *API) handleAdminGetHosts(args []string) *types.APIResponse {
	// Admin can list all hosts if no args provided
	if len(args) == 0 {
		return types.NewAPIResponse(a.HostManager.String())
	}

	if resp := ArgsCheckResponse(args, 1, 1); resp != nil {
		return resp
	}

	h := a.HostManager.MatchFirstHost(args[0])
	if h == nil {
		return types.NewAPIError(types.ErrCodeHostNotFound, "Host not found", args[0])
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

func (a *API) handleAdminGetIP(args []string) *types.APIResponse {
	if resp := ArgsCheckResponse(args, 1, 1); resp != nil {
		return resp
	}

	log.Infof("Checking IP %s", args[0])

	r, _, err := a.Dataset.CheckIP(args[0])
	if err != nil {
		return types.NewAPIError(types.ErrCodeInvalidIP, "IP check failed", err.Error())
	}

	// Admin gets string representation, no metrics counting
	return types.NewAPIResponse(r.String())
}

func (a *API) handleAdminGetCN(args []string) *types.APIResponse {
	if resp := ArgsCheckResponse(args, 2, 2); resp != nil {
		return resp
	}
	if args[0] == "" {
		return types.NewAPIError(types.ErrCodeInvalidArgument, "Country code cannot be empty", "")
	}
	r, _ := a.Dataset.CheckCN(args[0])

	// Admin gets string representation, no metrics counting
	return types.NewAPIResponse(r.String())
}

func (a *API) handleAdminGetGeoIso(args []string) *types.APIResponse {
	if resp := ArgsCheckResponse(args, 1, 1); resp != nil {
		return resp
	}

	if !a.GeoDatabase.IsValid() {
		return types.NewAPIError(types.ErrCodeGeoDBUnavailable, "GeoIP database not available", "")
	}

	log.Tracef("Checking geo:iso IP %s", args[0])
	val := net.ParseIP(args[0])
	if val == nil {
		return types.NewAPIError(types.ErrCodeInvalidIP, "Invalid IP address", args[0])
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

// handleAdminConnection handles admin connections using optimized string-based protocol
func (a *API) handleAdminConnection(ctx context.Context, sc server.SocketConn) {
	defer func() {
		err := sc.Conn.Close()
		if err != nil {
			log.Error("Error closing connection:", err)
		}
	}()

	// Use buffered reader for better performance with line-based protocol
	reader := bufio.NewReader(sc.Conn)

	for {
		// Read line by line instead of fixed buffer - more efficient for admin commands
		line, err := reader.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				// Client closed the connection gracefully
				break
			}
			log.Error("Read error:", err)
			return
		}

		// Trim whitespace and skip empty lines
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		apiCommand, args, err := a.parseAdminCommand(line)
		if err != nil {
			_, writeErr := fmt.Fprintf(sc.Conn, "ERROR [INVALID_REQUEST]: %s\n", err.Error())
			if writeErr != nil {
				log.Errorf("error writing parse error to admin socket: %v", writeErr)
			}
			continue
		}

		if len(apiCommand) == 0 {
			_, writeErr := fmt.Fprintf(sc.Conn, "ERROR [INVALID_REQUEST]: Empty command\n")
			if writeErr != nil {
				log.Errorf("error writing empty command error to admin socket: %v", writeErr)
			}
			continue
		}

		// Handle command directly without permission checks (admin-only connection)
		response := a.handleAdminCommand(ctx, apiCommand, args)

		if !response.Success {
			log.WithFields(log.Fields{
				"command":       strings.Join(apiCommand, ":"),
				"args":          args,
				"error_code":    response.Error.Code,
				"error_message": response.Error.Message,
			}).Debug("Admin command failed")

			_, err := fmt.Fprintf(sc.Conn, "ERROR [%s]: %s\n", response.Error.Code, response.Error.Message)
			if err != nil {
				log.Errorf("error returning error to admin socket: %v", err)
			}
			continue
		}

		_, err = fmt.Fprintf(sc.Conn, "%v\n", response.Data)
		if err != nil {
			log.Errorf("error writing response to admin socket: %v", err)
		}
	}
}

// parseAdminCommand parses admin commands using a smart pattern-matching approach
func (a *API) parseAdminCommand(line string) ([]string, []string, error) {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return nil, nil, fmt.Errorf("empty command")
	}

	if len(parts) < 2 {
		return nil, nil, fmt.Errorf("missing module")
	}

	// For 3-part commands, we need to handle cases where arguments come between command parts
	// e.g., "get host 127.0.0.1 session uuid key" should parse as "get:host:session"
	if len(parts) >= 4 {
		// Try verb:module:submodule pattern with different positions for submodule
		verb := parts[0]
		module := parts[1]

		// Look for known submodules in the remaining parts
		for i := 2; i < len(parts); i++ {
			candidateCmd := fmt.Sprintf("%s:%s:%s", verb, module, parts[i])
			if a.isValidCommand(candidateCmd) {
				// Found valid 3-part command, collect arguments from everywhere except the command parts
				cmdParts := []string{verb, module, parts[i]}
				args := make([]string, 0)

				// Add arguments that come before the submodule
				args = append(args, parts[2:i]...)
				// Add arguments that come after the submodule
				args = append(args, parts[i+1:]...)

				return cmdParts, args, nil
			}
		}
	}

	// Try standard 3-part commands (verb:module:submodule at start)
	if len(parts) >= 3 {
		threePartCmd := strings.Join(parts[:3], ":")
		if a.isValidCommand(threePartCmd) {
			return parts[:3], parts[3:], nil
		}
	}

	// Try 2-part commands (verb:module)
	twoPartCmd := strings.Join(parts[:2], ":")
	if a.isValidCommand(twoPartCmd) {
		return parts[:2], parts[2:], nil
	}

	// If no valid command found, return an explicit error
	return nil, nil, fmt.Errorf("invalid command: %q", line)
}

// isValidCommand checks if a command string matches any of our defined APICommands
func (a *API) isValidCommand(cmdStr string) bool {
	cmd := messages.CommandFromString(cmdStr)

	// Use the actual APICommand constants - no duplication!
	switch cmd {
	case messages.GetIP,
		messages.GetCN,
		messages.GetGeoIso,
		messages.GetHosts,
		messages.GetHostCookie,
		messages.GetHostSession,
		messages.ValHostCookie,
		messages.ValHostCaptcha,
		messages.SetHostSession,
		messages.DelHostSession,
		messages.DelHosts,
		messages.ValHostAppSec:
		return true
	default:
		return false
	}
}

// handleAdminCommand directly dispatches admin commands using clean APICommand constants
func (a *API) handleAdminCommand(ctx context.Context, apiCommand []string, args []string) *types.APIResponse {
	if len(apiCommand) < 2 {
		return types.NewAPIError(types.ErrCodeInvalidRequest, "Invalid command format", "expected at least verb and module")
	}

	// Build command string from parts and convert to APICommand for cleaner switching
	cmdStr := strings.Join(apiCommand, ":")
	cmd := messages.CommandFromString(cmdStr)

	// Use clean APICommand constants instead of nested string switches
	switch cmd {
	case messages.GetIP:
		return a.handleAdminGetIP(args)
	case messages.GetCN:
		return a.handleAdminGetCN(args)
	case messages.GetGeoIso:
		return a.handleAdminGetGeoIso(args)
	case messages.GetHosts:
		return a.handleAdminGetHosts(args)
	case messages.GetHostCookie:
		return a.handleAdminGetHostCookie(args)
	case messages.GetHostSession:
		return a.handleAdminGetHostSession(args)
	case messages.SetHostSession:
		return a.handleAdminSetHostSession(args)
	case messages.DelHostSession:
		return a.handleAdminDelHostSession(args)
	case messages.DelHosts:
		return a.handleAdminDelHosts(args)
	case messages.ValHostCookie:
		return a.handleAdminValHostCookie(args)
	case messages.ValHostCaptcha:
		return a.handleAdminValHostCaptcha(ctx, args)
	default:
		return types.NewAPIError(types.ErrCodeNotFound, "Unknown command", cmdStr)
	}
}
