package admin

import (
	"fmt"
	"strings"
)

// parseAdminCommand parses admin commands using a smart pattern-matching approach
func (s *Server) parseAdminCommand(line string) ([]string, []string, error) {
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
			if s.isValidCommand(candidateCmd) {
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
		if s.isValidCommand(threePartCmd) {
			return parts[:3], parts[3:], nil
		}
	}

	// Try 2-part commands (verb:module)
	twoPartCmd := strings.Join(parts[:2], ":")
	if s.isValidCommand(twoPartCmd) {
		return parts[:2], parts[2:], nil
	}

	// If no valid command found, return an explicit error
	return nil, nil, fmt.Errorf("invalid command: %q", line)
}

// isValidCommand checks if a command string matches any of our defined APICommands
func (s *Server) isValidCommand(cmdStr string) bool {
	cmd := CommandFromString(cmdStr)

	switch cmd {
	case GetIP,
		GetCN,
		GetGeoIso,
		GetHosts,
		GetHostCookie,
		GetHostSession,
		ValHostCookie,
		ValHostCaptcha,
		SetHostSession,
		DelHostSession,
		DelHosts:
		return true
	default:
		return false
	}
}

// handleAdminCommand directly dispatches admin commands using clean APICommand constants
func (s *Server) handleAdminCommand(apiCommand []string, args []string) *APIResponse {
	if len(apiCommand) < 2 {
		return NewAPIError(ErrCodeInvalidRequest, "Invalid command format", "expected at least verb and module")
	}

	// Build command string from parts and convert to APICommand for cleaner switching
	cmdStr := strings.Join(apiCommand, ":")
	cmd := CommandFromString(cmdStr)

	// Use clean APICommand constants instead of nested string switches
	switch cmd {
	case GetIP:
		return s.handleAdminGetIP(args)
	case GetCN:
		return s.handleAdminGetCN(args)
	case GetGeoIso:
		return s.handleAdminGetGeoIso(args)
	case GetHosts:
		return s.handleAdminGetHosts(args)
	case GetHostCookie:
		return s.handleAdminGetHostCookie(args)
	case GetHostSession:
		return s.handleAdminGetHostSession(args)
	case SetHostSession:
		return s.handleAdminSetHostSession(args)
	case DelHostSession:
		return s.handleAdminDelHostSession(args)
	case DelHosts:
		return s.handleAdminDelHosts(args)
	case ValHostCookie:
		return s.handleAdminValHostCookie(args)
	case ValHostCaptcha:
		return s.handleAdminValHostCaptcha(s.ctx, args)
	default:
		return NewAPIError(ErrCodeNotFound, "Unknown command", cmdStr)
	}
}
