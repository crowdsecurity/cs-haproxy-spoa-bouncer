package admin

import "fmt"

// APIResponse represents a standardized API response
type APIResponse struct {
	Success bool
	Data    interface{}
	Error   *APIError
}

// APIError represents a structured API error
type APIError struct {
	Code    ErrorCode
	Message string
}

// ErrorCode represents different types of API errors
type ErrorCode string

const (
	// Request-related errors
	ErrCodeInvalidRequest  ErrorCode = "INVALID_REQUEST"
	ErrCodeInvalidArgument ErrorCode = "INVALID_ARGUMENT"

	// Resource errors
	ErrCodeNotFound        ErrorCode = "NOT_FOUND"
	ErrCodeHostNotFound    ErrorCode = "HOST_NOT_FOUND"
	ErrCodeSessionNotFound ErrorCode = "SESSION_NOT_FOUND"

	// Validation errors
	ErrCodeInvalidCookie           ErrorCode = "INVALID_COOKIE"
	ErrCodeCaptchaValidationFailed ErrorCode = "CAPTCHA_VALIDATION_FAILED"
	ErrCodeInvalidIP               ErrorCode = "INVALID_IP"

	// Server errors
	ErrCodeServerError   ErrorCode = "SERVER_ERROR"
	ErrCodeDatabaseError ErrorCode = "DATABASE_ERROR"

	// Configuration errors
	ErrCodeGeoDBUnavailable ErrorCode = "GEODB_UNAVAILABLE"
)

// NewAPIResponse creates a successful API response
func NewAPIResponse(data interface{}) *APIResponse {
	return &APIResponse{
		Success: true,
		Data:    data,
	}
}

// NewAPIError creates an error API response
func NewAPIError(code ErrorCode, message string, details ...string) *APIResponse {
	msg := message
	if len(details) > 0 && details[0] != "" {
		msg = fmt.Sprintf("%s: %s", message, details[0])
	}

	return &APIResponse{
		Success: false,
		Error: &APIError{
			Code:    code,
			Message: msg,
		},
	}
}

// HostResponse represents a serializable version of host.Host for API responses
type HostResponse struct {
	Host                       string
	CaptchaSiteKey             string
	CaptchaProvider            string
	CaptchaFallbackRemediation string
	BanContactUsURL            string
	AppSecAlwaysSend           bool
}
