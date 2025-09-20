package types

import "fmt"

// APIResponse represents a standardized API response
type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   *APIError   `json:"error,omitempty"`
}

// APIError represents a structured API error
type APIError struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
	Details string    `json:"details,omitempty"`
}

// ErrorCode represents different types of API errors
type ErrorCode string

const (
	// Request-related errors
	ErrCodeInvalidRequest   ErrorCode = "INVALID_REQUEST"
	ErrCodeMissingArgument  ErrorCode = "MISSING_ARGUMENT"
	ErrCodeTooManyArguments ErrorCode = "TOO_MANY_ARGUMENTS"
	ErrCodeInvalidArgument  ErrorCode = "INVALID_ARGUMENT"

	// Authorization errors
	ErrCodePermissionDenied ErrorCode = "PERMISSION_DENIED"
	ErrCodeUnauthorized     ErrorCode = "UNAUTHORIZED"

	// Resource errors
	ErrCodeNotFound        ErrorCode = "NOT_FOUND"
	ErrCodeHostNotFound    ErrorCode = "HOST_NOT_FOUND"
	ErrCodeSessionNotFound ErrorCode = "SESSION_NOT_FOUND"
	ErrCodeWorkerNotFound  ErrorCode = "WORKER_NOT_FOUND"

	// Validation errors
	ErrCodeInvalidCookie           ErrorCode = "INVALID_COOKIE"
	ErrCodeInvalidCaptcha          ErrorCode = "INVALID_CAPTCHA"
	ErrCodeCaptchaValidationFailed ErrorCode = "CAPTCHA_VALIDATION_FAILED"
	ErrCodeCaptchaExpired          ErrorCode = "CAPTCHA_EXPIRED"
	ErrCodeInvalidIP               ErrorCode = "INVALID_IP"
	ErrCodeInvalidHost             ErrorCode = "INVALID_HOST"

	// Server errors
	ErrCodeServerError        ErrorCode = "SERVER_ERROR"
	ErrCodeServiceUnavailable ErrorCode = "SERVICE_UNAVAILABLE"
	ErrCodeTimeout            ErrorCode = "TIMEOUT"
	ErrCodeDatabaseError      ErrorCode = "DATABASE_ERROR"

	// Connection errors
	ErrCodeConnectionError ErrorCode = "CONNECTION_ERROR"
	ErrCodeDecodeError     ErrorCode = "DECODE_ERROR"
	ErrCodeEncodeError     ErrorCode = "ENCODE_ERROR"

	// Configuration errors
	ErrCodeConfigError      ErrorCode = "CONFIG_ERROR"
	ErrCodeGeoDBUnavailable ErrorCode = "GEODB_UNAVAILABLE"
)

// Error implements the error interface for APIError
func (e *APIError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("[%s] %s: %s", e.Code, e.Message, e.Details)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// NewAPIResponse creates a successful API response
func NewAPIResponse(data interface{}) *APIResponse {
	return &APIResponse{
		Success: true,
		Data:    data,
	}
}

// NewAPIError creates an error API response
func NewAPIError(code ErrorCode, message string, details ...string) *APIResponse {
	var detail string
	if len(details) > 0 {
		detail = details[0]
	}

	return &APIResponse{
		Success: false,
		Error: &APIError{
			Code:    code,
			Message: message,
			Details: detail,
		},
	}
}

// IsNotFoundError checks if the error represents a "not found" condition
func (r *APIResponse) IsNotFoundError() bool {
	return !r.Success && r.Error != nil &&
		(r.Error.Code == ErrCodeNotFound ||
			r.Error.Code == ErrCodeHostNotFound ||
			r.Error.Code == ErrCodeSessionNotFound ||
			r.Error.Code == ErrCodeWorkerNotFound)
}

// IsPermissionError checks if the error is permission-related
func (r *APIResponse) IsPermissionError() bool {
	return !r.Success && r.Error != nil &&
		(r.Error.Code == ErrCodePermissionDenied ||
			r.Error.Code == ErrCodeUnauthorized)
}

// IsServerError checks if the error is server-side
func (r *APIResponse) IsServerError() bool {
	return !r.Success && r.Error != nil &&
		(r.Error.Code == ErrCodeServerError ||
			r.Error.Code == ErrCodeServiceUnavailable ||
			r.Error.Code == ErrCodeTimeout ||
			r.Error.Code == ErrCodeDatabaseError)
}

// GetData safely extracts and converts the response data to the expected type
func GetData[T any](resp *APIResponse) (T, error) {
	var zero T

	if !resp.Success {
		return zero, resp.Error
	}

	if resp.Data == nil {
		return zero, &APIError{
			Code:    ErrCodeServerError,
			Message: "Response data is nil",
		}
	}

	result, ok := resp.Data.(T)
	if !ok {
		return zero, &APIError{
			Code:    ErrCodeServerError,
			Message: "Response data type mismatch",
			Details: fmt.Sprintf("expected %T, got %T", zero, resp.Data),
		}
	}

	return result, nil
}

// HostResponse represents a serializable version of host.Host for API responses
type HostResponse struct {
	Host                       string `json:"host"`
	CaptchaSiteKey             string `json:"captcha_site_key"`
	CaptchaProvider            string `json:"captcha_provider"`
	CaptchaFallbackRemediation string `json:"captcha_fallback_remediation"`
	BanContactUsURL            string `json:"ban_contact_us_url"`
	AppSecAlwaysSend           bool   `json:"appsec_always_send"`
}
