package captcha

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// CaptchaToken represents the payload stored in a signed captcha cookie
type CaptchaToken struct {
	UUID string `json:"uuid"` // UUID for traceability and debugging
	St   string `json:"st"`   // status: "pending", "passed", "failed", etc.
	Iat  int64  `json:"iat"`  // issued at (unix seconds)
	Exp  int64  `json:"exp"`  // expires at (unix seconds)
}

const (
	// DefaultPendingTTL is the default TTL for pending captcha tokens (30 minutes)
	DefaultPendingTTL = 30 * time.Minute
	// DefaultPassedTTL is the default TTL for passed captcha tokens (24 hours)
	DefaultPassedTTL = 24 * time.Hour
)

// SignCaptchaToken signs a CaptchaToken using JWT (JWS) and returns a signed JWT string
// Uses HMAC-SHA256 for signing. The token can be encrypted (JWE) in the future if needed.
func SignCaptchaToken(tok CaptchaToken, secret []byte) (string, error) {
	// Create JWT claims from CaptchaToken
	claims := jwt.MapClaims{
		"uuid": tok.UUID,
		"st":   tok.St,
		"iat":  tok.Iat,
		"exp":  tok.Exp,
	}

	// Create token with HMAC-SHA256 signing method
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign and get the complete encoded token as a string
	tokenString, err := token.SignedString(secret)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// ParseAndVerifyCaptchaToken parses and verifies a JWT token string
// Returns the token if valid, or an error if invalid, expired, or tampered with
// JWT library automatically handles expiration checking via the "exp" claim
func ParseAndVerifyCaptchaToken(raw string, secret []byte) (*CaptchaToken, error) {
	if raw == "" {
		return nil, fmt.Errorf("empty token")
	}

	// Parse and verify the JWT token
	token, err := jwt.Parse(raw, func(token *jwt.Token) (any, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse/verify token: %w", err)
	}

	// Verify token is valid (signature, expiration, etc.)
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Convert JWT claims back to CaptchaToken
	tok := &CaptchaToken{
		UUID: getStringClaim(claims, "uuid"),
		St:   getStringClaim(claims, "st"),
		Iat:  getInt64Claim(claims, "iat"),
		Exp:  getInt64Claim(claims, "exp"),
	}

	return tok, nil
}

// Helper functions to safely extract claims from JWT
func getStringClaim(claims jwt.MapClaims, key string) string {
	if val, ok := claims[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

func getInt64Claim(claims jwt.MapClaims, key string) int64 {
	if val, ok := claims[key]; ok {
		switch v := val.(type) {
		case int64:
			return v
		case float64:
			return int64(v)
		case int:
			return int64(v)
		}
	}
	return 0
}

// IsPassed checks if the token indicates the captcha was passed (not expired and status is valid)
func (t *CaptchaToken) IsPassed() bool {
	return time.Now().Unix() <= t.Exp && t.St == Valid
}

// IsPending checks if the token indicates the captcha is pending (not expired and status is pending)
func (t *CaptchaToken) IsPending() bool {
	return time.Now().Unix() <= t.Exp && t.St == Pending
}
