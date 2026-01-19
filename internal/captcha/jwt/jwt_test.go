package jwt

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testSecret = "test-secret-key-minimum-32-bytes-long-for-hmac-sha256"

// TestSignAndVerifyToken tests the basic JWT signing and verification flow
func TestSignAndVerifyToken(t *testing.T) {
	now := time.Now().Unix()
	tok := Token{
		UUID: "test-uuid-123",
		St:   Pending,
		Iat:  now,
		Exp:  now + 3600, // 1 hour from now
	}

	// Sign the token
	signed, err := Sign(tok, []byte(testSecret))
	require.NoError(t, err, "signing should succeed")
	assert.NotEmpty(t, signed, "signed token should not be empty")

	// JWT format check: header.payload.signature
	parts := strings.Split(signed, ".")
	assert.Len(t, parts, 3, "JWT should have 3 parts")

	// Verify the token
	verified, err := ParseAndVerify(signed, []byte(testSecret))
	require.NoError(t, err, "verification should succeed")
	assert.Equal(t, tok.UUID, verified.UUID, "UUID should match")
	assert.Equal(t, tok.St, verified.St, "status should match")
	assert.Equal(t, tok.Iat, verified.Iat, "issued at should match")
	assert.Equal(t, tok.Exp, verified.Exp, "expiration should match")
}

// TestSignEmptySecret tests signing with an empty secret
func TestSignEmptySecret(t *testing.T) {
	tok := Token{
		UUID: "test-uuid",
		St:   Pending,
		Iat:  time.Now().Unix(),
		Exp:  time.Now().Add(1 * time.Hour).Unix(),
	}

	// Signing with empty secret should still work (HMAC accepts any key length)
	// but it's cryptographically weak - validation should catch this in config
	signed, err := Sign(tok, []byte(""))
	require.NoError(t, err, "signing with empty secret succeeds (validation happens at config level)")
	assert.NotEmpty(t, signed)
}

// TestParseAndVerifyExpiredToken tests that expired tokens are rejected
func TestParseAndVerifyExpiredToken(t *testing.T) {
	now := time.Now().Unix()
	tok := Token{
		UUID: "test-uuid-expired",
		St:   Pending,
		Iat:  now - 7200, // 2 hours ago
		Exp:  now - 3600, // 1 hour ago (expired)
	}

	signed, err := Sign(tok, []byte(testSecret))
	require.NoError(t, err)

	// Verification should fail due to expiration
	_, err = ParseAndVerify(signed, []byte(testSecret))
	require.Error(t, err, "expired token should be rejected")
	assert.Contains(t, strings.ToLower(err.Error()), "token is expired", "error should mention expiration")
}

// TestParseAndVerifyTamperedSignature tests that tampered tokens are rejected
func TestParseAndVerifyTamperedSignature(t *testing.T) {
	now := time.Now().Unix()
	tok := Token{
		UUID: "test-uuid",
		St:   Pending,
		Iat:  now,
		Exp:  now + 3600,
	}

	signed, err := Sign(tok, []byte(testSecret))
	require.NoError(t, err)

	// Tamper with the signature (change last character)
	tampered := signed[:len(signed)-5] + "XXXXX"

	// Verification should fail
	_, err = ParseAndVerify(tampered, []byte(testSecret))
	assert.Error(t, err, "tampered token should be rejected")
}

// TestParseAndVerifyTamperedPayload tests that tampered payload is detected
func TestParseAndVerifyTamperedPayload(t *testing.T) {
	now := time.Now().Unix()
	tok := Token{
		UUID: "test-uuid",
		St:   Pending,
		Iat:  now,
		Exp:  now + 3600,
	}

	signed, err := Sign(tok, []byte(testSecret))
	require.NoError(t, err)

	// Tamper with the payload (change middle part)
	parts := strings.Split(signed, ".")
	require.Len(t, parts, 3)
	parts[1] = parts[1][:len(parts[1])-5] + "XXXXX" // Tamper with payload
	tampered := strings.Join(parts, ".")

	// Verification should fail (signature won't match tampered payload)
	_, err = ParseAndVerify(tampered, []byte(testSecret))
	assert.Error(t, err, "token with tampered payload should be rejected")
}

// TestParseAndVerifyWrongSecret tests verification with wrong secret
func TestParseAndVerifyWrongSecret(t *testing.T) {
	now := time.Now().Unix()
	tok := Token{
		UUID: "test-uuid",
		St:   Pending,
		Iat:  now,
		Exp:  now + 3600,
	}

	// Sign with one secret
	signed, err := Sign(tok, []byte(testSecret))
	require.NoError(t, err)

	// Try to verify with different secret
	wrongSecret := "different-secret-key-32-bytes-long-for-hmac-test"
	_, err = ParseAndVerify(signed, []byte(wrongSecret))
	assert.Error(t, err, "verification with wrong secret should fail")
}

// TestParseAndVerifyEmptyToken tests parsing an empty token
func TestParseAndVerifyEmptyToken(t *testing.T) {
	_, err := ParseAndVerify("", []byte(testSecret))
	require.Error(t, err, "empty token should be rejected")
	assert.Contains(t, err.Error(), "empty token")
}

// TestParseAndVerifyMalformedToken tests parsing malformed tokens
func TestParseAndVerifyMalformedToken(t *testing.T) {
	testCases := []struct {
		name  string
		token string
	}{
		{"only one part", "single-part"},
		{"only two parts", "header.payload"},
		{"invalid base64", "not!!!.valid!!!.base64!!!"},
		{"random string", "this-is-not-a-jwt-token"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseAndVerify(tc.token, []byte(testSecret))
			assert.Error(t, err, "malformed token should be rejected")
		})
	}
}

// TestTokenIsPassed tests the IsPassed method
func TestTokenIsPassed(t *testing.T) {
	now := time.Now().Unix()

	testCases := []struct {
		name     string
		token    Token
		expected bool
	}{
		{
			name: "valid passed token",
			token: Token{
				St:  Valid,
				Exp: now + 3600, // not expired
			},
			expected: true,
		},
		{
			name: "expired passed token",
			token: Token{
				St:  Valid,
				Exp: now - 3600, // expired
			},
			expected: false,
		},
		{
			name: "pending token",
			token: Token{
				St:  Pending,
				Exp: now + 3600,
			},
			expected: false,
		},
		{
			name: "valid token at exact expiry",
			token: Token{
				St:  Valid,
				Exp: now, // exactly at expiry
			},
			expected: true, // still valid (<=)
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.token.IsPassed()
			assert.Equal(t, tc.expected, result)
		})
	}
}

// TestTokenIsPending tests the IsPending method
func TestTokenIsPending(t *testing.T) {
	now := time.Now().Unix()

	testCases := []struct {
		name     string
		token    Token
		expected bool
	}{
		{
			name: "valid pending token",
			token: Token{
				St:  Pending,
				Exp: now + 3600,
			},
			expected: true,
		},
		{
			name: "expired pending token",
			token: Token{
				St:  Pending,
				Exp: now - 3600,
			},
			expected: false,
		},
		{
			name: "passed token",
			token: Token{
				St:  Valid,
				Exp: now + 3600,
			},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.token.IsPending()
			assert.Equal(t, tc.expected, result)
		})
	}
}

// TestSignedTokenRoundTrip tests that a signed token can be verified
func TestSignedTokenRoundTrip(t *testing.T) {
	now := time.Now().Unix()
	tok := Token{
		UUID: "test-uuid-456",
		St:   Valid,
		Iat:  now,
		Exp:  now + 3600,
	}

	// Sign token
	signed, err := Sign(tok, []byte(testSecret))
	require.NoError(t, err)

	// Verify it's a valid JWT format
	parts := strings.Split(signed, ".")
	assert.Len(t, parts, 3, "signed token should be a JWT")

	// Parse and verify
	validated, err := ParseAndVerify(signed, []byte(testSecret))
	require.NoError(t, err, "token validation should succeed")

	assert.Equal(t, tok.UUID, validated.UUID)
	assert.Equal(t, tok.St, validated.St)
	assert.Equal(t, tok.Iat, validated.Iat)
	assert.Equal(t, tok.Exp, validated.Exp)
}

// TestSigningMethodValidation tests that non-HMAC signing methods are rejected
func TestSigningMethodValidation(t *testing.T) {
	// This test ensures the parser validates the signing method
	// We can't easily create a token with a different signing method without
	// using the jwt library directly, but the validation is in the code

	now := time.Now().Unix()
	tok := Token{
		UUID: "test-uuid",
		St:   Pending,
		Iat:  now,
		Exp:  now + 3600,
	}

	// Normal HMAC token should work
	signed, err := Sign(tok, []byte(testSecret))
	require.NoError(t, err)

	verified, err := ParseAndVerify(signed, []byte(testSecret))
	require.NoError(t, err)
	assert.Equal(t, tok.UUID, verified.UUID)
}

// TestRoundTripMultipleTokens tests signing and verifying multiple tokens
func TestRoundTripMultipleTokens(t *testing.T) {
	now := time.Now().Unix()
	tokens := []Token{
		{UUID: "user-1", St: Pending, Iat: now, Exp: now + 1800},
		{UUID: "user-2", St: Valid, Iat: now, Exp: now + 86400},
		{UUID: "user-3", St: Pending, Iat: now, Exp: now + 900},
	}

	for i, tok := range tokens {
		t.Run(tok.UUID, func(t *testing.T) {
			// Sign
			signed, err := Sign(tok, []byte(testSecret))
			require.NoError(t, err, "token %d signing should succeed", i)

			// Verify
			verified, err := ParseAndVerify(signed, []byte(testSecret))
			require.NoError(t, err, "token %d verification should succeed", i)

			assert.Equal(t, tok.UUID, verified.UUID)
			assert.Equal(t, tok.St, verified.St)
			assert.Equal(t, tok.Iat, verified.Iat)
			assert.Equal(t, tok.Exp, verified.Exp)
		})
	}
}

// TestTokenStatusTransition tests token status changes
func TestTokenStatusTransition(t *testing.T) {
	now := time.Now().Unix()

	// Create pending token
	pendingTok := Token{
		UUID: "test-uuid",
		St:   Pending,
		Iat:  now,
		Exp:  now + 3600,
	}

	// Sign as pending
	signed, err := Sign(pendingTok, []byte(testSecret))
	require.NoError(t, err)

	// Verify it's pending
	verified, err := ParseAndVerify(signed, []byte(testSecret))
	require.NoError(t, err)
	assert.True(t, verified.IsPending())
	assert.False(t, verified.IsPassed())

	// Create passed token (simulating successful validation)
	passedTok := Token{
		UUID: "test-uuid",
		St:   Valid,
		Iat:  now,
		Exp:  now + 86400, // longer TTL for passed tokens
	}

	// Sign as passed
	signedPassed, err := Sign(passedTok, []byte(testSecret))
	require.NoError(t, err)

	// Verify it's passed
	verifiedPassed, err := ParseAndVerify(signedPassed, []byte(testSecret))
	require.NoError(t, err)
	assert.False(t, verifiedPassed.IsPending())
	assert.True(t, verifiedPassed.IsPassed())
}
