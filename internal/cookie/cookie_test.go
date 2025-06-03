package cookie

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/crowdsecurity/crowdsec-spoa/internal/session"
	"github.com/crowdsecurity/go-cs-lib/ptr"
	log "github.com/sirupsen/logrus"
)

// helper to create a logger
func makeLogger() *log.Entry {
	return log.NewEntry(log.New())
}

// TestGenerateAndValidateSignedCookie tests that a cookie is properly signed, encoded, and validated.
func TestGenerateAndValidateSignedCookie(t *testing.T) {
	logger := makeLogger()
	cg := &CookieGenerator{}

	// Initialize with name and secret; SetDefaults() will run inside Init
	cg.Init(logger, "testcookie", "mysecretkey")
	// Explicitly enable signing
	cg.SignCookies = ptr.Of(true)
	// Force Secure to "always"
	cg.Secure = "always"
	// HTTPOnly should default true, but set explicitly for clarity
	cg.HTTPOnly = ptr.Of(true)

	// Create a dummy session
	sess := &session.Session{UUID: "session-1234"}

	sslFlag := true
	cookie, err := cg.GenerateCookie(sess, &sslFlag)
	if err != nil {
		t.Fatalf("GenerateCookie returned error: %v", err)
	}

	// Name must match
	if cookie.Name != "testcookie" {
		t.Errorf("expected cookie.Name == %q, got %q", "testcookie", cookie.Name)
	}

	// Secure was set to "always" → Secure must be true
	if !cookie.Secure {
		t.Errorf("expected Secure=true, got %v", cookie.Secure)
	}

	// HttpOnly must be true
	if !cookie.HttpOnly {
		t.Errorf("expected HttpOnly=true, got %v", cookie.HttpOnly)
	}

	// Value should be base64(signature‖UUID). Decode it and check validation:
	decoded, err := base64.URLEncoding.DecodeString(cookie.Value)
	if err != nil {
		t.Fatalf("failed to base64-decode cookie.Value: %v", err)
	}
	// The raw decoded value is 32-byte HMAC + "session-1234"
	if len(decoded) < sha256.Size {
		t.Fatalf("decoded length too short: %d", len(decoded))
	}
	rawValue := string(decoded[sha256.Size:])
	if rawValue != "session-1234" {
		t.Errorf("after decoding, rawValue = %q; want %q", rawValue, "session-1234")
	}

	// Now call ValidateCookie: should return the original UUID
	validated, err := cg.ValidateCookie(cookie.Value)
	if err != nil {
		t.Fatalf("ValidateCookie returned unexpected error: %v", err)
	}
	if validated != "session-1234" {
		t.Errorf("ValidateCookie returned %q; want %q", validated, "session-1234")
	}
}

// TestGenerateAndValidateUnsignedCookie tests an unsigned cookie round‐trip.
func TestGenerateAndValidateUnsignedCookie(t *testing.T) {
	logger := makeLogger()
	cg := &CookieGenerator{}
	cg.Init(logger, "nocookie", "irrelevant")

	// Explicitly disable signing
	cg.SignCookies = ptr.Of(false)
	// Set Secure to "never" (any value other than "auto" or "always" yields Secure=false)
	cg.Secure = "never"
	cg.HTTPOnly = ptr.Of(false) // test that HttpOnly follows the flag

	sess := &session.Session{UUID: "no-sign-uuid"}

	// Pass ssl=nil to force default Secure behavior (should be false)
	cookie, err := cg.GenerateCookie(sess, nil)
	if err != nil {
		t.Fatalf("GenerateCookie returned error: %v", err)
	}

	// Secure must be false (because Secure="never" and ssl=nil)
	if cookie.Secure {
		t.Errorf("expected Secure=false, got %v", cookie.Secure)
	}

	// HttpOnly must follow our setting (false)
	if cookie.HttpOnly {
		t.Errorf("expected HttpOnly=false, got %v", cookie.HttpOnly)
	}

	// Value was just the raw UUID, base64-encoded
	decoded, err := base64.URLEncoding.DecodeString(cookie.Value)
	if err != nil {
		t.Fatalf("failed to base64-decode cookie.Value: %v", err)
	}
	if string(decoded) != "no-sign-uuid" {
		t.Errorf("decoded value = %q; want %q", string(decoded), "no-sign-uuid")
	}

	// ValidateCookie should accept and return "no-sign-uuid"
	validated, err := cg.ValidateCookie(cookie.Value)
	if err != nil {
		t.Fatalf("ValidateCookie returned unexpected error: %v", err)
	}
	if validated != "no-sign-uuid" {
		t.Errorf("ValidateCookie returned %q; want %q", validated, "no-sign-uuid")
	}
}

// TestValidateCookie_InvalidBase64 ensures that invalid Base64 yields an error.
func TestValidateCookie_InvalidBase64(t *testing.T) {
	logger := makeLogger()
	cg := &CookieGenerator{}
	cg.Init(logger, "dummy", "secret")
	cg.SignCookies = ptr.Of(true) // signing or not does not matter here

	invalid := "not_a_valid_base64!!"
	_, err := cg.ValidateCookie(invalid)
	if err == nil {
		t.Errorf("expected error for invalid Base64 input, got nil")
	}
}

// TestValidateCookie_BadSignature ensures that tampering with a signed cookie is detected.
func TestValidateCookie_BadSignature(t *testing.T) {
	logger := makeLogger()
	cg := &CookieGenerator{}
	cg.Init(logger, "secure", "supersecret")
	cg.SignCookies = ptr.Of(true)

	// Generate a properly signed cookie
	sess := &session.Session{UUID: "tamper-uuid"}
	cookie, err := cg.GenerateCookie(sess, ptr.Of(false))
	if err != nil {
		t.Fatalf("GenerateCookie returned error: %v", err)
	}

	// Decode original, mutate one byte in the signature, re-encode
	raw, err := base64.URLEncoding.DecodeString(cookie.Value)
	if err != nil {
		t.Fatalf("failed to decode original cookie: %v", err)
	}
	// Flip a bit in the first byte of the signature
	raw[0] ^= 0xFF
	badB64 := base64.URLEncoding.EncodeToString(raw)

	_, err = cg.ValidateCookie(badB64)
	if err == nil {
		t.Errorf("expected signature validation error after tampering, got nil")
	}
}

// TestGenerateCookie_SecureAutoNil tests Secure="auto" with nil ssl pointer
func TestGenerateCookie_SecureAutoNil(t *testing.T) {
	logger := makeLogger()
	cg := &CookieGenerator{}
	cg.Init(logger, "autocookie", "secretkey")
	cg.SignCookies = ptr.Of(false) // skip signing; focus on Secure behavior
	cg.Secure = "auto"
	cg.HTTPOnly = ptr.Of(true)

	sess := &session.Session{UUID: "auto-uuid"}

	// Pass ssl=nil → should get Secure=false and a warning in logs
	cookie, err := cg.GenerateCookie(sess, nil)
	if err != nil {
		t.Fatalf("GenerateCookie returned error: %v", err)
	}

	if cookie.Secure {
		t.Errorf("expected Secure=false when ssl=nil in 'auto' mode, got true")
	}
	if cookie.Name != "autocookie" {
		t.Errorf("cookie.Name = %q; want %q", cookie.Name, "autocookie")
	}
	if cookie.HttpOnly != true {
		t.Errorf("cookie.HttpOnly = %v; want true", cookie.HttpOnly)
	}

	// Ensure the value is still correct (raw "auto-uuid" base64-encoded)
	decoded, err := base64.URLEncoding.DecodeString(cookie.Value)
	if err != nil {
		t.Fatalf("failed to decode cookie.Value: %v", err)
	}
	if string(decoded) != "auto-uuid" {
		t.Errorf("decoded cookie value = %q; want %q", string(decoded), "auto-uuid")
	}
}

// TestGenerateCookie_SecureAlwaysAndAuto ensures Secure="always" overrides ssl, and Secure="auto" honors ssl.
func TestGenerateCookie_SecureBehavior(t *testing.T) {
	logger := makeLogger()
	cg := &CookieGenerator{}
	cg.Init(logger, "mixcookie", "secret")
	cg.SignCookies = ptr.Of(false)
	cg.HTTPOnly = ptr.Of(true)

	// Case A: Secure="always"
	cg.Secure = "always"
	sessA := &session.Session{UUID: "uuid-A"}
	cookieA, err := cg.GenerateCookie(sessA, ptr.Of(false)) // ssl=false but "always" should force true
	if err != nil {
		t.Fatalf("GenerateCookie returned error for case A: %v", err)
	}
	if !cookieA.Secure {
		t.Errorf("case A: expected Secure=true when Secure='always', got false")
	}

	// Case B: Secure="auto" and ssl=true
	cg.Secure = "auto"
	sessB := &session.Session{UUID: "uuid-B"}
	cookieB, err := cg.GenerateCookie(sessB, ptr.Of(true))
	if err != nil {
		t.Fatalf("GenerateCookie returned error for case B: %v", err)
	}
	if !cookieB.Secure {
		t.Errorf("case B: expected Secure=true when Secure='auto' and ssl=true, got false")
	}

	// Case C: Secure="auto" and ssl=false
	sessC := &session.Session{UUID: "uuid-C"}
	cookieC, err := cg.GenerateCookie(sessC, ptr.Of(false))
	if err != nil {
		t.Fatalf("GenerateCookie returned error for case C: %v", err)
	}
	if cookieC.Secure {
		t.Errorf("case C: expected Secure=false when Secure='auto' and ssl=false, got true")
	}
}
