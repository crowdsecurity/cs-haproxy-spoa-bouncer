package session

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/stretchr/testify/assert"
)

// TestNewSession ensures that NewSession returns a non‐nil Session with a valid UUID
// and that CreationTime and UpdateTime are set to (roughly) now.
func TestNewSession(t *testing.T) {
	s, err := NewSession()
	if err != nil {
		t.Fatalf("NewSession returned unexpected error: %v", err)
	}
	if s == nil {
		t.Fatal("NewSession returned nil session")
	}
	// UUID should be a valid UUID string
	if _, err := uuid.Parse(s.UUID); err != nil {
		t.Errorf("NewSession generated invalid UUID %q: %v", s.UUID, err)
	}
	// KV should be initialized empty
	assert.Len(t, s.KV, 0, "NewSession: expected empty KV, got %v", s.KV)

	// CreationTime and UpdateTime should be close to now (within 1 second)
	now := time.Now().UTC()
	if s.CreationTime.After(now) {
		t.Errorf("CreationTime is in the future: %v > %v", s.CreationTime, now)
	}

}

// TestNewSessionWithUUID ensures that NewSessionWithUUID sets the UUID field exactly
// and initializes times and KV correctly.
func TestNewSessionWithUUID(t *testing.T) {
	const testUUID = "123e4567-e89b-12d3-a456-426614174000"
	s := NewSessionWithUUID(testUUID)
	assert.Equal(t, s.UUID, testUUID, "NewSessionWithUUID: expected UUID %q, got %q", testUUID, s.UUID)
	assert.Len(t, s.KV, 0, "NewSessionWithUUID: expected empty KV, got %v", s.KV)
}

// TestGetSetDelete ensures that Set stores a key/value, Get retrieves it, Delete removes it,
// and that each operation updates UpdateTime.
func TestGetSetDelete(t *testing.T) {
	s := NewSessionWithUUID("test-getset")

	// Record initial UpdateTime
	initialUpdate := s.UpdateTime

	// Sleep briefly to ensure timestamp difference
	time.Sleep(time.Millisecond)

	// Test Set
	s.Set("foo", 42)
	if val := s.Get("foo"); val != 42 {
		t.Errorf("Expected Get(\"foo\") to return 42, got %v", val)
	}
	if _, exists := s.KV["foo"]; !exists {
		t.Errorf("After Set, key \"foo\" not present in KV")
	}
	// UpdateTime must have been updated by Set (strictly greater than initialUpdate)
	if !s.UpdateTime.After(initialUpdate) {
		t.Errorf("Set did not update UpdateTime: before %v, after %v", initialUpdate, s.UpdateTime)
	}

	// Sleep before next operation
	time.Sleep(time.Millisecond)
	// Record UpdateTime after Set
	postSetTime := s.UpdateTime

	// Test Get: should update UpdateTime again (even though value unchanged)
	time.Sleep(time.Millisecond)
	_ = s.Get("foo")
	if !s.UpdateTime.After(postSetTime) {
		t.Errorf("Get did not update UpdateTime: before %v, after %v", postSetTime, s.UpdateTime)
	}

	// Sleep before Delete
	time.Sleep(time.Millisecond)
	postGetTime := s.UpdateTime

	// Test Delete
	time.Sleep(time.Millisecond)
	s.Delete("foo")
	if _, exists := s.KV["foo"]; exists {
		t.Errorf("Delete did not remove key \"foo\" from KV")
	}
	if !s.UpdateTime.After(postGetTime) {
		t.Errorf("Delete did not update UpdateTime: before %v, after %v", postGetTime, s.UpdateTime)
	}
}

// TestHasTimedOut tests HasTimedOut by manually setting UpdateTime into the past.
func TestHasTimedOut(t *testing.T) {
	s := NewSessionWithUUID("timeout-test")

	// Simulate that last update was 2 hours ago
	past := time.Now().UTC().Add(-2 * time.Hour)
	s.UpdateTime = past

	// If idle timeout is 1 hour, HasTimedOut should return true
	if !s.HasTimedOut(1 * time.Hour) {
		t.Errorf("Expected HasTimedOut(1h) == true for UpdateTime %v", s.UpdateTime)
	}
	// If idle timeout is 3 hours, HasTimedOut should return false
	if s.HasTimedOut(3 * time.Hour) {
		t.Errorf("Expected HasTimedOut(3h) == false for UpdateTime %v", s.UpdateTime)
	}
}

// TestHasMaxTime tests HasMaxTime by manually setting CreationTime into the past.
func TestHasMaxTime(t *testing.T) {
	s := NewSessionWithUUID("maxtime-test")

	// Simulate that creation was 10 days ago
	past := time.Now().UTC().Add(-10 * 24 * time.Hour) // 10 days ago
	s.CreationTime = past

	// If max time is 5 days, HasMaxTime should return true
	if !s.HasMaxTime(5 * 24 * time.Hour) {
		t.Errorf("Expected HasMaxTime(5d) == true for CreationTime %v", s.CreationTime)
	}
	// If max time is 15 days, HasMaxTime should return false
	if s.HasMaxTime(15 * 24 * time.Hour) {
		t.Errorf("Expected HasMaxTime(15d) == false for CreationTime %v", s.CreationTime)
	}
}
