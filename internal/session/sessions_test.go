package session

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper to create a Sessions instance with a logger and a cancelable context.
func newSessionsForTest(idleTimeout, maxTime string, garbageSeconds int) (*Sessions, context.CancelFunc) {
	logger := logrus.NewEntry(logrus.New())
	ctx, cancel := context.WithCancel(context.Background())

	s := &Sessions{
		SessionIdleTimeout:    idleTimeout,
		SessionMaxTime:        maxTime,
		SessionGarbageSeconds: uint16(garbageSeconds),
	}
	s.Init(logger, ctx)

	return s, cancel
}

func TestInitDefaults(t *testing.T) {
	s, cancel := newSessionsForTest("", "", 0)
	defer cancel()

	// After Init, parsedIdleTimeout should be 1h, parsedMaxTime should be 12h.
	assert.Equal(t, time.Hour, s.parsedIdleTimeout, "parsedIdleTimeout should default to 1h")
	assert.Equal(t, 12*time.Hour, s.parsedMaxTime, "parsedMaxTime should default to 12h")

	// If SessionGarbageSeconds was zero, it should default to 60
	assert.Equal(t, uint16(60), s.SessionGarbageSeconds, "SessionGarbageSeconds should default to 60")
}

func TestInitWithInvalidDurations(t *testing.T) {
	// Provide invalid duration strings; parsed durations should remain zero.
	s, cancel := newSessionsForTest("notaduration", "alsoinvalid", 0)
	defer cancel()

	assert.Equal(t, time.Duration(0), s.parsedIdleTimeout, "parsedIdleTimeout should be 0 for invalid input")
	assert.Equal(t, time.Duration(0), s.parsedMaxTime, "parsedMaxTime should be 0 for invalid input")
}

func TestNewRandomSessionAndGetSession(t *testing.T) {
	s, cancel := newSessionsForTest("1h", "2h", 0)
	defer cancel()

	session, err := s.NewRandomSession()
	require.NoError(t, err, "NewRandomSession should not return an error")

	got := s.GetSession(session.UUID)
	assert.NotNil(t, got, "GetSession should return a valid session immediately after creation")
	assert.Equal(t, session.UUID, got.UUID, "retrieved session UUID should match")
}

func TestGetSessionIdleTimeout(t *testing.T) {
	// Set idle timeout to 0 so that any session is immediately timed out
	s, cancel := newSessionsForTest("0s", "1h", 0)
	defer cancel()

	session, err := s.NewRandomSession()
	require.NoError(t, err, "NewRandomSession should not return an error")

	got := s.GetSession(session.UUID)
	assert.Nil(t, got, "GetSession should return nil for idle-timed-out session")
}

func TestGetSessionMaxTime(t *testing.T) {
	// Set max time to 0 so that any session is immediately expired
	s, cancel := newSessionsForTest("1h", "0s", 0)
	defer cancel()

	session, err := s.NewRandomSession()
	require.NoError(t, err, "NewRandomSession should not return an error")

	got := s.GetSession(session.UUID)
	assert.Nil(t, got, "GetSession should return nil for max-time-expired session")
}

func TestAddAndRemoveSession(t *testing.T) {
	s, cancel := newSessionsForTest("1h", "2h", 0)
	defer cancel()

	session, err := s.NewRandomSession()
	require.NoError(t, err, "NewRandomSession should not return an error")

	// Ensure the session exists
	assert.NotNil(t, s.GetSession(session.UUID), "Session should be present after NewRandomSession")

	// Remove it
	s.RemoveSession(session)
	assert.Nil(t, s.GetSession(session.UUID), "Session should be nil after RemoveSession")
}

func TestGarbageCollectRemovesExpired(t *testing.T) {
	// Set idle timeout to 1s, max time to 2s, garbage collection every 1 second
	s, cancel := newSessionsForTest("1s", "2s", 1)
	defer cancel()

	session, err := s.NewRandomSession()
	require.NoError(t, err, "NewRandomSession should not return an error")

	// Immediately, session should be retrievable
	assert.NotNil(t, s.GetSession(session.UUID), "Session should exist immediately after creation")

	// Wait for longer than idle timeout + one garbage interval
	time.Sleep(2 * time.Second)

	// By now, garbageCollect should have run at least once and removed the session
	assert.Nil(t, s.GetSession(session.UUID), "Session should be removed by garbageCollect after idle timeout")
}

func TestGarbageCollectStopsOnContextCancel(t *testing.T) {
	// Set idle timeout long so session won't expire on its own
	s, cancel := newSessionsForTest("10s", "20s", 1)

	session, err := s.NewRandomSession()
	require.NoError(t, err, "NewRandomSession should not return an error")

	// Cancel the context to stop garbageCollect
	cancel()

	// Give a short moment for the goroutine to notice the cancel
	time.Sleep(100 * time.Millisecond)

	// After stopping, internal sessions map should be reset
	assert.Nil(t, s.GetSession(session.UUID), "Sessions map should be cleared on context cancel")
}
