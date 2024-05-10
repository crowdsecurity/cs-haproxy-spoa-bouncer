package session

import (
	"context"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

// Known keys for the session KV store
const (
	URI            = "URI"            // Last URI the user visited
	CAPTCHA_STATUS = "CAPTCHA_STATUS" // Status of the captcha
	CAPTCHA_TRIES  = "CAPTCHA_TRIES"  // Number of captcha tries
)

func NewSession() (*Session, error) {
	uid, err := uuid.NewRandom()
	return NewSessionWithUUID(uid.String()), err
}

func NewSessionWithUUID(uuid string) *Session {
	return &Session{
		Uuid:         uuid,
		KV:           make(map[string]interface{}),
		UpdateTime:   time.Now().UTC(),
		CreationTime: time.Now().UTC(),
	}
}

type Session struct {
	Uuid         string                 // UUID of the session
	KV           map[string]interface{} // Key-Value store for the session
	CreationTime time.Time              // Creation time of the session used to compare against max time
	UpdateTime   time.Time              // Last update time of the session used to compare against idle timeout
}

// Get returns the value of the key from the session
func (s *Session) Get(key string) interface{} {
	s.updateTime()
	return s.KV[key]
}

// Set sets the value of the key in the session
func (s *Session) Set(key string, value interface{}) {
	s.updateTime()
	s.KV[key] = value
}

// Delete deletes the key from the session
func (s *Session) Delete(key string) {
	s.updateTime()
	delete(s.KV, key)
}

func (s *Session) updateTime() {
	s.UpdateTime = time.Now().UTC()
}

// HasTimedOut checks if the session has timed out
func (s *Session) HasTimedOut(ss *Sessions) bool {
	return time.Since(s.UpdateTime) > ss.parsedIdleTimeout
}

// HasMaxTime checks if the session has reached the max time to prevent cookie reuse
func (s *Session) HasMaxTime(ss *Sessions) bool {
	return time.Since(s.CreationTime) > ss.parsedMaxTime
}

type Sessions struct {
	s                  []*Session    `yaml:"-"`                    // underlying sessions slice
	SessionIdleTimeout string        `yaml:"session_idle_timeout"` // Max session idle timeout as a GoLang duration string EG: "2h"
	SessionMaxTime     string        `yaml:"session_max_time"`     // Max session time as a GoLang duration string EG: "24h"
	parsedIdleTimeout  time.Duration `yaml:"-"`                    // Parsed session timeout
	parsedMaxTime      time.Duration `yaml:"-"`                    // Parsed max session time
	logger             *log.Entry    `yaml:"-"`                    // logger passed from the remediation
}

func (s *Sessions) Init(log *log.Entry, ctx context.Context) {
	var err error

	if s.SessionIdleTimeout == "" {
		s.SessionIdleTimeout = "1h"
	}

	if s.SessionMaxTime == "" {
		s.SessionMaxTime = "12h"
	}

	s.parsedIdleTimeout, err = time.ParseDuration(s.SessionIdleTimeout)
	if err != nil {
		log.Errorf("failed to parse session timeout: %s", err)
	}

	s.parsedMaxTime, err = time.ParseDuration(s.SessionMaxTime)
	if err != nil {
		log.Errorf("failed to parse session max time: %s", err)
	}

	if s.parsedMaxTime < s.parsedIdleTimeout {
		log.Warn("session max time is less than session idle timeout, this may cause unexpected behavior")
	}

	s.logger = log.WithField("type", "sessions")
	go s.GarbageCollect(ctx)
}

func (s *Sessions) NewRandomSession() (*Session, error) {
	session, err := NewSession()
	if err != nil {
		return nil, err
	}
	s.AddSession(session)
	return session, nil
}

func (s *Sessions) GetSession(uuid string) *Session {
	for _, session := range s.s {
		if session.Uuid == uuid {
			// We check if the session has timed out or reached max time
			if session.HasTimedOut(s) || session.HasMaxTime(s) {
				s.logger.Tracef("session %s is invalid", uuid)
				// So we don't return a session that ultimately will be removed by the garbage collector we break
				break
			}
			return session
		}
	}
	return nil
}

// AddSession adds a session to the sessions slice
func (s *Sessions) AddSession(session *Session) {
	s.s = append(s.s, session)
}

// RemoveSession removes a session from the sessions slice
func (s *Sessions) RemoveSession(session *Session) {
	for i, sess := range s.s {
		if sess.Uuid == session.Uuid {
			if i == len(s.s)-1 {
				s.s = (s.s)[:i]
			} else {
				s.s = append((s.s)[:i], (s.s)[i+1:]...)
			}
			break
		}
	}
}

func (s *Sessions) GarbageCollect(ctx context.Context) {
	s.logger.Debug("starting session garbage collection goroutine")
	// Currently not configurable but can be made configurable in future
	ticker := time.NewTicker(10 * time.Second)
	for {
		select {
		case <-ctx.Done():
			ticker.Stop()
			return
		case <-ticker.C:
			s.logger.Trace("checking for sessions to garbage collect")

			if len(s.s) == 0 {
				s.logger.Trace("no sessions to garbage collect")
				continue
			}

			tSessions := make([]*Session, 0, len(s.s))
			for _, session := range s.s {
				if !session.HasTimedOut(s) && !session.HasMaxTime(s) {
					tSessions = append(tSessions, session)
				}
			}

			diff := len(s.s) - len(tSessions)

			if diff == 0 {
				s.logger.Trace("no timed out sessions to garbage collect")
				tSessions = nil // Make sure we don't keep a reference to the temp slice
				continue        // No sessions to garbage collect
			}

			s.logger.Tracef("flushed %d sessions", diff)
			s.s = tSessions
		}
	}
}
