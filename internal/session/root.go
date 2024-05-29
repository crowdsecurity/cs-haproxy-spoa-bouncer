package session

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

const (
	URI            = "URI"            // Last URI the user visited
	CAPTCHA_STATUS = "CAPTCHA_STATUS" // Status of the captcha
	CAPTCHA_TRIES  = "CAPTCHA_TRIES"  // Number of captcha tries
)

func NewSession() (*Session, error) {
	uid, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}
	return NewSessionWithUUID(uid.String()), nil
}

func NewSessionWithUUID(uuid string) *Session {
	now := time.Now().UTC()
	return &Session{
		Uuid:         uuid,
		KV:           make(map[string]interface{}),
		UpdateTime:   now,
		CreationTime: now,
	}
}

type Session struct {
	Uuid         string                 // UUID of the session
	KV           map[string]interface{} // Key-Value store for the session
	CreationTime time.Time              // Creation time of the session used to compare against max time
	UpdateTime   time.Time              // Last update time of the session used to compare against idle timeout
	mu           sync.RWMutex           // Mutex for thread-safe access to KV
}

func (s *Session) Get(key string) interface{} {
	s.updateTime()
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.KV[key]
}

func (s *Session) Set(key string, value interface{}) {
	s.updateTime()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.KV[key] = value
}

func (s *Session) Delete(key string) {
	s.updateTime()
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.KV, key)
}

func (s *Session) updateTime() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.UpdateTime = time.Now().UTC()
}

func (s *Session) HasTimedOut(parsedIdleTimeout time.Duration) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Since(s.UpdateTime) > parsedIdleTimeout
}

func (s *Session) HasMaxTime(parsedMaxTime time.Duration) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Since(s.CreationTime) > parsedMaxTime
}

type Sessions struct {
	sessions              map[string]*Session
	SessionIdleTimeout    string
	SessionMaxTime        string
	SessionGarbageSeconds uint16
	parsedIdleTimeout     time.Duration
	parsedMaxTime         time.Duration
	logger                *log.Entry
	mu                    sync.RWMutex
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
		log.Errorf("failed to parse session idle timeout: %s", err)
	}
	s.parsedMaxTime, err = time.ParseDuration(s.SessionMaxTime)
	if err != nil {
		log.Errorf("failed to parse session max time: %s", err)
	}

	if s.parsedMaxTime < s.parsedIdleTimeout {
		log.Warn("session max time is less than session idle timeout, this may cause unexpected behavior")
	}

	s.logger = log.WithField("type", "sessions")
	s.sessions = make(map[string]*Session)

	if s.SessionGarbageSeconds == 0 {
		s.SessionGarbageSeconds = 60
	}

	go s.garbageCollect(ctx)
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
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, exists := s.sessions[uuid]
	if !exists || session.HasTimedOut(s.parsedIdleTimeout) || session.HasMaxTime(s.parsedMaxTime) {
		s.logger.Tracef("session %s is invalid or does not exist", uuid)
		return nil
	}
	return session
}

func (s *Sessions) AddSession(session *Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.Uuid] = session
}

func (s *Sessions) RemoveSession(session *Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, session.Uuid)
}

func (s *Sessions) garbageCollect(ctx context.Context) {
	s.logger.Debug("starting session garbage collection goroutine")
	ticker := time.NewTicker(time.Duration(s.SessionGarbageSeconds) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.logger.Trace("checking for sessions to garbage collect")
			s.mu.Lock()
			expiredSessions := make([]string, 0)

			for uuid, session := range s.sessions {
				if session.HasTimedOut(s.parsedIdleTimeout) || session.HasMaxTime(s.parsedMaxTime) {
					s.logger.Tracef("session %s has timed out or reached max time", uuid)
					expiredSessions = append(expiredSessions, uuid)
				}
			}

			for _, uuid := range expiredSessions {
				delete(s.sessions, uuid)
			}

			s.mu.Unlock()

			if len(expiredSessions) > 0 {
				s.logger.Tracef("flushed %d sessions", len(expiredSessions))
			} else {
				s.logger.Trace("no timed out sessions to garbage collect")
			}
		}
	}
}
