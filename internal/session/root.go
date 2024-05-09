package session

import (
	"context"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

// Known keys for the session KV store
const (
	URI            = "URI"
	CAPTCHA_STATUS = "CAPTCHA_STATUS"
)

func NewSession(expiryTime time.Time) (*Session, error) {
	uid, err := uuid.NewRandom()
	return NewSessionWithUUID(uid.String(), expiryTime), err
}

func NewSessionWithUUID(uuid string, expiryTime time.Time) *Session {
	return &Session{
		Uuid:       uuid,
		KV:         make(map[string]interface{}),
		UpdateTime: time.Now().UTC(),
		ExpiryTime: expiryTime.Unix(),
	}
}

type Session struct {
	Uuid       string                 // UUID of the session
	KV         map[string]interface{} // Key-Value store for the session
	UpdateTime time.Time              // Update time of the session (might be used for garbage collection in future)
	ExpiryTime int64                  // Expiry time of the session used for cookie max age and garbage collection
}

func (s *Session) Get(key string) interface{} {
	s.UpdateTime = time.Now().UTC()
	return s.KV[key]
}

func (s *Session) Set(key string, value interface{}) {
	s.UpdateTime = time.Now().UTC()
	s.KV[key] = value
}

func (s *Session) Delete(key string) {
	s.UpdateTime = time.Now().UTC()
	delete(s.KV, key)
}

func (s *Session) IsExpired() bool {
	return time.Now().UTC().Unix() > s.ExpiryTime
}

func (s *Session) RenewExpiryTime(expiryTime time.Time) {
	s.ExpiryTime = expiryTime.Unix()
}

type Sessions []*Session

func (s *Sessions) NewRandomSession(expiryTime time.Time) (*Session, error) {
	session, err := NewSession(expiryTime)
	if err != nil {
		return nil, err
	}
	s.AddSession(session)
	return session, nil
}

func (s Sessions) GetSession(uuid string) *Session {
	for _, session := range s {
		if session.Uuid == uuid {
			return session
		}
	}
	return nil
}

func (s *Sessions) AddSession(session *Session) {
	*s = append(*s, session)
}

func (s *Sessions) RemoveSession(session *Session) {
	for i, sess := range *s {
		if sess.Uuid == session.Uuid {
			if i == len(*s)-1 {
				*s = (*s)[:i]
			} else {
				*s = append((*s)[:i], (*s)[i+1:]...)
			}
			break
		}
	}
}

func (s *Sessions) GarbageCollect(ctx context.Context) {
	// Currently not configurable but can be made configurable in future
	ticker := time.NewTicker(time.Minute)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if len(*s) == 0 {
				log.Trace("no sessions to garbage collect")
				continue
			}

			tSessions := make(Sessions, 0, len(*s))
			for _, session := range *s {
				if !session.IsExpired() {
					tSessions = append(tSessions, session)
				}
			}

			if len(*s)-len(tSessions) == 0 {
				continue // No sessions to garbage collect
			}

			log.Tracef("flushed %d sessions", len(*s)-len(tSessions))
			*s = tSessions
		}
	}
}
