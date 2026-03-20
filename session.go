package main

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// sessionEntry хранит сессию с меткой последнего обращения
type sessionEntry struct {
	sess     *RatchetSession
	lastSeen time.Time
}

// SessionStore — потокобезопасное хранилище сессий с TTL
type SessionStore struct {
	mu      sync.RWMutex
	entries map[string]*sessionEntry
	ttl     time.Duration
}

func newSessionStore(ttl time.Duration) *SessionStore {
	s := &SessionStore{
		entries: make(map[string]*sessionEntry),
		ttl:     ttl,
	}
	go s.cleanupLoop()
	return s
}

func (s *SessionStore) Get(id string) (*RatchetSession, bool) {
	s.mu.RLock()
	e, ok := s.entries[id]
	s.mu.RUnlock()
	if !ok {
		return nil, false
	}
	// Обновляем lastSeen без полной блокировки (допускаем гонку на метке — некритично)
	e.lastSeen = time.Now()
	return e.sess, true
}

func (s *SessionStore) Set(id string, sess *RatchetSession) {
	s.mu.Lock()
	s.entries[id] = &sessionEntry{sess: sess, lastSeen: time.Now()}
	s.mu.Unlock()
}

func (s *SessionStore) Delete(id string) {
	s.mu.Lock()
	delete(s.entries, id)
	s.mu.Unlock()
}

// cleanupLoop удаляет истёкшие сессии каждые ttl/2
func (s *SessionStore) cleanupLoop() {
	ticker := time.NewTicker(s.ttl / 2)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		s.mu.Lock()
		for id, e := range s.entries {
			if now.Sub(e.lastSeen) > s.ttl {
				delete(s.entries, id)
			}
		}
		s.mu.Unlock()
	}
}

// newSessionID генерирует криптографически случайный ID сессии
func newSessionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
