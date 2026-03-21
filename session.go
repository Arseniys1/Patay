package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// ErrSessionLimitReached возвращается когда достигнут лимит сессий.
var ErrSessionLimitReached = errors.New("session limit reached")

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
	max     int           // 0 = без лимита
	stop    chan struct{}  // сигнал остановки cleanupLoop
}

func newSessionStore(ttl time.Duration) *SessionStore {
	return newSessionStoreWithMax(ttl, 0)
}

func newSessionStoreWithMax(ttl time.Duration, max int) *SessionStore {
	s := &SessionStore{
		entries: make(map[string]*sessionEntry),
		ttl:     ttl,
		max:     max,
		stop:    make(chan struct{}),
	}
	go s.cleanupLoop()
	return s
}

// Stop останавливает фоновую горутину очистки.
func (s *SessionStore) Stop() {
	close(s.stop)
}

func (s *SessionStore) Get(id string) (*RatchetSession, bool) {
	s.mu.Lock()
	e, ok := s.entries[id]
	if ok {
		e.lastSeen = time.Now()
	}
	s.mu.Unlock()
	if !ok {
		return nil, false
	}
	return e.sess, true
}

// Set сохраняет сессию. Возвращает ErrSessionLimitReached если достигнут лимит.
func (s *SessionStore) Set(id string, sess *RatchetSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.max > 0 && len(s.entries) >= s.max {
		// Разрешаем обновление существующей сессии без проверки лимита
		if _, exists := s.entries[id]; !exists {
			return ErrSessionLimitReached
		}
	}
	s.entries[id] = &sessionEntry{sess: sess, lastSeen: time.Now()}
	return nil
}

func (s *SessionStore) Delete(id string) {
	s.mu.Lock()
	delete(s.entries, id)
	s.mu.Unlock()
}

// Count возвращает текущее количество активных сессий.
func (s *SessionStore) Count() int {
	s.mu.RLock()
	n := len(s.entries)
	s.mu.RUnlock()
	return n
}

// cleanupLoop удаляет истёкшие сессии каждые ttl/2. Завершается при вызове Stop().
func (s *SessionStore) cleanupLoop() {
	ticker := time.NewTicker(s.ttl / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			s.mu.Lock()
			for id, e := range s.entries {
				if now.Sub(e.lastSeen) > s.ttl {
					delete(s.entries, id)
				}
			}
			s.mu.Unlock()
		case <-s.stop:
			return
		}
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
