package main

import (
	"errors"
	"testing"
	"time"
)

func TestSessionStore_Count(t *testing.T) {
	s := newSessionStore(time.Hour)
	if s.Count() != 0 {
		t.Fatalf("Count() = %d, want 0", s.Count())
	}
	_ = s.Set("a", newRatchetSession())
	_ = s.Set("b", newRatchetSession())
	if s.Count() != 2 {
		t.Fatalf("Count() = %d, want 2", s.Count())
	}
	s.Delete("a")
	if s.Count() != 1 {
		t.Fatalf("Count() = %d, want 1 после Delete", s.Count())
	}
}

func TestSessionStore_MaxSessions_Enforced(t *testing.T) {
	s := newSessionStoreWithMax(time.Hour, 2)

	if err := s.Set("s1", newRatchetSession()); err != nil {
		t.Fatalf("Set s1: %v", err)
	}
	if err := s.Set("s2", newRatchetSession()); err != nil {
		t.Fatalf("Set s2: %v", err)
	}
	// 3-я новая сессия должна вернуть ошибку
	err := s.Set("s3", newRatchetSession())
	if !errors.Is(err, ErrSessionLimitReached) {
		t.Fatalf("ожидаем ErrSessionLimitReached, получили: %v", err)
	}
}

func TestSessionStore_MaxSessions_UpdateAllowed(t *testing.T) {
	s := newSessionStoreWithMax(time.Hour, 1)
	_ = s.Set("s1", newRatchetSession())
	// Обновление существующей сессии должно проходить даже при лимите
	if err := s.Set("s1", newRatchetSession()); err != nil {
		t.Fatalf("обновление существующей сессии: %v", err)
	}
}

func TestSessionStore_MaxSessions_Zero(t *testing.T) {
	s := newSessionStoreWithMax(time.Hour, 0) // 0 = без лимита
	for i := range 100 {
		id := string(rune('a' + i))
		if err := s.Set(id, newRatchetSession()); err != nil {
			t.Fatalf("Set %s: %v", id, err)
		}
	}
	if s.Count() != 100 {
		t.Fatalf("Count() = %d, want 100", s.Count())
	}
}
