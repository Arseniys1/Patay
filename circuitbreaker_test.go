package main

import (
	"testing"
	"time"
)

func TestCB_ClosedAllowsRequests(t *testing.T) {
	cb := newCircuitBreaker(3, time.Second)
	if !cb.Allow() {
		t.Fatal("Closed: Allow() должен возвращать true")
	}
	if cb.State() != CBClosed {
		t.Fatalf("начальное состояние = %v, want CBClosed", cb.State())
	}
}

func TestCB_OpenAfterThreshold(t *testing.T) {
	cb := newCircuitBreaker(3, time.Second)
	for i := range 3 {
		cb.RecordFailure()
		if i < 2 && cb.State() == CBOpen {
			t.Fatalf("cb открылся после %d ошибок, ожидаем threshold=3", i+1)
		}
	}
	if cb.State() != CBOpen {
		t.Fatalf("после %d ошибок состояние = %v, want CBOpen", 3, cb.State())
	}
}

func TestCB_OpenRejects(t *testing.T) {
	cb := newCircuitBreaker(1, time.Second)
	cb.RecordFailure()
	if cb.Allow() {
		t.Fatal("Open: Allow() должен возвращать false")
	}
}

func TestCB_HalfOpenAfterTimeout(t *testing.T) {
	cb := newCircuitBreaker(1, 20*time.Millisecond)
	cb.RecordFailure() // → Open
	time.Sleep(30 * time.Millisecond)
	if cb.State() != CBHalfOpen {
		t.Fatalf("после timeout состояние = %v, want CBHalfOpen", cb.State())
	}
	if !cb.Allow() {
		t.Fatal("HalfOpen: Allow() должен возвращать true")
	}
}

func TestCB_ClosedAfterSuccess(t *testing.T) {
	cb := newCircuitBreaker(1, 20*time.Millisecond)
	cb.RecordFailure() // → Open
	time.Sleep(30 * time.Millisecond)
	// Теперь HalfOpen
	cb.RecordSuccess() // → Closed
	if cb.State() != CBClosed {
		t.Fatalf("после успеха в HalfOpen: %v, want CBClosed", cb.State())
	}
}

func TestCB_OpenAfterHalfOpenFail(t *testing.T) {
	cb := newCircuitBreaker(1, 20*time.Millisecond)
	cb.RecordFailure() // → Open
	time.Sleep(30 * time.Millisecond)
	// Теперь HalfOpen
	cb.RecordFailure() // → снова Open
	if cb.State() != CBOpen {
		t.Fatalf("после ошибки в HalfOpen: %v, want CBOpen", cb.State())
	}
}
