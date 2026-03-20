package main

import (
	"errors"
	"sync"
	"time"
)

// CBState — состояние circuit breaker.
type CBState int

const (
	CBClosed   CBState = iota // запросы проходят
	CBOpen                    // запросы блокируются
	CBHalfOpen                // один пробный запрос разрешён
)

// ErrCircuitOpen возвращается когда circuit breaker открыт.
var ErrCircuitOpen = errors.New("backend circuit open")

// CircuitBreakerConfig — настройки circuit breaker из конфига.
type CircuitBreakerConfig struct {
	Enabled   bool          `yaml:"enabled"`
	Threshold int           `yaml:"threshold"` // ошибок подряд → Open
	Timeout   time.Duration `yaml:"timeout"`   // через timeout → HalfOpen
}

// CircuitBreaker реализует паттерн Circuit Breaker.
type CircuitBreaker struct {
	mu        sync.Mutex
	state     CBState
	failures  int
	threshold int
	timeout   time.Duration
	openedAt  time.Time
}

func newCircuitBreaker(threshold int, timeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		state:     CBClosed,
		threshold: threshold,
		timeout:   timeout,
	}
}

// State возвращает текущее состояние (потокобезопасно).
func (cb *CircuitBreaker) State() CBState {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.tryTransition()
	return cb.state
}

// Allow возвращает true если запрос разрешён.
func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.tryTransition()
	return cb.state != CBOpen
}

// RecordSuccess регистрирует успешный запрос.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures = 0
	cb.state = CBClosed
}

// RecordFailure регистрирует ошибку.
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures++
	if cb.state == CBHalfOpen || cb.failures >= cb.threshold {
		cb.state = CBOpen
		cb.openedAt = time.Now()
	}
}

// tryTransition проверяет не пора ли перейти из Open в HalfOpen.
// Должен вызываться под блокировкой.
func (cb *CircuitBreaker) tryTransition() {
	if cb.state == CBOpen && time.Since(cb.openedAt) >= cb.timeout {
		cb.state = CBHalfOpen
	}
}
