package main

import (
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimitConfig — настройки rate limiting из конфига.
type RateLimitConfig struct {
	Enabled bool    `yaml:"enabled"`
	RPS     float64 `yaml:"rps"`   // запросов в секунду с одного IP
	Burst   int     `yaml:"burst"` // пиковый запас
}

// IPRateLimiter — токен-бакет rate limiter с ограничением по IP.
type IPRateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*ipEntry
	rps      rate.Limit
	burst    int
	ttl      time.Duration
}

type ipEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// newIPRateLimiter создаёт новый IPRateLimiter с фоновой очисткой устаревших IP.
func newIPRateLimiter(rps float64, burst int) *IPRateLimiter {
	rl := &IPRateLimiter{
		limiters: make(map[string]*ipEntry),
		rps:      rate.Limit(rps),
		burst:    burst,
		ttl:      10 * time.Minute,
	}
	go rl.cleanupLoop()
	return rl
}

// Allow возвращает true если запрос с данного IP разрешён.
func (rl *IPRateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	e, ok := rl.limiters[ip]
	if !ok {
		e = &ipEntry{limiter: rate.NewLimiter(rl.rps, rl.burst)}
		rl.limiters[ip] = e
	}
	e.lastSeen = time.Now()
	allowed := e.limiter.Allow()
	rl.mu.Unlock()
	return allowed
}

func (rl *IPRateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.ttl / 2)
	defer ticker.Stop()
	for range ticker.C {
		deadline := time.Now().Add(-rl.ttl)
		rl.mu.Lock()
		for ip, e := range rl.limiters {
			if e.lastSeen.Before(deadline) {
				delete(rl.limiters, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// clientIP извлекает IP-адрес клиента из запроса.
func clientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		// берём первый IP из списка
		for i := 0; i < len(ip); i++ {
			if ip[i] == ',' {
				return ip[:i]
			}
		}
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
