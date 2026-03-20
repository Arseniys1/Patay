package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiter_AllowsBurst(t *testing.T) {
	rl := newIPRateLimiter(10, 5)
	ip := "192.168.1.1"
	for i := range 5 {
		if !rl.Allow(ip) {
			t.Fatalf("запрос %d должен быть разрешён (burst=5)", i+1)
		}
	}
}

func TestRateLimiter_Blocks(t *testing.T) {
	rl := newIPRateLimiter(10, 5)
	ip := "10.0.0.1"
	for range 5 {
		rl.Allow(ip)
	}
	if rl.Allow(ip) {
		t.Fatal("6-й запрос должен быть заблокирован (burst=5)")
	}
}

func TestRateLimiter_RecoverAfterWait(t *testing.T) {
	// rps=100 чтобы восстановление было быстрым
	rl := newIPRateLimiter(100, 1)
	ip := "10.0.0.2"
	rl.Allow(ip) // использовали burst
	if rl.Allow(ip) {
		t.Fatal("второй запрос должен быть заблокирован")
	}
	time.Sleep(15 * time.Millisecond) // ждём ~1/100 сек
	if !rl.Allow(ip) {
		t.Fatal("после паузы запрос должен быть разрешён")
	}
}

func TestRateLimiter_PerIP(t *testing.T) {
	rl := newIPRateLimiter(10, 1)
	// исчерпываем burst для ip1
	rl.Allow("1.1.1.1")
	if rl.Allow("1.1.1.1") {
		t.Fatal("2-й запрос для ip1 должен быть заблокирован")
	}
	// ip2 должен быть независим
	if !rl.Allow("2.2.2.2") {
		t.Fatal("первый запрос для ip2 должен быть разрешён")
	}
}

func TestHandleInit_RateLimit_429(t *testing.T) {
	cfg := &Config{
		Backend:    "http://127.0.0.1:19999",
		SessionTTL: time.Hour,
		InitPath:   "/ratchet/init",
		APIPath:    "/ratchet/api",
		HealthPath: "/health",
		LogLevel:   "error",
		LogFormat:  "text",
		RateLimit:  RateLimitConfig{Enabled: true, RPS: 100, Burst: 3},
	}
	h, err := newProxyHandler(cfg)
	if err != nil {
		t.Fatalf("newProxyHandler: %v", err)
	}

	// первые 3 запроса проходят
	for i := range 3 {
		req := httptest.NewRequest(http.MethodGet, "/ratchet/init", nil)
		req.RemoteAddr = "5.5.5.5:1234"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code == http.StatusTooManyRequests {
			t.Fatalf("запрос %d не должен быть заблокирован", i+1)
		}
	}

	// 4-й должен получить 429
	req := httptest.NewRequest(http.MethodGet, "/ratchet/init", nil)
	req.RemoteAddr = "5.5.5.5:1234"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("4-й запрос: status = %d, want 429", w.Code)
	}
}

func TestHandleInit_RateLimit_Disabled(t *testing.T) {
	cfg := &Config{
		Backend:    "http://127.0.0.1:19999",
		SessionTTL: time.Hour,
		InitPath:   "/ratchet/init",
		APIPath:    "/ratchet/api",
		HealthPath: "/health",
		LogLevel:   "error",
		LogFormat:  "text",
		RateLimit:  RateLimitConfig{Enabled: false, RPS: 1, Burst: 1},
	}
	h, err := newProxyHandler(cfg)
	if err != nil {
		t.Fatalf("newProxyHandler: %v", err)
	}

	// при disabled лимит не применяется — все запросы проходят
	for i := range 10 {
		req := httptest.NewRequest(http.MethodGet, "/ratchet/init", nil)
		req.RemoteAddr = "6.6.6.6:1234"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code == http.StatusTooManyRequests {
			t.Fatalf("запрос %d заблокирован при disabled rate limit", i+1)
		}
	}
}
