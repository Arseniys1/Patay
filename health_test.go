package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestHandler(t *testing.T) *ProxyHandler {
	t.Helper()
	cfg := &Config{
		Listen:     ":0",
		Backend:    "http://127.0.0.1:19999",
		SessionTTL: time.Hour,
		InitPath:   "/ratchet/init",
		APIPath:    "/ratchet/api",
		HealthPath: "/health",
		LogLevel:   "error",
		LogFormat:  "text",
	}
	h, err := newProxyHandler(cfg)
	if err != nil {
		t.Fatalf("newProxyHandler: %v", err)
	}
	return h
}

func TestHealth_Returns200(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if ct == "" {
		t.Error("Content-Type не установлен")
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("невалидный JSON: %v", err)
	}
	if resp["status"] != "ok" {
		t.Errorf("status = %v, want ok", resp["status"])
	}
	if _, ok := resp["uptime"]; !ok {
		t.Error("поле uptime отсутствует")
	}
}

func TestHealth_SessionCount(t *testing.T) {
	h := newTestHandler(t)

	// Создаём 2 сессии вручную
	h.store.Set("sess1", newRatchetSession())
	h.store.Set("sess2", newRatchetSession())

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("невалидный JSON: %v", err)
	}
	// JSON числа декодируются как float64
	sessions := resp["sessions"].(float64)
	if int(sessions) != 2 {
		t.Errorf("sessions = %v, want 2", sessions)
	}
}

func TestHealth_NotProxiedToBackend(t *testing.T) {
	backendCalled := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := &Config{
		Backend:    backend.URL,
		SessionTTL: time.Hour,
		InitPath:   "/ratchet/init",
		APIPath:    "/ratchet/api",
		HealthPath: "/health",
		LogLevel:   "error",
		LogFormat:  "text",
	}
	h, err := newProxyHandler(cfg)
	if err != nil {
		t.Fatalf("newProxyHandler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if backendCalled {
		t.Error("/health не должен проксироваться на бэкенд")
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}
