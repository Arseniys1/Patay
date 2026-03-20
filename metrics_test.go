package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func counterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		t.Fatalf("counter.Write: %v", err)
	}
	return m.Counter.GetValue()
}

func gaugeValue(t *testing.T, g prometheus.Gauge) float64 {
	t.Helper()
	var m dto.Metric
	if err := g.Write(&m); err != nil {
		t.Fatalf("gauge.Write: %v", err)
	}
	return m.Gauge.GetValue()
}

func TestMetrics_DecryptErrorCounter(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetrics(reg)

	before := counterValue(t, m.decryptErrors)
	m.decryptErrors.Inc()
	after := counterValue(t, m.decryptErrors)

	if after-before != 1 {
		t.Errorf("decryptErrors: delta = %v, want 1", after-before)
	}
}

func TestMetrics_ActiveSessionsGauge(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetrics(reg)

	m.activeSessions.Set(5)
	if v := gaugeValue(t, m.activeSessions); v != 5 {
		t.Errorf("activeSessions = %v, want 5", v)
	}
	m.activeSessions.Set(3)
	if v := gaugeValue(t, m.activeSessions); v != 3 {
		t.Errorf("activeSessions = %v, want 3", v)
	}
}

func TestMetrics_RateLimitRejectCounter(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetrics(reg)

	m.rateLimitRejects.Inc()
	m.rateLimitRejects.Inc()
	if v := counterValue(t, m.rateLimitRejects); v != 2 {
		t.Errorf("rateLimitRejects = %v, want 2", v)
	}
}

func TestMetrics_Endpoint(t *testing.T) {
	cfg := &Config{
		Backend:     "http://127.0.0.1:19999",
		SessionTTL:  time.Hour,
		InitPath:    "/ratchet/init",
		APIPath:     "/ratchet/api",
		HealthPath:  "/health",
		MetricsPath: "/metrics",
		LogLevel:    "error",
		LogFormat:   "text",
	}
	h, err := newProxyHandler(cfg)
	if err != nil {
		t.Fatalf("newProxyHandler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body, _ := io.ReadAll(w.Body)
	if !strings.Contains(string(body), "proxy_active_sessions") {
		t.Error("ответ /metrics должен содержать proxy_active_sessions")
	}
	if !strings.Contains(string(body), "proxy_decrypt_errors_total") {
		t.Error("ответ /metrics должен содержать proxy_decrypt_errors_total")
	}
}
