package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// proxyMetrics хранит все Prometheus метрики прокси.
type proxyMetrics struct {
	requestsTotal    *prometheus.CounterVec
	requestDuration  *prometheus.HistogramVec
	decryptErrors    prometheus.Counter
	encryptErrors    prometheus.Counter
	activeSessions   prometheus.Gauge
	activeWSConns    prometheus.Gauge
	rateLimitRejects prometheus.Counter
}

// newMetrics регистрирует метрики в переданном registerer.
// Использование отдельного registerer позволяет изолировать тесты.
func newMetrics(reg prometheus.Registerer) *proxyMetrics {
	factory := promauto.With(reg)
	return &proxyMetrics{
		requestsTotal: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "proxy_requests_total",
			Help: "Общее количество запросов по пути, методу и статусу.",
		}, []string{"path", "method", "status"}),

		requestDuration: factory.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "proxy_request_duration_seconds",
			Help:    "Время обработки запроса в секундах.",
			Buckets: prometheus.DefBuckets,
		}, []string{"path"}),

		decryptErrors: factory.NewCounter(prometheus.CounterOpts{
			Name: "proxy_decrypt_errors_total",
			Help: "Количество ошибок расшифровки.",
		}),

		encryptErrors: factory.NewCounter(prometheus.CounterOpts{
			Name: "proxy_encrypt_errors_total",
			Help: "Количество ошибок шифрования.",
		}),

		activeSessions: factory.NewGauge(prometheus.GaugeOpts{
			Name: "proxy_active_sessions",
			Help: "Текущее количество активных сессий.",
		}),

		activeWSConns: factory.NewGauge(prometheus.GaugeOpts{
			Name: "proxy_active_ws_connections",
			Help: "Текущее количество активных WebSocket соединений.",
		}),

		rateLimitRejects: factory.NewCounter(prometheus.CounterOpts{
			Name: "proxy_ratelimit_rejected_total",
			Help: "Количество запросов отклонённых rate limiter'ом.",
		}),
	}
}
