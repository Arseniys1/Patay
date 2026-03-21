package main

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

var envVarRe = regexp.MustCompile(`\$\{([^}:-]+)(?::-(.*?))?\}`)

// expandEnv заменяет ${VAR} и ${VAR:-default} в YAML-байтах значениями env-переменных.
func expandEnv(data []byte) []byte {
	return envVarRe.ReplaceAllFunc(data, func(match []byte) []byte {
		parts := envVarRe.FindSubmatch(match)
		if len(parts) < 2 {
			return match
		}
		name := string(parts[1])
		val, ok := os.LookupEnv(name)
		if !ok || val == "" {
			if len(parts) == 3 {
				return parts[2] // default value
			}
			return []byte{}
		}
		return []byte(val)
	})
}

// Config — полная конфигурация прокси
type Config struct {
	Listen     string        `yaml:"listen"`      // адрес для входящих соединений, напр. ":8080"
	Backend    string        `yaml:"backend"`     // URL бэкенда, напр. "http://127.0.0.1:80"
	SessionTTL time.Duration `yaml:"session_ttl"` // время жизни сессии, напр. "1h"

	// Маршруты: список правил. Первое совпадение побеждает.
	Routes []RouteRule `yaml:"routes"`

	// Служебные пути прокси (не проксируются на бэкенд)
	InitPath   string `yaml:"init_path"`   // GET /ratchet/init  — по умолчанию "/ratchet/init"
	APIPath    string `yaml:"api_path"`    // POST /ratchet/api  — по умолчанию "/ratchet/api"
	HealthPath string `yaml:"health_path"` // GET /health        — по умолчанию "/health"

	// Логирование
	LogLevel  string `yaml:"log_level"`  // debug|info|warn|error (по умолчанию "info")
	LogFormat string `yaml:"log_format"` // text|json (по умолчанию "text")

	// Rate limiting для /ratchet/init
	RateLimit RateLimitConfig `yaml:"rate_limit"`

	// Максимальное количество одновременных сессий (0 = без лимита)
	MaxSessions int `yaml:"max_sessions"`

	// Максимальный размер WebSocket-сообщения в байтах (0 = без лимита, по умолчанию 65536)
	WSMaxMessageBytes int64 `yaml:"ws_max_message_bytes"`

	// Разрешённые origins для WebSocket (пусто = любой)
	AllowedOrigins []string `yaml:"allowed_origins"`

	// Путь для Prometheus метрик (по умолчанию "/metrics")
	MetricsPath string `yaml:"metrics_path"`

	// TLS (опционально — если задано, сервер запускается как HTTPS)
	TLSCert string `yaml:"tls_cert"` // путь к cert.pem
	TLSKey  string `yaml:"tls_key"`  // путь к key.pem

	// Circuit breaker для бэкенда
	CircuitBreaker CircuitBreakerConfig `yaml:"circuit_breaker"`
}

// RouteRule описывает одно правило маршрутизации
type RouteRule struct {
	// Путь или префикс. Если заканчивается на '/', то prefix match, иначе exact match.
	Path string `yaml:"path"`

	// Режим:
	//   "encrypt"   — запрос расшифровывается, пересылается на бэкенд, ответ шифруется
	//   "plain"     — запрос пересылается на бэкенд как есть (GET страницы, статика)
	Mode string `yaml:"mode"`

	// Методы HTTP которые разрешены (опционально, пусто = все)
	Methods []string `yaml:"methods,omitempty"`
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	data = expandEnv(data)

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	// Дефолтные значения
	if cfg.Listen == "" {
		cfg.Listen = ":8080"
	}
	if cfg.Backend == "" {
		cfg.Backend = "http://127.0.0.1:80"
	}
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = time.Hour
	}
	if cfg.InitPath == "" {
		cfg.InitPath = "/ratchet/init"
	}
	if cfg.APIPath == "" {
		cfg.APIPath = "/ratchet/api"
	}
	if cfg.HealthPath == "" {
		cfg.HealthPath = "/health"
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}
	if cfg.LogFormat == "" {
		cfg.LogFormat = "text"
	}
	if cfg.MetricsPath == "" {
		cfg.MetricsPath = "/metrics"
	}
	if cfg.CircuitBreaker.Threshold == 0 {
		cfg.CircuitBreaker.Threshold = 5
	}
	if cfg.CircuitBreaker.Timeout == 0 {
		cfg.CircuitBreaker.Timeout = 30 * time.Second
	}
	if cfg.WSMaxMessageBytes == 0 {
		cfg.WSMaxMessageBytes = 64 * 1024 // 64 KB
	}
	if cfg.RateLimit.RPS == 0 {
		cfg.RateLimit.RPS = 10
	}
	if cfg.RateLimit.Burst == 0 {
		cfg.RateLimit.Burst = 20
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (cfg *Config) validate() error {
	u, err := url.Parse(cfg.Backend)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("backend must be http:// or https://, got %q", cfg.Backend)
	}
	for i, r := range cfg.Routes {
		if r.Path == "" {
			return fmt.Errorf("routes[%d]: path is empty", i)
		}
		if r.Mode != "encrypt" && r.Mode != "plain" {
			return fmt.Errorf("routes[%d]: mode must be 'encrypt' or 'plain', got %q", i, r.Mode)
		}
	}
	return nil
}

// BackendWSURL возвращает URL бэкенда для WebSocket соединений.
func (cfg *Config) BackendWSURL() string {
	switch {
	case strings.HasPrefix(cfg.Backend, "wss://"), strings.HasPrefix(cfg.Backend, "ws://"):
		return cfg.Backend
	case strings.HasPrefix(cfg.Backend, "https://"):
		return "wss://" + cfg.Backend[len("https://"):]
	default:
		return "ws://" + strings.TrimPrefix(cfg.Backend, "http://")
	}
}

// matchRoute возвращает RouteRule для данного пути/метода, или nil если нет совпадения.
// Первое совпадение побеждает.
func (cfg *Config) matchRoute(path, method string) *RouteRule {
	for i := range cfg.Routes {
		r := &cfg.Routes[i]
		// Path matching
		if strings.HasSuffix(r.Path, "/") {
			if !strings.HasPrefix(path, r.Path) {
				continue
			}
		} else {
			if path != r.Path {
				continue
			}
		}
		// Method matching (пусто = все методы)
		if len(r.Methods) > 0 {
			matched := false
			for _, m := range r.Methods {
				if strings.EqualFold(m, method) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		return r
	}
	return nil
}
