package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func newTestHandlerWithCfg(t *testing.T, cfg *Config) *ProxyHandler {
	t.Helper()
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
		cfg.LogLevel = "error"
	}
	if cfg.LogFormat == "" {
		cfg.LogFormat = "text"
	}
	h, err := newProxyHandler(cfg)
	if err != nil {
		t.Fatalf("newProxyHandler: %v", err)
	}
	return h
}

// ── 2.1 WS message size limit ─────────────────────────────────────────────────

func TestWSMessageSizeLimit_Enforced(t *testing.T) {
	// Бэкенд — простой WS эхо-сервер
	backendUpgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := backendUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			mt, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			conn.WriteMessage(mt, msg)
		}
	}))
	defer backend.Close()

	cfg := &Config{
		Backend:           strings.Replace(backend.URL, "http://", "ws://", 1),
		WSMaxMessageBytes: 10, // лимит 10 байт
		Routes:            []RouteRule{{Path: "/ws", Mode: "plain"}},
	}
	h := newTestHandlerWithCfg(t, cfg)
	srv := httptest.NewServer(h)
	defer srv.Close()

	wsURL := strings.Replace(srv.URL, "http://", "ws://", 1) + "/ws"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Отправляем сообщение > 10 байт
	big := strings.Repeat("x", 100)
	conn.WriteMessage(websocket.TextMessage, []byte(big))

	// Следующее чтение должно вернуть ошибку (соединение закрыто)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _, err = conn.ReadMessage()
	if err == nil {
		t.Fatal("ожидаем ошибку после превышения лимита размера сообщения")
	}
}

func TestWSMessageSizeLimit_Allowed(t *testing.T) {
	backendUpgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := backendUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		mt, msg, err := conn.ReadMessage()
		if err != nil {
			return
		}
		conn.WriteMessage(mt, msg)
	}))
	defer backend.Close()

	cfg := &Config{
		Backend:           strings.Replace(backend.URL, "http://", "ws://", 1),
		WSMaxMessageBytes: 1024,
		Routes:            []RouteRule{{Path: "/ws", Mode: "plain"}},
	}
	h := newTestHandlerWithCfg(t, cfg)
	srv := httptest.NewServer(h)
	defer srv.Close()

	wsURL := strings.Replace(srv.URL, "http://", "ws://", 1) + "/ws"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	msg := []byte("hello")
	conn.WriteMessage(websocket.TextMessage, msg)

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, got, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if string(got) != string(msg) {
		t.Errorf("got %q, want %q", got, msg)
	}
}

// ── 2.2 Origin whitelist ──────────────────────────────────────────────────────

func TestOriginCheck_EmptyList_AllowsAll(t *testing.T) {
	cfg := &Config{AllowedOrigins: nil}
	u := buildUpgrader(cfg)
	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	if !u.CheckOrigin(req) {
		t.Error("пустой список должен разрешать любой origin")
	}
}

func TestOriginCheck_AllowedOrigin(t *testing.T) {
	cfg := &Config{AllowedOrigins: []string{"https://app.example.com"}}
	u := buildUpgrader(cfg)

	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	req.Header.Set("Origin", "https://app.example.com")
	if !u.CheckOrigin(req) {
		t.Error("разрешённый origin должен проходить")
	}
}

func TestOriginCheck_DeniedOrigin(t *testing.T) {
	cfg := &Config{AllowedOrigins: []string{"https://app.example.com"}}
	u := buildUpgrader(cfg)

	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	if u.CheckOrigin(req) {
		t.Error("неразрешённый origin должен блокироваться")
	}
}

func TestOriginCheck_Wildcard(t *testing.T) {
	cfg := &Config{AllowedOrigins: []string{"*"}}
	u := buildUpgrader(cfg)

	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	req.Header.Set("Origin", "https://any.example.com")
	if !u.CheckOrigin(req) {
		t.Error("wildcard * должен разрешать любой origin")
	}
}
