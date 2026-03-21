package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// allowedMethods — whitelist допустимых HTTP-методов для проксирования.
var allowedMethods = map[string]bool{
	"GET":     true,
	"POST":    true,
	"PUT":     true,
	"DELETE":  true,
	"PATCH":   true,
	"HEAD":    true,
	"OPTIONS": true,
}

// blockedHeaders — заголовки, которые клиент не должен подменять.
var blockedHeaders = map[string]bool{
	"Host":              true,
	"Authorization":     true,
	"Cookie":            true,
	"Set-Cookie":        true,
	"Connection":        true,
	"Content-Length":    true,
	"Transfer-Encoding": true,
	"X-Forwarded-For":   true,
	"X-Real-Ip":         true, // canonical form of X-Real-IP
}

// ── Wire форматы ──────────────────────────────────────────────────────────────

// InitResponse — ответ на /ratchet/init
type InitResponse struct {
	SessionID        string `json:"sessionId"`
	ECDHPublicKey    string `json:"ecdhPublicKey"`
	RatchetPublicKey string `json:"ratchetPublicKey"`
}

// APIRequest — тело зашифрованного запроса к /ratchet/api
// ecdhPublicKey присутствует только в первом запросе после init
type APIRequest struct {
	ECDHPublicKey string        `json:"ecdhPublicKey,omitempty"`
	Header        MessageHeader `json:"header"`
	Ciphertext    string        `json:"ciphertext"`
	Nonce         string        `json:"nonce"`
	Tag           string        `json:"tag"`
	// Метаданные оригинального запроса (метод, путь, заголовки)
	// клиент шифрует их вместе с телом через поле Body в EncryptedBody
}

// EncryptedBody — структура которую клиент шифрует как plaintext
type EncryptedBody struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"` // base64 или JSON строка
}

// ── Proxy Handler ─────────────────────────────────────────────────────────────

type ProxyHandler struct {
	cfg           atomic.Pointer[Config]
	store         *SessionStore
	serverECDH    *DHKeyPair         // ECDH ключ для начального key agreement
	serverRatchet *DHKeyPair         // DH ключ для инициализации Double Ratchet
	plain         *httputil.ReverseProxy
	client        *http.Client       // HTTP клиент для запросов к бэкенду
	upgrader      websocket.Upgrader // WebSocket upgrader
	startTime     time.Time          // время запуска для /health
	rateLimiter   *IPRateLimiter     // rate limiter для /ratchet/init
	m             *proxyMetrics      // Prometheus метрики
	metricsReg    *prometheus.Registry
	wsWg          sync.WaitGroup     // graceful shutdown WS соединений
	cb            *CircuitBreaker    // circuit breaker для бэкенда
}

// WaitWS ждёт завершения всех активных WebSocket соединений.
func (h *ProxyHandler) WaitWS() {
	h.wsWg.Wait()
}

// statusRecorder оборачивает ResponseWriter для захвата статус-кода.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (sr *statusRecorder) WriteHeader(code int) {
	sr.status = code
	sr.ResponseWriter.WriteHeader(code)
}

func (sr *statusRecorder) Status() int {
	if sr.status == 0 {
		return http.StatusOK
	}
	return sr.status
}

// Hijack реализует http.Hijacker — делегирует к базовому ResponseWriter.
func (sr *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return sr.ResponseWriter.(http.Hijacker).Hijack()
}

func newProxyHandler(cfg *Config) (*ProxyHandler, error) {
	// Генерируем ключи при старте
	serverECDH, err := generateDH()
	if err != nil {
		return nil, fmt.Errorf("generate ECDH key: %w", err)
	}
	serverRatchet, err := generateDH()
	if err != nil {
		return nil, fmt.Errorf("generate ratchet key: %w", err)
	}

	backendURL, err := url.Parse(cfg.Backend)
	if err != nil {
		return nil, fmt.Errorf("invalid backend URL %q: %w", cfg.Backend, err)
	}

	// ReverseProxy для plain маршрутов
	rp := httputil.NewSingleHostReverseProxy(backendURL)

	// HTTP клиент для зашифрованных маршрутов (ручное проксирование)
	transport := &http.Transport{
		MaxIdleConns:        1000,
		MaxIdleConnsPerHost: 200,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
	}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}

	slog.Info("keys ready",
		"ecdh", serverECDH.PubHex[:20],
		"ratchet", serverRatchet.PubHex[:20])

	reg := prometheus.NewRegistry()
	m := newMetrics(reg)

	h := &ProxyHandler{
		store:         newSessionStoreWithMax(cfg.SessionTTL, cfg.MaxSessions),
		serverECDH:    serverECDH,
		serverRatchet: serverRatchet,
		plain:         rp,
		client:        client,
		startTime:     time.Now(),
		rateLimiter:   newIPRateLimiter(cfg.RateLimit.RPS, cfg.RateLimit.Burst),
		upgrader:      buildUpgrader(cfg),
		m:             m,
		metricsReg:    reg,
		cb:            newCircuitBreaker(cfg.CircuitBreaker.Threshold, cfg.CircuitBreaker.Timeout),
	}
	h.cfg.Store(cfg)
	return h, nil
}

func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Генерируем request ID для трассировки
	reqID := newRequestID()
	r = r.WithContext(withRequestID(r.Context(), reqID))
	w.Header().Set("X-Request-ID", reqID)

	// Служебные эндпоинты прокси
	cfg := h.cfg.Load()
	if r.URL.Path == cfg.HealthPath {
		h.handleHealth(w, r)
		return
	}
	if r.URL.Path == cfg.MetricsPath {
		promhttp.HandlerFor(h.metricsReg, promhttp.HandlerOpts{}).ServeHTTP(w, r)
		return
	}
	if r.URL.Path == cfg.InitPath {
		h.handleInit(w, r)
		return
	}
	if r.URL.Path == cfg.APIPath {
		h.handleEncrypted(w, r)
		return
	}

	// Трекинг метрик для всех остальных запросов
	sr := &statusRecorder{ResponseWriter: w}
	start := time.Now()
	defer func() {
		label := metricPath(cfg, r.URL.Path)
		h.m.requestsTotal.WithLabelValues(label, r.Method, strconv.Itoa(sr.Status())).Inc()
		h.m.requestDuration.WithLabelValues(label).Observe(time.Since(start).Seconds())
		h.m.activeSessions.Set(float64(h.store.Count()))
	}()
	w = sr

	// Маршрутизация по конфигу
	rule := cfg.matchRoute(r.URL.Path, r.Method)

	// WebSocket upgrade
	if isWebSocketUpgrade(r) {
		if rule == nil {
			h.handlePlainWS(w, r)
			return
		}
		switch rule.Mode {
		case "encrypt":
			h.handleEncryptedWS(w, r)
		case "plain":
			h.handlePlainWS(w, r)
		}
		return
	}

	if rule == nil {
		// Нет правила — пропускаем как есть на бэкенд
		h.plain.ServeHTTP(w, r)
		return
	}

	switch rule.Mode {
	case "encrypt":
		h.handleEncrypted(w, r)
	case "plain":
		h.plain.ServeHTTP(w, r)
	}
}

// handleHealth отдаёт статус сервера без проксирования на бэкенд.
func (h *ProxyHandler) handleHealth(w http.ResponseWriter, r *http.Request) {
	cbState := "closed"
	if h.cb.State() == CBOpen {
		cbState = "open"
	} else if h.cb.State() == CBHalfOpen {
		cbState = "half-open"
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":          "ok",
		"sessions":        h.store.Count(),
		"uptime":          time.Since(h.startTime).Round(time.Second).String(),
		"circuit_breaker": cbState,
	})
}

// handleInit выдаёт ключи сервера и создаёт слот сессии
func (h *ProxyHandler) handleInit(w http.ResponseWriter, r *http.Request) {
	h.setCORSHeaders(w, r)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if h.cfg.Load().RateLimit.Enabled && !h.rateLimiter.Allow(clientIP(r)) {
		h.m.rateLimitRejects.Inc()
		jsonError(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	sid, err := newSessionID()
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	// Резервируем слот (сессия будет инициализирована при первом зашифрованном запросе)
	h.store.Delete(sid)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(InitResponse{
		SessionID:        sid,
		ECDHPublicKey:    h.serverECDH.PubHex,
		RatchetPublicKey: h.serverRatchet.PubHex,
	})
}

// handleEncrypted: расшифровывает запрос → пересылает на бэкенд → шифрует ответ
func (h *ProxyHandler) handleEncrypted(w http.ResponseWriter, r *http.Request) {
	h.setCORSHeaders(w, r)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Читаем тело (лимит 10 MB)
	raw, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
	if err != nil {
		jsonError(w, "failed to read body", http.StatusBadRequest)
		return
	}

	var req APIRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	// Получаем Session ID из заголовка
	sid := r.Header.Get("X-Session-ID")
	if sid == "" {
		jsonError(w, "X-Session-ID header required", http.StatusBadRequest)
		return
	}

	sess, ok := h.store.Get(sid)

	// Первый запрос — инициализируем рatchet
	if !ok {
		if req.ECDHPublicKey == "" {
			jsonError(w, "ecdhPublicKey required for first request", http.StatusBadRequest)
			return
		}
		sess, err = h.initSession(req.ECDHPublicKey)
		if err != nil {
			slog.Error("session init", "err", err)
			jsonError(w, "handshake failed", http.StatusBadRequest)
			return
		}
		if err := h.store.Set(sid, sess); err != nil {
			jsonError(w, "session limit reached", http.StatusServiceUnavailable)
			return
		}
	}

	// Расшифровываем запрос
	pkt := &EncryptedPacket{
		Header:     req.Header,
		Ciphertext: req.Ciphertext,
		Nonce:      req.Nonce,
		Tag:        req.Tag,
	}
	plaintext, err := sess.Decrypt(pkt)
	if err != nil {
		h.m.decryptErrors.Inc()
		slog.Error("decrypt", "err", err)
		jsonError(w, "decryption failed", http.StatusBadRequest)
		return
	}

	// Разбираем зашифрованный запрос клиента
	var encBody EncryptedBody
	if err := json.Unmarshal(plaintext, &encBody); err != nil {
		jsonError(w, "invalid encrypted payload", http.StatusBadRequest)
		return
	}

	slog.Debug("msg", "request_id", requestIDFromCtx(r.Context()), "n", req.Header.N, "method", encBody.Method, "path", encBody.Path, "dh", req.Header.DH[:16])

	// Пересылаем на бэкенд (с circuit breaker)
	cbEnabled := h.cfg.Load().CircuitBreaker.Enabled
	if cbEnabled && !h.cb.Allow() {
		jsonError(w, "backend circuit open", http.StatusBadGateway)
		return
	}
	backendResp, err := h.forwardToBackend(r, &encBody)
	if err != nil {
		if cbEnabled {
			h.cb.RecordFailure()
		}
		slog.Error("backend", "err", err)
		jsonError(w, "backend error", http.StatusBadGateway)
		return
	}
	if cbEnabled {
		if backendResp.StatusCode >= 500 {
			h.cb.RecordFailure()
		} else {
			h.cb.RecordSuccess()
		}
	}
	defer backendResp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(backendResp.Body, 10<<20))
	if err != nil {
		jsonError(w, "failed to read backend response", http.StatusBadGateway)
		return
	}

	// Оборачиваем ответ бэкенда
	encResp := map[string]interface{}{
		"status":  backendResp.StatusCode,
		"headers": extractHeaders(backendResp.Header),
		"body":    string(respBody),
	}
	encRespJSON, err := json.Marshal(encResp)
	if err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Шифруем ответ
	respPkt, err := sess.Encrypt(encRespJSON)
	if err != nil {
		h.m.encryptErrors.Inc()
		slog.Error("encrypt", "err", err)
		jsonError(w, "encryption failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(respPkt)
}

// initSession вычисляет SK через ECDH и инициализирует RatchetSession
func (h *ProxyHandler) initSession(clientECDHPubHex string) (*RatchetSession, error) {
	sharedSecret, err := dhCompute(h.serverECDH, clientECDHPubHex)
	if err != nil {
		return nil, fmt.Errorf("ECDH compute: %w", err)
	}
	SK, err := kdfSK(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("KDF SK: %w", err)
	}
	sess := newRatchetSession()
	sess.InitBob(SK, h.serverRatchet)
	return sess, nil
}

// forwardToBackend пересылает расшифрованный запрос на бэкенд
func (h *ProxyHandler) forwardToBackend(origReq *http.Request, enc *EncryptedBody) (*http.Response, error) {
	// 1. Валидация метода
	method := strings.ToUpper(enc.Method)
	if method == "" {
		method = origReq.Method
	}
	if !allowedMethods[method] {
		return nil, fmt.Errorf("invalid method: %q", method)
	}

	// 2. Нормализация и валидация пути
	rawPath := enc.Path
	if rawPath == "" {
		rawPath = origReq.URL.RequestURI()
	}
	pathPart := rawPath
	queryPart := ""
	if idx := strings.IndexByte(rawPath, '?'); idx >= 0 {
		pathPart = rawPath[:idx]
		queryPart = rawPath[idx:]
	}
	cleanedPath := path.Clean("/" + strings.TrimPrefix(pathPart, "/"))
	if strings.Contains(cleanedPath, "..") {
		return nil, fmt.Errorf("invalid path: %q", enc.Path)
	}
	backendBase, err := url.Parse(h.cfg.Load().Backend)
	if err != nil {
		return nil, fmt.Errorf("invalid backend URL: %w", err)
	}
	targetURL := backendBase.JoinPath(cleanedPath).String() + queryPart

	var bodyReader io.Reader
	if enc.Body != "" {
		bodyReader = bytes.NewBufferString(enc.Body)
	}

	req, err := http.NewRequestWithContext(origReq.Context(), method, targetURL, bodyReader)
	if err != nil {
		return nil, err
	}

	// 3. Фильтрация заголовков из зашифрованного пакета
	for k, v := range enc.Headers {
		canonical := http.CanonicalHeaderKey(k)
		if blockedHeaders[canonical] {
			continue
		}
		if strings.ContainsAny(v, "\r\n") {
			continue // предотвращаем CRLF injection
		}
		req.Header.Set(canonical, v)
	}
	if req.Header.Get("Content-Type") == "" && enc.Body != "" {
		req.Header.Set("Content-Type", "application/json")
	}

	// 4. Реальный IP клиента (только хост, без порта)
	clientHost, _, splitErr := net.SplitHostPort(origReq.RemoteAddr)
	if splitErr != nil {
		clientHost = origReq.RemoteAddr
	}
	req.Header.Set("X-Forwarded-For", clientHost)
	req.Header.Set("X-Real-IP", clientHost)

	// 5. Propagate request ID
	if reqID := requestIDFromCtx(origReq.Context()); reqID != "" {
		req.Header.Set("X-Request-ID", reqID)
	}

	return h.client.Do(req)
}

// extractHeaders копирует нужные заголовки из ответа бэкенда
func extractHeaders(h http.Header) map[string]string {
	keep := []string{"Content-Type", "X-Request-ID", "Cache-Control", "ETag"}
	out := make(map[string]string, len(keep))
	for _, k := range keep {
		if v := h.Get(k); v != "" {
			out[k] = v
		}
	}
	return out
}

// reloadConfig атомарно заменяет конфиг из файла.
// НЕ перезагружает: Listen, Backend, InitPath (требуют рестарт).
func (h *ProxyHandler) reloadConfig(path string) error {
	newCfg, err := loadConfig(path)
	if err != nil {
		return fmt.Errorf("reload config: %w", err)
	}
	h.cfg.Store(newCfg)
	h.upgrader = buildUpgrader(newCfg)
	slog.Info("config reloaded", "path", path)
	return nil
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	fmt.Fprintf(w, `{"error":%q}`, msg)
}

// setCORSHeaders добавляет CORS-заголовки если origin разрешён конфигом.
func (h *ProxyHandler) setCORSHeaders(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return
	}
	cfg := h.cfg.Load()
	if len(cfg.AllowedOrigins) == 0 {
		return
	}
	for _, allowed := range cfg.AllowedOrigins {
		if allowed == "*" || allowed == origin {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Session-ID")
			return
		}
	}
}

// metricPath нормализует путь запроса до метки метрики (по конфигу маршрутов).
// Предотвращает неограниченную кардинальность time series.
func metricPath(cfg *Config, urlPath string) string {
	for _, r := range cfg.Routes {
		if strings.HasSuffix(r.Path, "/") && strings.HasPrefix(urlPath, r.Path) {
			return r.Path
		}
		if urlPath == r.Path {
			return r.Path
		}
	}
	return "other"
}
