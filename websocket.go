package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const wsPingTimeout = 120 * time.Second
const wsWriteTimeout = 5 * time.Second

// isWebSocketUpgrade возвращает true если запрос является WebSocket upgrade.
func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

// writeWSError отправляет клиенту JSON ошибку и закрывает соединение.
func writeWSError(conn *websocket.Conn, msg string) {
	data, _ := json.Marshal(map[string]string{"error": msg})
	_ = conn.WriteMessage(websocket.TextMessage, data)
	_ = conn.Close()
}

// forwardHeaders копирует заголовки клиента для dial на бэкенд.
// Исключает заголовки, которые gorilla управляет сама.
func forwardHeaders(h http.Header) http.Header {
	skip := map[string]bool{
		"Upgrade":               true,
		"Connection":            true,
		"Sec-Websocket-Key":     true,
		"Sec-Websocket-Version": true,
		"Sec-Websocket-Extensions": true,
	}
	out := make(http.Header)
	for k, v := range h {
		if !skip[k] {
			out[k] = v
		}
	}
	return out
}

// decryptAPIRequest строит EncryptedPacket из APIRequest и вызывает sess.Decrypt.
func decryptAPIRequest(sess *RatchetSession, req *APIRequest) ([]byte, error) {
	pkt := &EncryptedPacket{
		Header:     req.Header,
		Ciphertext: req.Ciphertext,
		Nonce:      req.Nonce,
		Tag:        req.Tag,
	}
	return sess.Decrypt(pkt)
}

// setReadDeadline устанавливает дедлайн на чтение с учётом таймаута.
func setReadDeadline(conn *websocket.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(wsPingTimeout))
}

// ── Plain WebSocket ───────────────────────────────────────────────────────────

// handlePlainWS прозрачно туннелирует WebSocket соединение на бэкенд.
func (h *ProxyHandler) handlePlainWS(w http.ResponseWriter, r *http.Request) {
	clientConn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[ws-plain] upgrade error: %v", err)
		return
	}
	defer clientConn.Close()

	backendURL := h.cfg.BackendWSURL() + r.RequestURI
	backendConn, _, err := websocket.DefaultDialer.DialContext(r.Context(), backendURL, forwardHeaders(r.Header))
	if err != nil {
		log.Printf("[ws-plain] dial backend error: %v", err)
		writeWSError(clientConn, "backend unavailable")
		return
	}
	defer backendConn.Close()

	log.Printf("[ws-plain] %s → %s", r.RemoteAddr, backendURL)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	var once sync.Once
	closeAll := func() { once.Do(cancel) }

	// Client → Backend
	go func() {
		defer closeAll()
		setReadDeadline(clientConn)
		clientConn.SetPingHandler(func(data string) error {
			setReadDeadline(clientConn)
			return clientConn.WriteControl(websocket.PongMessage, []byte(data), time.Now().Add(wsWriteTimeout))
		})
		for {
			msgType, msg, err := clientConn.ReadMessage()
			if err != nil {
				return
			}
			setReadDeadline(clientConn)
			if err := backendConn.WriteMessage(msgType, msg); err != nil {
				return
			}
		}
	}()

	// Backend → Client
	go func() {
		defer closeAll()
		for {
			msgType, msg, err := backendConn.ReadMessage()
			if err != nil {
				return
			}
			if err := clientConn.WriteMessage(msgType, msg); err != nil {
				return
			}
		}
	}()

	<-ctx.Done()
}

// ── Encrypted WebSocket ───────────────────────────────────────────────────────

// handleEncryptedWS шифрует/расшифровывает WebSocket фреймы через Double Ratchet.
//
// Протокол:
//  1. Клиент предварительно вызывает GET /ratchet/init (HTTP) и получает sessionId.
//  2. Клиент подключается к WS с заголовком X-Session-ID.
//  3. Первый фрейм: APIRequest JSON с ecdhPublicKey (инит сессии).
//  4. Последующие фреймы: APIRequest JSON (без ecdhPublicKey).
//  5. Сервер → клиент: EncryptedPacket JSON.
func (h *ProxyHandler) handleEncryptedWS(w http.ResponseWriter, r *http.Request) {
	sid := r.Header.Get("X-Session-ID")
	if sid == "" {
		http.Error(w, `{"error":"X-Session-ID header required"}`, http.StatusBadRequest)
		return
	}

	clientConn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[ws-enc] upgrade error: %v", err)
		return
	}
	defer clientConn.Close()

	// Читаем первый фрейм (инит сессии)
	_, raw, err := clientConn.ReadMessage()
	if err != nil {
		log.Printf("[ws-enc] read init msg: %v", err)
		return
	}
	var initReq APIRequest
	if err := json.Unmarshal(raw, &initReq); err != nil {
		writeWSError(clientConn, "invalid init JSON")
		return
	}

	// Получаем или создаём сессию
	sess, ok := h.store.Get(sid)
	if !ok {
		if initReq.ECDHPublicKey == "" {
			writeWSError(clientConn, "ecdhPublicKey required for first message")
			return
		}
		sess, err = h.initSession(initReq.ECDHPublicKey)
		if err != nil {
			log.Printf("[ws-enc] session init error: %v", err)
			writeWSError(clientConn, "handshake failed")
			return
		}
		h.store.Set(sid, sess)
	}

	// Расшифровываем первый фрейм
	firstPlain, err := decryptAPIRequest(sess, &initReq)
	if err != nil {
		log.Printf("[ws-enc] decrypt init: %v", err)
		writeWSError(clientConn, "decryption failed")
		return
	}

	// Подключаемся к бэкенду
	backendURL := h.cfg.BackendWSURL() + r.RequestURI
	backendConn, _, err := websocket.DefaultDialer.DialContext(r.Context(), backendURL, nil)
	if err != nil {
		log.Printf("[ws-enc] dial backend error: %v", err)
		writeWSError(clientConn, "backend unavailable")
		return
	}
	defer backendConn.Close()

	log.Printf("[ws-enc] session %s | %s → %s", sid[:8], r.RemoteAddr, backendURL)

	// Отправляем первое расшифрованное сообщение на бэкенд
	if err := backendConn.WriteMessage(websocket.TextMessage, firstPlain); err != nil {
		log.Printf("[ws-enc] write first msg to backend: %v", err)
		return
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	var once sync.Once
	closeAll := func() { once.Do(cancel) }

	// Client → Backend: расшифровываем и пересылаем
	go func() {
		defer closeAll()
		setReadDeadline(clientConn)
		clientConn.SetPingHandler(func(data string) error {
			setReadDeadline(clientConn)
			return clientConn.WriteControl(websocket.PongMessage, []byte(data), time.Now().Add(wsWriteTimeout))
		})
		for {
			_, raw, err := clientConn.ReadMessage()
			if err != nil {
				return
			}
			setReadDeadline(clientConn)
			var req APIRequest
			if err := json.Unmarshal(raw, &req); err != nil {
				log.Printf("[ws-enc] bad client frame: %v", err)
				return
			}
			plain, err := decryptAPIRequest(sess, &req)
			if err != nil {
				log.Printf("[ws-enc] decrypt: %v", err)
				return
			}
			if err := backendConn.WriteMessage(websocket.TextMessage, plain); err != nil {
				return
			}
		}
	}()

	// Backend → Client: шифруем и пересылаем
	go func() {
		defer closeAll()
		for {
			msgType, msg, err := backendConn.ReadMessage()
			if err != nil {
				return
			}
			pkt, err := sess.Encrypt(msg)
			if err != nil {
				log.Printf("[ws-enc] encrypt: %v", err)
				return
			}
			out, _ := json.Marshal(pkt)
			_ = msgType // всегда отправляем как текст (JSON)
			if err := clientConn.WriteMessage(websocket.TextMessage, out); err != nil {
				return
			}
		}
	}()

	<-ctx.Done()

	closeMsg := websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")
	_ = clientConn.WriteControl(websocket.CloseMessage, closeMsg, time.Now().Add(wsWriteTimeout))
}

