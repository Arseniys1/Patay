package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"strings"
)

type ctxKey int

const ctxRequestID ctxKey = 0

// initLogger инициализирует глобальный slog.Logger по конфигу.
func initLogger(level, format string) {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}
	var h slog.Handler
	if strings.ToLower(format) == "json" {
		h = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		h = slog.NewTextHandler(os.Stderr, opts)
	}
	slog.SetDefault(slog.New(h))
}

// newRequestID генерирует случайный 8-байтовый hex идентификатор запроса.
func newRequestID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// withRequestID добавляет request_id в контекст.
func withRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxRequestID, id)
}

// requestIDFromCtx извлекает request_id из контекста.
func requestIDFromCtx(ctx context.Context) string {
	if id, ok := ctx.Value(ctxRequestID).(string); ok {
		return id
	}
	return ""
}

// newLoggerWithWriter создаёт logger с кастомным writer — используется в тестах.
func newLoggerWithWriter(w io.Writer, level slog.Level, format string) *slog.Logger {
	opts := &slog.HandlerOptions{Level: level}
	if strings.ToLower(format) == "json" {
		return slog.New(slog.NewJSONHandler(w, opts))
	}
	return slog.New(slog.NewTextHandler(w, opts))
}
