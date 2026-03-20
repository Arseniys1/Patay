package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestLoggerInit_TextFormat(t *testing.T) {
	// не должно паниковать
	initLogger("info", "text")
	slog.Info("test text logger")
}

func TestLoggerInit_JSONFormat(t *testing.T) {
	// не должно паниковать
	initLogger("debug", "json")
	slog.Debug("test json logger")
}

func TestLogLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	logger := newLoggerWithWriter(&buf, slog.LevelWarn, "text")

	logger.Debug("debug msg")
	logger.Info("info msg")
	logger.Warn("warn msg")
	logger.Error("error msg")

	out := buf.String()
	if strings.Contains(out, "debug msg") {
		t.Error("debug message должен быть отфильтрован при level=warn")
	}
	if strings.Contains(out, "info msg") {
		t.Error("info message должен быть отфильтрован при level=warn")
	}
	if !strings.Contains(out, "warn msg") {
		t.Error("warn message должен присутствовать в выводе")
	}
	if !strings.Contains(out, "error msg") {
		t.Error("error message должен присутствовать в выводе")
	}
}

func TestRequestID_RoundTrip(t *testing.T) {
	rid := newRequestID()
	if len(rid) != 16 {
		t.Fatalf("ожидаем 16 hex символов, получили %d: %q", len(rid), rid)
	}

	ctx := withRequestID(t.Context(), rid)
	got := requestIDFromCtx(ctx)
	if got != rid {
		t.Errorf("requestIDFromCtx = %q, want %q", got, rid)
	}
}

func TestRequestID_EmptyContext(t *testing.T) {
	got := requestIDFromCtx(t.Context())
	if got != "" {
		t.Errorf("пустой контекст должен возвращать пустую строку, got %q", got)
	}
}
