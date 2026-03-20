package main

import (
	"os"
	"testing"
)

func TestExpandEnv_Simple(t *testing.T) {
	t.Setenv("TEST_PORT", "8080")
	out := expandEnv([]byte("listen: ${TEST_PORT}"))
	if string(out) != "listen: 8080" {
		t.Errorf("got %q, want %q", out, "listen: 8080")
	}
}

func TestExpandEnv_WithDefault_Unset(t *testing.T) {
	os.Unsetenv("TEST_UNSET_VAR")
	out := expandEnv([]byte("listen: ${TEST_UNSET_VAR:-9090}"))
	if string(out) != "listen: 9090" {
		t.Errorf("got %q, want %q", out, "listen: 9090")
	}
}

func TestExpandEnv_WithDefault_Set(t *testing.T) {
	t.Setenv("TEST_OVERRIDE", "3000")
	out := expandEnv([]byte("listen: ${TEST_OVERRIDE:-9090}"))
	if string(out) != "listen: 3000" {
		t.Errorf("got %q, want %q", out, "listen: 3000")
	}
}

func TestExpandEnv_MultipleVars(t *testing.T) {
	t.Setenv("TEST_HOST", "example.com")
	t.Setenv("TEST_PORT2", "443")
	out := expandEnv([]byte("backend: https://${TEST_HOST}:${TEST_PORT2}"))
	want := "backend: https://example.com:443"
	if string(out) != want {
		t.Errorf("got %q, want %q", out, want)
	}
}

func TestExpandEnv_NoVars(t *testing.T) {
	input := []byte("listen: :8080")
	out := expandEnv(input)
	if string(out) != string(input) {
		t.Errorf("без переменных вывод не должен меняться: got %q", out)
	}
}

func TestLoadConfig_EnvExpansion(t *testing.T) {
	t.Setenv("TEST_BACKEND", "http://mybackend:9000")

	yaml := `
backend: ${TEST_BACKEND}
session_ttl: 1h
routes:
  - path: /api/
    mode: encrypt
`
	f, err := os.CreateTemp("", "config*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(yaml)
	f.Close()

	cfg, err := loadConfig(f.Name())
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.Backend != "http://mybackend:9000" {
		t.Errorf("Backend = %q, want %q", cfg.Backend, "http://mybackend:9000")
	}
}

func TestHotReload_UpdatesRoutes(t *testing.T) {
	yaml1 := `
backend: http://127.0.0.1:19999
routes:
  - path: /old-path
    mode: plain
`
	f, err := os.CreateTemp("", "cfg*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(yaml1)
	f.Close()

	cfg, err := loadConfig(f.Name())
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	h, err := newProxyHandler(cfg)
	if err != nil {
		t.Fatalf("newProxyHandler: %v", err)
	}

	// До reload: /old-path матчится, /new-path — нет
	if h.cfg.Load().matchRoute("/old-path", "GET") == nil {
		t.Error("до reload /old-path должен матчиться")
	}
	if h.cfg.Load().matchRoute("/new-path", "GET") != nil {
		t.Error("до reload /new-path не должен матчиться")
	}

	// Перезаписываем файл с новым маршрутом
	yaml2 := `
backend: http://127.0.0.1:19999
routes:
  - path: /new-path
    mode: plain
`
	if err := os.WriteFile(f.Name(), []byte(yaml2), 0644); err != nil {
		t.Fatal(err)
	}

	if err := h.reloadConfig(f.Name()); err != nil {
		t.Fatalf("reloadConfig: %v", err)
	}

	// После reload: /new-path матчится, /old-path — нет
	if h.cfg.Load().matchRoute("/new-path", "GET") == nil {
		t.Error("после reload /new-path должен матчиться")
	}
	if h.cfg.Load().matchRoute("/old-path", "GET") != nil {
		t.Error("после reload /old-path не должен матчиться")
	}
}

func TestHotReload_InvalidYAML_NoChange(t *testing.T) {
	yaml1 := `
backend: http://127.0.0.1:19999
routes:
  - path: /api/
    mode: encrypt
`
	f, err := os.CreateTemp("", "cfg*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(yaml1)
	f.Close()

	cfg, err := loadConfig(f.Name())
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	h, err := newProxyHandler(cfg)
	if err != nil {
		t.Fatalf("newProxyHandler: %v", err)
	}

	// Перезаписываем файл YAML с невалидным значением mode (не проходит validate())
	badYAML := `
backend: http://127.0.0.1:19999
routes:
  - path: /api/
    mode: bad-mode
`
	if err := os.WriteFile(f.Name(), []byte(badYAML), 0644); err != nil {
		t.Fatal(err)
	}

	err = h.reloadConfig(f.Name())
	if err == nil {
		t.Fatal("reloadConfig с невалидным YAML должен вернуть ошибку")
	}

	// Старый конфиг не изменился
	if h.cfg.Load().matchRoute("/api/", "GET") == nil {
		t.Error("после неудачного reload /api/ должен матчиться (старый конфиг)")
	}
}
