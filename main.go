package main

import (
	"context"
	"flag"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	cfgPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("Config error: %v", err)
	}

	initLogger(cfg.LogLevel, cfg.LogFormat)

	handler, err := newProxyHandler(cfg)
	if err != nil {
		slog.Error("init failed", "err", err)
		os.Exit(1)
	}

	srv := &http.Server{
		Addr:         cfg.Listen,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Hot reload on SIGHUP
	reload := make(chan os.Signal, 1)
	signal.Notify(reload, syscall.SIGHUP)
	go func() {
		for range reload {
			slog.Info("SIGHUP received, reloading config")
			if err := handler.reloadConfig(*cfgPath); err != nil {
				slog.Error("reload failed", "err", err)
			}
		}
	}()

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		slog.Info("proxy started", "listen", cfg.Listen, "backend", cfg.Backend, "init_path", cfg.InitPath, "tls", cfg.TLSCert != "")
		printRoutes(cfg)
		var err error
		if cfg.TLSCert != "" && cfg.TLSKey != "" {
			err = srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
		} else {
			err = srv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "err", err)
			os.Exit(1)
		}
	}()

	<-stop
	slog.Info("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("shutdown error", "err", err)
	}

	// Ждём завершения всех WebSocket соединений (до 30 секунд)
	wsDone := make(chan struct{})
	go func() {
		handler.WaitWS()
		close(wsDone)
	}()
	select {
	case <-wsDone:
	case <-time.After(30 * time.Second):
		slog.Warn("ws connections did not finish in time")
	}
	slog.Info("stopped")
}

func printRoutes(cfg *Config) {
	for _, r := range cfg.Routes {
		methods := "*"
		if len(r.Methods) > 0 {
			methods = strings.Join(r.Methods, ",")
		}
		slog.Info("route", "mode", r.Mode, "methods", methods, "path", r.Path)
	}
}
