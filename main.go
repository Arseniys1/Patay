package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
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

	handler, err := newProxyHandler(cfg)
	if err != nil {
		log.Fatalf("Init error: %v", err)
	}

	srv := &http.Server{
		Addr:         cfg.Listen,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Printf("[proxy] Listening on %s → backend %s", cfg.Listen, cfg.Backend)
		log.Printf("[proxy] Init endpoint: %s", cfg.InitPath)
		printRoutes(cfg)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	<-stop
	log.Println("[proxy] Shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Shutdown error: %v", err)
	}
	log.Println("[proxy] Stopped")
}

func printRoutes(cfg *Config) {
	log.Printf("[proxy] Routes:")
	for _, r := range cfg.Routes {
		methods := "*"
		if len(r.Methods) > 0 {
			methods = ""
			for i, m := range r.Methods {
				if i > 0 {
					methods += ","
				}
				methods += m
			}
		}
		log.Printf("[proxy]   [%s] %-6s  %s", r.Mode, methods, r.Path)
	}
}
