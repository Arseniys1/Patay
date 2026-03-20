package main

import (
	"sync"
	"testing"
	"time"
)

func TestGracefulWSShutdown_WaitsForConnections(t *testing.T) {
	h := newTestHandler(t)

	done := make(chan struct{})
	h.wsWg.Add(1)

	go func() {
		h.WaitWS()
		close(done)
	}()

	// WaitWS должен блокироваться
	select {
	case <-done:
		t.Fatal("WaitWS завершился раньше чем все соединения закрылись")
	case <-time.After(50 * time.Millisecond):
		// ожидаемо — блокируется
	}

	// Освобождаем
	h.wsWg.Done()

	select {
	case <-done:
		// ожидаемо — завершился
	case <-time.After(time.Second):
		t.Fatal("WaitWS не завершился после закрытия всех соединений")
	}
}

func TestGracefulWSShutdown_CompletesWhenDone(t *testing.T) {
	h := newTestHandler(t)

	var wg sync.WaitGroup
	for range 5 {
		h.wsWg.Add(1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer h.wsWg.Done()
			time.Sleep(10 * time.Millisecond)
		}()
	}

	done := make(chan struct{})
	go func() {
		h.WaitWS()
		close(done)
	}()

	wg.Wait()

	select {
	case <-done:
		// ожидаемо
	case <-time.After(time.Second):
		t.Fatal("WaitWS не завершился после закрытия всех 5 соединений")
	}
}
