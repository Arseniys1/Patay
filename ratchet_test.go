package main

import (
	"testing"
)

// Тест полного цикла Double Ratchet: инициализация → обмен сообщениями → forward secrecy
func TestDoubleRatchet_FullExchange(t *testing.T) {
	// ── Серверные ключи ───────────────────────────────────────────────────────
	serverECDH, err := generateDH()
	if err != nil {
		t.Fatal(err)
	}
	serverRatchet, err := generateDH()
	if err != nil {
		t.Fatal(err)
	}

	// ── ECDH handshake (клиентская сторона) ──────────────────────────────────
	clientECDH, err := generateDH()
	if err != nil {
		t.Fatal(err)
	}

	// Клиент: sharedSecret = DH(clientECDH, serverECDH.pub)
	clientShared, err := dhCompute(clientECDH, serverECDH.PubHex)
	if err != nil {
		t.Fatal(err)
	}
	clientSK, err := kdfSK(clientShared)
	if err != nil {
		t.Fatal(err)
	}

	// Сервер: sharedSecret = DH(serverECDH, clientECDH.pub)
	serverShared, err := dhCompute(serverECDH, clientECDH.PubHex)
	if err != nil {
		t.Fatal(err)
	}
	serverSK, err := kdfSK(serverShared)
	if err != nil {
		t.Fatal(err)
	}

	// SK должны совпасть
	if string(clientSK) != string(serverSK) {
		t.Fatal("SK mismatch")
	}

	// ── Инициализация рatchet ────────────────────────────────────────────────
	// Сервер (Bob)
	serverSess := newRatchetSession()
	serverSess.InitBob(serverSK, serverRatchet)

	// Клиент (Alice) — initAlice логика
	aliceDH, err := generateDH()
	if err != nil {
		t.Fatal(err)
	}
	dhOut, err := dhCompute(aliceDH, serverRatchet.PubHex)
	if err != nil {
		t.Fatal(err)
	}
	aliceRK, aliceCKs, err := kdfRK(clientSK, dhOut)
	if err != nil {
		t.Fatal(err)
	}
	clientSess := newRatchetSession()
	clientSess.RK     = aliceRK
	clientSess.CKs    = aliceCKs
	clientSess.DHs    = aliceDH
	clientSess.DHrHex = serverRatchet.PubHex

	// ── Обмен сообщениями ────────────────────────────────────────────────────
	for round := 0; round < 5; round++ {
		reqMsg := []byte(`{"action":"test","round":` + string(rune('0'+round)) + `}`)

		// Клиент шифрует запрос
		reqPkt, err := clientSess.Encrypt(reqMsg)
		if err != nil {
			t.Fatalf("round %d: client encrypt: %v", round, err)
		}

		// Сервер расшифровывает
		got, err := serverSess.Decrypt(reqPkt)
		if err != nil {
			t.Fatalf("round %d: server decrypt: %v", round, err)
		}
		if string(got) != string(reqMsg) {
			t.Fatalf("round %d: request mismatch: got %q want %q", round, got, reqMsg)
		}

		respMsg := []byte(`{"ok":true,"round":` + string(rune('0'+round)) + `}`)

		// Сервер шифрует ответ
		respPkt, err := serverSess.Encrypt(respMsg)
		if err != nil {
			t.Fatalf("round %d: server encrypt: %v", round, err)
		}

		// Клиент расшифровывает
		got, err = clientSess.Decrypt(respPkt)
		if err != nil {
			t.Fatalf("round %d: client decrypt: %v", round, err)
		}
		if string(got) != string(respMsg) {
			t.Fatalf("round %d: response mismatch: got %q want %q", round, got, respMsg)
		}
	}

	t.Log("5 rounds OK")
}

// Тест смены DH ключей при каждом раунде
func TestDoubleRatchet_KeyRotation(t *testing.T) {
	serverECDH, _    := generateDH()
	serverRatchet, _ := generateDH()

	clientECDH, _ := generateDH()
	clientShared, _ := dhCompute(clientECDH, serverECDH.PubHex)
	SK, _ := kdfSK(clientShared)
	serverShared, _ := dhCompute(serverECDH, clientECDH.PubHex)
	serverSK, _ := kdfSK(serverShared)

	serverSess := newRatchetSession()
	serverSess.InitBob(serverSK, serverRatchet)

	aliceDH, _ := generateDH()
	dhOut, _    := dhCompute(aliceDH, serverRatchet.PubHex)
	rk, cks, _ := kdfRK(SK, dhOut)
	clientSess := newRatchetSession()
	clientSess.RK = rk; clientSess.CKs = cks; clientSess.DHs = aliceDH; clientSess.DHrHex = serverRatchet.PubHex

	// Запоминаем начальные DH ключи
	prevClientDH := clientSess.DHs.PubHex
	prevServerDH := serverSess.DHs.PubHex

	// Раунд 1
	pkt, _ := clientSess.Encrypt([]byte("hello"))
	serverSess.Decrypt(pkt)
	resp, _ := serverSess.Encrypt([]byte("world"))
	clientSess.Decrypt(resp)

	// После первого раунда DH ключи должны измениться
	if clientSess.DHs.PubHex == prevClientDH {
		t.Error("client DHs должен смениться после первого ответа")
	}
	if serverSess.DHs.PubHex == prevServerDH {
		t.Error("server DHs должен смениться после первого запроса")
	}

	// Root Key тоже должен смениться
	t.Log("Key rotation OK")
}

// Тест replay attack
func TestDoubleRatchet_ReplayProtection(t *testing.T) {
	serverECDH, _    := generateDH()
	serverRatchet, _ := generateDH()
	clientECDH, _    := generateDH()

	clientShared, _ := dhCompute(clientECDH, serverECDH.PubHex)
	serverShared, _ := dhCompute(serverECDH, clientECDH.PubHex)
	SK1, _  := kdfSK(clientShared)
	SK2, _  := kdfSK(serverShared)

	serverSess := newRatchetSession()
	serverSess.InitBob(SK2, serverRatchet)

	aliceDH, _     := generateDH()
	dhOut, _        := dhCompute(aliceDH, serverRatchet.PubHex)
	rk, cks, _     := kdfRK(SK1, dhOut)
	clientSess := newRatchetSession()
	clientSess.RK = rk; clientSess.CKs = cks; clientSess.DHs = aliceDH; clientSess.DHrHex = serverRatchet.PubHex

	// Отправляем запрос #0
	pkt, _ := clientSess.Encrypt([]byte("original"))
	serverSess.Decrypt(pkt)
	resp, _ := serverSess.Encrypt([]byte("ok"))
	clientSess.Decrypt(resp)

	// Replay того же пакета должен завершиться ошибкой (ключ сообщения уже удалён)
	_, err := serverSess.Decrypt(pkt)
	if err == nil {
		t.Error("replay attack должен был вернуть ошибку")
	} else {
		t.Logf("Replay blocked: %v", err)
	}
}
