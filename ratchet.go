package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"

	"golang.org/x/crypto/hkdf"
)

const maxSkip = 500

// ── DH хелперы ────────────────────────────────────────────────────────────────

// DHKeyPair хранит пару ключей P-256 и hex-закодированный публичный ключ
type DHKeyPair struct {
	Private *ecdh.PrivateKey
	PubHex  string // uncompressed 65 bytes hex (04 || x || y)
}

func generateDH() (*DHKeyPair, error) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &DHKeyPair{
		Private: priv,
		PubHex:  hex.EncodeToString(priv.PublicKey().Bytes()),
	}, nil
}

// dhCompute вычисляет x-координату общей точки (32 bytes для P-256)
func dhCompute(local *DHKeyPair, remotePubHex string) ([]byte, error) {
	raw, err := hex.DecodeString(remotePubHex)
	if err != nil {
		return nil, fmt.Errorf("dhCompute: invalid hex: %w", err)
	}
	remotePub, err := ecdh.P256().NewPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("dhCompute: invalid public key: %w", err)
	}
	return local.Private.ECDH(remotePub)
}

// ── KDF функции ───────────────────────────────────────────────────────────────

// kdfRK: HKDF(SHA-256, ikm=dhOutput, salt=rootKey, info='DoubleRatchetV1') → [newRK, newCK]
// Идентично JS: hkdfSync('sha256', dhOutput, rootKey, 'DoubleRatchetV1', 64)
func kdfRK(rootKey, dhOutput []byte) (newRK, newCK []byte, err error) {
	h := hkdf.New(sha256.New, dhOutput, rootKey, []byte("DoubleRatchetV1"))
	buf := make([]byte, 64)
	if _, err = io.ReadFull(h, buf); err != nil {
		return
	}
	return buf[:32], buf[32:64], nil
}

// kdfCK: HMAC-SHA256 → [messageKey, nextChainKey]
// Идентично JS: createHmac('sha256', chainKey).update([0x01]).digest()
func kdfCK(chainKey []byte) (messageKey, nextChainKey []byte) {
	mac := hmac.New(sha256.New, chainKey)
	mac.Write([]byte{0x01})
	messageKey = mac.Sum(nil)
	mac.Reset()
	mac.Write([]byte{0x02})
	nextChainKey = mac.Sum(nil)
	return
}

// kdfSK: HKDF для деривации SK из ECDH shared secret
// Идентично JS deriveAESKey / crypto-utils.js
func kdfSK(sharedSecret []byte) ([]byte, error) {
	h := hkdf.New(sha256.New, sharedSecret, []byte("encryptserver-v1"), []byte("aes-key"))
	sk := make([]byte, 32)
	_, err := io.ReadFull(h, sk)
	return sk, err
}

// ── AES-256-GCM ───────────────────────────────────────────────────────────────

func encryptAES(key, plaintext, aad []byte) (ciphertext, nonce, tag []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}
	nonce = make([]byte, gcm.NonceSize()) // 12 bytes
	if _, err = rand.Read(nonce); err != nil {
		return
	}
	sealed := gcm.Seal(nil, nonce, plaintext, aad)
	overhead := gcm.Overhead() // 16 bytes
	ciphertext = sealed[:len(sealed)-overhead]
	tag = sealed[len(sealed)-overhead:]
	return
}

func decryptAES(key, ciphertext, nonce, tag, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	combined := append(ciphertext, tag...) //nolint:gocritic
	return gcm.Open(nil, nonce, combined, aad)
}

// ── Wire форматы ──────────────────────────────────────────────────────────────

// MessageHeader вкладывается в AAD при шифровании (защита от подмены порядка)
type MessageHeader struct {
	DH string `json:"dh"` // hex-публичный ключ отправителя
	PN int    `json:"pn"` // длина предыдущей цепи
	N  int    `json:"n"`  // номер сообщения в текущей цепи
}

// EncryptedPacket — JSON который ходит по сети вместо plain текста
type EncryptedPacket struct {
	Header     MessageHeader `json:"header"`
	Ciphertext string        `json:"ciphertext"` // base64
	Nonce      string        `json:"nonce"`      // base64
	Tag        string        `json:"tag"`        // base64
}

// ── RatchetSession ────────────────────────────────────────────────────────────

// RatchetSession хранит состояние Double Ratchet одной клиентской сессии
type RatchetSession struct {
	mu sync.Mutex

	RK      []byte // Root Key (32 bytes) — обновляется при каждом DH шаге
	CKs     []byte // Sending Chain Key  — ключ отправляющей цепи
	CKr     []byte // Receiving Chain Key — ключ принимающей цепи
	DHs     *DHKeyPair // Текущая DH пара сервера (меняется при каждом DH шаге)
	DHrHex  string     // Последний известный DH ключ клиента
	Ns      int   // Счётчик отправленных сообщений
	Nr      int   // Счётчик принятых сообщений
	PN      int   // Длина предыдущей отправляющей цепи
	Skipped map[string][]byte // "pubHex:N" → messageKey — буфер пропущенных ключей
}

func newRatchetSession() *RatchetSession {
	return &RatchetSession{Skipped: make(map[string][]byte)}
}

// InitBob инициализирует сессию на стороне сервера (Bob в спецификации Signal)
func (s *RatchetSession) InitBob(SK []byte, ratchetKP *DHKeyPair) {
	s.RK     = append([]byte(nil), SK...)
	s.DHs    = ratchetKP
	s.DHrHex = ""
	s.CKs    = nil
	s.CKr    = nil
	s.Ns, s.Nr, s.PN = 0, 0, 0
	s.Skipped = make(map[string][]byte)
}

// Encrypt шифрует payload и продвигает отправляющую цепь
func (s *RatchetSession) Encrypt(plaintext []byte) (*EncryptedPacket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.CKs == nil {
		return nil, fmt.Errorf("ratchet: no sending chain key")
	}

	mk, nextCKs := kdfCK(s.CKs)
	s.CKs = nextCKs
	defer zeroBytes(mk) // Стираем ключ сообщения после использования

	header := MessageHeader{DH: s.DHs.PubHex, PN: s.PN, N: s.Ns}
	s.Ns++

	aad, _ := json.Marshal(header)
	ct, nonce, tag, err := encryptAES(mk, plaintext, aad)
	if err != nil {
		return nil, err
	}

	return &EncryptedPacket{
		Header:     header,
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Tag:        base64.StdEncoding.EncodeToString(tag),
	}, nil
}

// Decrypt расшифровывает входящий пакет и продвигает принимающую цепь
func (s *RatchetSession) Decrypt(pkt *EncryptedPacket) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	header := pkt.Header
	aad, _ := json.Marshal(header)

	ct, err := base64.StdEncoding.DecodeString(pkt.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext base64: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(pkt.Nonce)
	if err != nil {
		return nil, fmt.Errorf("invalid nonce base64: %w", err)
	}
	tag, err := base64.StdEncoding.DecodeString(pkt.Tag)
	if err != nil {
		return nil, fmt.Errorf("invalid tag base64: %w", err)
	}

	// 1. Проверяем буфер пропущенных ключей
	skipKey := fmt.Sprintf("%s:%d", header.DH, header.N)
	if mk, ok := s.Skipped[skipKey]; ok {
		delete(s.Skipped, skipKey)
		defer zeroBytes(mk)
		return decryptAES(mk, ct, nonce, tag, aad)
	}

	// 2. DH рatchet шаг при новом ключе клиента
	if header.DH != s.DHrHex {
		if err := s.skipMsgKeys(s.DHrHex, header.PN); err != nil {
			return nil, err
		}
		if err := s.dhRatchet(header.DH); err != nil {
			return nil, fmt.Errorf("DH ratchet: %w", err)
		}
	}

	// 3. Пропускаем до нужного номера (сообщения вне порядка)
	if err := s.skipMsgKeys(header.DH, header.N); err != nil {
		return nil, err
	}

	// 4. Продвигаем принимающую цепь
	mk, nextCKr := kdfCK(s.CKr)
	s.CKr = nextCKr
	s.Nr++
	defer zeroBytes(mk)

	return decryptAES(mk, ct, nonce, tag, aad)
}

// dhRatchet выполняет DH шаг храповика:
// 1. Деривирует новую принимающую цепь из DH(наш старый ключ, новый ключ клиента)
// 2. Генерирует новую DH пару
// 3. Деривирует новую отправляющую цепь из DH(наш новый ключ, новый ключ клиента)
func (s *RatchetSession) dhRatchet(newDHrHex string) error {
	s.PN = s.Ns
	s.Ns = 0
	s.Nr = 0

	// Удаляем пропущенные ключи старого DHr — они больше не нужны
	if s.DHrHex != "" {
		prefix := s.DHrHex + ":"
		for k := range s.Skipped {
			if strings.HasPrefix(k, prefix) {
				delete(s.Skipped, k)
			}
		}
	}

	// Принимающий шаг
	dhOut1, err := dhCompute(s.DHs, newDHrHex)
	if err != nil {
		return err
	}
	rk1, newCKr, err := kdfRK(s.RK, dhOut1)
	if err != nil {
		return err
	}

	// Новая DH пара для отправки
	newDHs, err := generateDH()
	if err != nil {
		return err
	}

	// Отправляющий шаг
	dhOut2, err := dhCompute(newDHs, newDHrHex)
	if err != nil {
		return err
	}
	rk2, newCKs, err := kdfRK(rk1, dhOut2)
	if err != nil {
		return err
	}

	s.DHrHex = newDHrHex
	s.DHs    = newDHs
	s.RK     = rk2
	s.CKr    = newCKr
	s.CKs    = newCKs
	return nil
}

func (s *RatchetSession) skipMsgKeys(dhrHex string, until int) error {
	if s.CKr == nil || dhrHex == "" {
		return nil
	}
	if s.Nr+maxSkip < until {
		return fmt.Errorf("too many skipped messages (%d → %d)", s.Nr, until)
	}
	for s.Nr < until {
		mk, nextCKr := kdfCK(s.CKr)
		s.CKr = nextCKr
		s.Skipped[fmt.Sprintf("%s:%d", dhrHex, s.Nr)] = mk
		s.Nr++
	}
	return nil
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
