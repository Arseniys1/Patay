# Encrypt Proxy — инструкция по запуску и использованию

Encrypt Proxy — это обратный прокси-сервер на Go, который прозрачно шифрует трафик между клиентом и бэкенд-сервером по протоколу **Double Ratchet** (ECDH P-256 + AES-256-GCM). Клиент никогда не отправляет данные в открытом виде — только зашифрованные пакеты.

---

## Архитектура

```
Клиент ──(зашифрованный трафик)──► Encrypt Proxy :8080 ──(plain HTTP)──► Бэкенд :8090
```

- **Клиент** реализует Double Ratchet и отправляет только зашифрованные пакеты
- **Прокси** расшифровывает, пересылает обычный HTTP на бэкенд, шифрует ответ
- **Бэкенд** — любой HTTP-сервер (nginx, Apache, Express, FastAPI и т.д.), не знает о шифровании

---

## Требования

- **Docker** 24+ и **Docker Compose** v2 (для запуска через Docker)
- **Go 1.25+** (для сборки из исходников)

---

## Быстрый старт (Docker)

### 1. Запуск с nginx-бэкендом (по умолчанию)

```bash
docker compose up --build
```

Прокси будет доступен на `http://localhost:8080`.

### 2. Запуск с конкретным бэкендом

| Бэкенд  | Команда |
|---------|---------|
| nginx   | `docker compose up --build` |
| Express (Node.js) | `docker compose -f docker-compose.yml -f docker-compose.express.yml up --build` |
| FastAPI (Python)  | `docker compose -f docker-compose.yml -f docker-compose.fastapi.yml up --build` |
| Apache (PHP)      | `docker compose -f docker-compose.yml -f docker-compose.apache.yml up --build` |
| Traefik + nginx   | `docker compose -f docker-compose.yml -f docker-compose.traefik.yml up --build` |

### 3. Запуск интеграционных тестов

```bash
# Один бэкенд
./test-docker.sh nginx
./test-docker.sh express
./test-docker.sh fastapi
./test-docker.sh apache
./test-docker.sh traefik

# Все бэкенды подряд
./test-docker.sh all
```

Скрипт поднимает стек, запускает Node.js-клиент с 8 тест-сценариями и печатает итог.

---

## Запуск из исходников (без Docker)

```bash
# Сборка
go build -o encryptproxy .

# Запуск с конфигом
./encryptproxy -config config.yaml
```

Прокси требует работающего бэкенда по адресу из `config.yaml` (поле `backend`).

---

## Конфигурация

Конфиг-файл — YAML. Поддерживает подстановку переменных окружения: `${VAR:-default}`.
Путь по умолчанию: `config.yaml`. Переопределяется флагом `-config`.

```yaml
# Адрес прокси
listen: ":8080"

# URL бэкенда (HTTP или HTTPS)
backend: "http://127.0.0.1:80"

# Время жизни сессии (без активности сессия удаляется)
session_ttl: "1h"

# Служебные пути прокси (не проксируются на бэкенд)
init_path:    "/ratchet/init"   # GET  — получить ключи сервера
api_path:     "/ratchet/api"    # POST — зашифрованный запрос
health_path:  "/health"         # GET  — health check прокси
metrics_path: "/metrics"        # GET  — Prometheus метрики

# Логирование
log_level:  "info"    # debug | info | warn | error
log_format: "json"    # json | text

# Лимит сессий (0 = без лимита)
max_sessions: 10000

# Максимальный размер WebSocket-сообщения (байт)
ws_max_message_bytes: 65536

# Разрешённые Origins для WebSocket (пусто = любой)
allowed_origins: []

# Rate limiting для /ratchet/init
rate_limit:
  enabled: false
  rps: 10      # запросов в секунду с одного IP
  burst: 20    # пиковый burst

# Circuit breaker: размыкает цепь после N ошибок бэкенда
circuit_breaker:
  enabled: true
  threshold: 5      # ошибок до размыкания
  timeout: "10s"    # время до перехода в half-open

# Таблица маршрутов (первое совпадение побеждает)
routes:
  - path: "/api/"
    mode: encrypt          # шифровать запрос и ответ

  - path: "/auth/"
    mode: encrypt
    methods: [POST, PUT]   # только эти методы шифруются, остальные — plain

  - path: "/webhook/"
    mode: encrypt
    methods: [POST]

  - path: "/health"
    mode: plain            # передать бэкенду как есть

  - path: "/static/"
    mode: plain
    methods: [GET, HEAD]

  - path: "/"
    mode: plain
    methods: [GET]
```

### Правила маршрутизации

| Поле | Описание |
|------|----------|
| `path` | Путь. Если заканчивается на `/` — prefix-матч, иначе — точное совпадение |
| `mode: encrypt` | Прокси расшифровывает запрос, пересылает на бэкенд, шифрует ответ |
| `mode: plain` | Прокси пересылает запрос на бэкенд без изменений |
| `methods` | Список разрешённых HTTP-методов (пусто = все) |

Пути, не совпавшие ни с одним правилом, пересылаются на бэкенд в режиме plain.

### Hot reload конфига

Отправьте процессу сигнал `SIGHUP` — конфиг перечитается без перезапуска:

```bash
kill -HUP <PID>
```

Параметры `listen`, `backend` и `*_path` **не** перезагружаются — они требуют полного рестарта.

---

## Протокол Double Ratchet

### Криптография

| Компонент | Алгоритм |
|-----------|----------|
| Key agreement | ECDH P-256 |
| KDF (SK) | HKDF-SHA256, salt=`encryptserver-v1`, info=`aes-key`, 32 байта |
| KDF (RK/CK) | HKDF-SHA256, salt=rootKey, info=`DoubleRatchetV1`, 64 байта |
| Chain KDF | HMAC-SHA256(chainKey, 0x01) → MK; HMAC-SHA256(chainKey, 0x02) → nextCK |
| Шифрование | AES-256-GCM, nonce=12 байт (случайный), AAD=JSON(header), tag=16 байт |

### Handshake (установка сессии)

```
Клиент                                    Прокси
  │                                          │
  │── GET /ratchet/init ────────────────────►│
  │                                          │  генерирует sessionId,
  │                                          │  ECDH-ключ сервера,
  │                                          │  Ratchet-ключ сервера
  │◄── { sessionId, ecdhPublicKey,           │
  │       ratchetPublicKey } ────────────────│
  │                                          │
  │  sharedSecret = ECDH(clientPriv, serverECDH)
  │  SK = kdfSK(sharedSecret)
  │  initAlice(SK, serverRatchetPublicKey)   │
```

### Зашифрованный запрос

```
Клиент                                    Прокси                    Бэкенд
  │                                          │                         │
  │  payload = { method, path, headers, body }
  │  encPkt = ratchet.encrypt(JSON(payload)) │
  │                                          │
  │── POST /ratchet/api ───────────────────►│
  │   X-Session-ID: <sessionId>             │
  │   { ecdhPublicKey*, header,             │  * только в первом запросе
  │     ciphertext, nonce, tag }            │
  │                                          │  расшифровывает payload
  │                                          │── GET/POST /api/... ──►│
  │                                          │◄── 200 { ... } ────────│
  │                                          │  шифрует ответ
  │◄── { header, ciphertext, nonce, tag } ──│
  │  plaintext = ratchet.decrypt(encPkt)    │
  │  resp = JSON.parse(plaintext)           │
  │  → { status, headers, body }            │
```

Каждый запрос продвигает KDF-цепочку (forward secrecy). Каждые N сообщений автоматически выполняется DH-рatchet-шаг — обновляются ключи обеих сторон.

---

## API прокси

### `GET /ratchet/init` — инициализация сессии

**Ответ:**
```json
{
  "sessionId":        "a3f1c2d4e5b6...",
  "ecdhPublicKey":    "04ab12cd...",
  "ratchetPublicKey": "04ef34gh..."
}
```

- `sessionId` — 32-символьная hex-строка, идентификатор сессии
- `ecdhPublicKey` — публичный ECDH-ключ сервера (P-256, uncompressed, hex)
- `ratchetPublicKey` — публичный Ratchet-ключ (P-256, uncompressed, hex)

### `POST /ratchet/api` — зашифрованный запрос

**Заголовки:**
```
X-Session-ID: <sessionId>
Content-Type: application/json
```

**Тело запроса (первый запрос):**
```json
{
  "ecdhPublicKey": "04ab12...",
  "header": { "dh": "04cd34...", "pn": 0, "n": 0 },
  "ciphertext": "<base64>",
  "nonce":      "<base64>",
  "tag":        "<base64>"
}
```

**Тело запроса (последующие запросы)** — то же, без `ecdhPublicKey`.

**Зашифрованный plaintext** содержит JSON:
```json
{
  "method":  "POST",
  "path":    "/api/users",
  "headers": { "Authorization": "Bearer ..." },
  "body":    "{\"name\":\"alice\"}"
}
```

**Ответ прокси** — зашифрованный пакет:
```json
{
  "header":     { "dh": "04...", "pn": 0, "n": 0 },
  "ciphertext": "<base64>",
  "nonce":      "<base64>",
  "tag":        "<base64>"
}
```

**Расшифрованный plaintext** ответа:
```json
{
  "status":  200,
  "headers": { "Content-Type": "application/json" },
  "body":    "{\"id\":1,\"name\":\"alice\"}"
}
```

### `GET /health` — состояние прокси

```json
{
  "status":   "ok",
  "sessions": 42,
  "uptime":   "1h23m"
}
```

### `GET /metrics` — Prometheus метрики

Стандартный formат Prometheus. Основные метрики:

| Метрика | Тип | Описание |
|---------|-----|----------|
| `encryptproxy_decrypt_errors_total` | Counter | Ошибки расшифровки |
| `encryptproxy_active_sessions` | Gauge | Активные сессии |
| `encryptproxy_rate_limit_rejects_total` | Counter | Отклонённые rate-limit |
| `encryptproxy_requests_total` | Counter | Запросы по пути/методу/статусу |
| `encryptproxy_request_duration_seconds` | Histogram | Время обработки |

---

## Реализация клиента

Клиент должен реализовать:

1. **Генерацию ECDH-ключей** — P-256, uncompressed (65 байт, формат `04 || x || y`), hex
2. **ECDH key agreement** → **KDF SK** через HKDF-SHA256
3. **Double Ratchet** — инициализация как Alice, encrypt/decrypt
4. **HTTP-запросы** к `/ratchet/init` и `/ratchet/api`

### Пример на Node.js (готовая реализация)

Смотрите `docker/client/src/` — полная реализация клиента:

```
docker/client/src/
├── crypto-utils.js   — ECDH, KDF, AES-GCM
├── ratchet.js        — Double Ratchet (Alice-сторона)
├── encrypt-client.js — HTTP-обёртка (axios)
└── test.js           — интеграционные тесты
```

**Минимальный пример:**

```js
const { EncryptedClient } = require('./docker/client/src/encrypt-client');

const client = new EncryptedClient('http://localhost:8080');
await client.init();

// GET /api/users
const res = await client.get('/api/users');
console.log(res.status, JSON.parse(res.body));

// POST /api/users
const res2 = await client.post('/api/users', { name: 'alice' });
console.log(res2.status, JSON.parse(res2.body));
```

### Реализация на других языках

Необходимые алгоритмы (стандартные, есть в любой крипто-библиотеке):

```
ECDH P-256
HKDF-SHA256
HMAC-SHA256
AES-256-GCM (nonce 12 байт, tag 16 байт)
```

Параметры KDF точно совпадают с Go-реализацией:
- `kdfSK`: `HKDF(sha256, ikm=sharedSecret, salt="encryptserver-v1", info="aes-key", len=32)`
- `kdfRK`: `HKDF(sha256, ikm=dhOutput, salt=rootKey, info="DoubleRatchetV1", len=64)`
- `kdfCK`: `mk=HMAC(chainKey, [0x01])`, `nextCK=HMAC(chainKey, [0x02])`

---

## Мониторинг и отладка

### Логи

Прокси пишет структурированные логи (JSON или text):

```json
{"time":"...","level":"INFO","msg":"proxy started","listen":":8080","backend":"http://..."}
{"time":"...","level":"DEBUG","msg":"msg","n":0,"method":"GET","path":"/api/hello","dh":"..."}
{"time":"...","level":"ERROR","msg":"decrypt","err":"cipher: message authentication failed"}
```

Уровень `debug` показывает каждый расшифрованный запрос с номером сообщения (`n`) и текущим DH-ключом.

### Circuit Breaker

Если бэкенд вернул ошибку подряд N раз (по умолчанию 5), прокси переходит в состояние **Open** и сразу отвечает `502 Bad Gateway` без обращения к бэкенду. Через 10 секунд — переход в **Half-Open** для проверки восстановления.

---

## Troubleshooting

| Симптом | Причина | Решение |
|---------|---------|---------|
| `401 X-Session-ID header required` | Нет заголовка сессии | Добавить `X-Session-ID` в каждый запрос к `/ratchet/api` |
| `400 ecdhPublicKey required` | Не передан ключ в первом запросе | В первом запросе после `/ratchet/init` добавить `ecdhPublicKey` |
| `400 decryption failed` | Рассинхронизация ratchet или неверный ключ | Выполнить handshake заново |
| `502 backend circuit open` | Circuit breaker разомкнут | Бэкенд недоступен, подождать `timeout` секунд |
| `503 session limit reached` | Превышен `max_sessions` | Увеличить лимит или уменьшить `session_ttl` |
| `429 rate limit exceeded` | Слишком много запросов к `/ratchet/init` | Уменьшить частоту handshake или отключить rate limit |
