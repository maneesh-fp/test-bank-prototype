# SecureBank — Fingerprint Pro Demo

A banking prototype that demonstrates Fingerprint Pro device intelligence across multiple Fingerprint SDK surfaces: the JS Agent (v3 and v4), the Node.js backend with sealed-result decryption and webhook verification, and six server-side SDK integrations (Node, Python, Go, Java, .NET, PHP).

---

## Table of Contents

- [Project Overview](#project-overview)
- [Architecture](#architecture)
- [v3 vs v4 — What's Different](#v3-vs-v4--whats-different)
- [Files and What They Do](#files-and-what-they-do)
- [Log Files](#log-files)
- [Setup](#setup)
- [Running the Demo](#running-the-demo)
- [Server SDK Scripts](#server-sdk-scripts)
- [Webhook Verification](#webhook-verification)

---

## Project Overview

SecureBank simulates two user flows in a fictional banking app:

| Flow | Page | JS Agent Version | Sealed Results | Server API |
|---|---|---|---|---|
| Login | `login.html` | v3 (via proxy) | Yes — v3 key | v3 (`/events/:requestId`) |
| Accounts tab | `dashboard.html` | v4 (CDN) | Yes — v4 key | v4 (`/v4/events/:eventId`) |

Both flows call the `decrypt.js` Express server, which validates the sealed result, calls the Fingerprint Server API, and logs the raw JSON response to disk.

---

## Architecture

```
Browser (login.html / dashboard.html)
        │
        │  JS Agent fingerprint + sealed result (AES-256-GCM)
        ▼
decrypt.js  ─── Express server (localhost:3000)
   ├── POST /api/login       → unseal (v3 key) → Server API v3  → events.txt
   ├── POST /api/identify    → unseal (v4 key) → Server API v4  → events.txt
   ├── POST /api/webhook     → HMAC verify (v3 secret) → webhooks.txt
   └── POST /api/webhook-v4  → HMAC verify (v4 secret) → webhooks.txt

Standalone SDK scripts (run separately against any event_id / request_id):
   node-sdk.js       → node_sdk_response.txt
   python-sdk.py     → python_sdk_response.txt
   go-server/main.go → go_server_response.txt
   java-sdk/         → java_sdk_response.txt
   dotnet-sdk/       → dotnet_sdk_response.txt
   php-sdk/          → php_sdk_response.txt
```

---

## v3 vs v4 — What's Different

Fingerprint Pro v4 is a flatter, renamed API. This project uses both versions to demonstrate migration.

| | v3 | v4 |
|---|---|---|
| **JS Agent load** | `FingerprintJS.load()` | `Fingerprint.start()` |
| **Result field** | `requestId` | `event_id` |
| **Visitor field** | `visitorId` | `visitor_id` |
| **Server API endpoint** | `/events/:requestId` | `/v4/events/:eventId` |
| **Auth header** | `Auth-API-Key: <key>` | `Authorization: Bearer <key>` |
| **Response structure** | Nested under `products.*` | Flat snake_case fields |
| **Suspect score path** | `products.suspectScore.data.result` | `suspect_score` |
| **Bot path** | `products.botd.data.bot.result` | `bot` |
| **VPN path** | `products.vpn.data.result` | `vpn` |
| **City path** | `products.ipInfo.data.v4.geolocation.city.name` | `ip_info.v4.geolocation.city_name` |
| **Sealed key env var** | `FP_SEALED_KEY` | `FP_SEALED_KEY_ACCOUNTS` |
| **Where used** | Login page (`login.html`) | Accounts tab (`dashboard.html`) |

---

## Files and What They Do

### Frontend (Static HTML)

| File | Description |
|---|---|
| `login.html` | Login page — loads JS Agent v3 via custom proxy, sends sealed result to `/api/login` |
| `dashboard.html` | Dashboard — loads JS Agent v4 from CDN, sends sealed result to `/api/identify` on Accounts tab click |

> **Configuring keys in HTML files:** JS Agent public keys are loaded from `config.js` (gitignored). Copy `config.example.js` to `config.js` and fill in your values. See [Setup](#setup) below.

### Backend

| File | Description |
|---|---|
| `decrypt.js` | Express server — handles login, identify, and webhook routes; decrypts sealed results; calls Server API |
| `package.json` | Node dependencies: `@fingerprintjs/fingerprintjs-pro-server-api` (v3), `@fingerprint/node-sdk` (v4), `express`, `dotenv` |

### Server SDK Scripts (standalone — v4)

Each script accepts a single `event_id` argument, calls the Fingerprint v4 Server API, prints a summary to the console, and appends the full raw JSON response to a log file.

| Script | Language | SDK | Log file |
|---|---|---|---|
| `node-sdk.js` | Node.js | `@fingerprint/node-sdk` v7 | `node_sdk_response.txt` |
| `python-sdk.py` | Python 3 | `fingerprint_server_sdk` | `python_sdk_response.txt` |
| `go-server/main.go` | Go | `go-sdk/v8` | `go_server_response.txt` |
| `java-sdk/` | Java 11+ | `com.github.fingerprintjs:java-sdk` (JitPack) | `java_sdk_response.txt` |
| `dotnet-sdk/` | .NET 8 | `Fingerprint.ServerSdk` v8 | `dotnet_sdk_response.txt` |
| `php-sdk/` | PHP 8 | `fingerprint/server-sdk` v7 | `php_sdk_response.txt` |

All server SDKs use **Region AP** (`ap.api.fpjs.io`) and return the v4 flat response structure.

---

## Log Files

Log files are **gitignored** — they are created locally when the demo runs and never committed to the repo.

| File | Populated when |
|---|---|
| `events.txt` | Every login (`/api/login`) and Accounts tab click (`/api/identify`) via `decrypt.js` |
| `unsealed_results.txt` | Every time a sealed result is successfully decrypted by `decrypt.js` |
| `webhooks.txt` | Every Fingerprint webhook received at `/api/webhook` (v3) or `/api/webhook-v4` (v4) |
| `node_sdk_response.txt` | `node node-sdk.js <event_id>` |
| `python_sdk_response.txt` | `python3 python-sdk.py <event_id>` |
| `go_server_response.txt` | `go run go-server/main.go <event_id>` |
| `java_sdk_response.txt` | `mvn exec:java -Dexec.args="<event_id>"` (from `java-sdk/`) |
| `dotnet_sdk_response.txt` | `dotnet run -- <event_id>` (from `dotnet-sdk/FingerprintSdk/`) |
| `php_sdk_response.txt` | `php php-sdk/fingerprint.php <event_id>` |

Each entry is separated by a `────` line and includes a UTC timestamp and the event/request ID.

---

## Setup

### 1. Clone and install Node dependencies

```bash
git clone https://github.com/maneesh-fp/test-bank-prototype.git
cd test-bank-prototype
npm install
```

### 2. Configure environment variables

```bash
cp .env.example .env
```

Edit `.env` and fill in your values:

```
FP_SERVER_API_KEY=        # Fingerprint Server API key (works for both v3 and v4)
FP_WEBHOOK_SECRET=        # Webhook secret from your v3 Fingerprint environment
FP_WEBHOOK_SECRET_V4=     # Webhook secret from your v4 Fingerprint environment
FP_SEALED_KEY=            # Sealed results decryption key — v3 environment (base64)
FP_SEALED_KEY_ACCOUNTS=   # Sealed results decryption key — v4 environment (base64)
FP_JS_AGENT_KEY_V3=       # Public JS Agent key — v3 environment
FP_JS_AGENT_KEY_V4=       # Public JS Agent key — v4 environment
FP_PROXY_SCRIPT=          # Custom proxy script URL (v3) — leave blank to use CDN
FP_PROXY_ENDPOINT=        # Custom proxy endpoint URL (v3) — leave blank to use CDN
```

### 3. Configure public JS Agent keys for the HTML pages

```bash
cp config.example.js config.js
```

Edit `config.js` and fill in your JS Agent public keys and proxy URLs. This file is gitignored and never committed.

### 4. (Optional) Install per-language dependencies

**Python:**
```bash
pip install fingerprint-server-sdk python-dotenv
```

**Go** (from `go-server/`):
```bash
go mod tidy
```

**Java** (from `java-sdk/`):
```bash
mvn package -q
```

**PHP** (from `php-sdk/`):
```bash
composer install
```

**.NET** (requires .NET 8 SDK):
```bash
cd dotnet-sdk/FingerprintSdk && dotnet restore
```

---

## Running the Demo

### Start the backend server

```bash
node decrypt.js
# Server listening on http://localhost:3000
```

### Open the login page

Open `login.html` directly in your browser (or serve it with any static server). The page communicates with `localhost:3000`.

### Accounts tab

Log in successfully to reach `dashboard.html`. Click **Accounts** to trigger a separate v4 identification event.

---

## Server SDK Scripts

Run any of these independently with a valid `event_id` from your Fingerprint dashboard:

```bash
# Node
node node-sdk.js <event_id>

# Python
python3 python-sdk.py <event_id>

# Go
go run go-server/main.go <event_id>

# Java
cd java-sdk && mvn exec:java -Dexec.args="<event_id>"

# .NET
cd dotnet-sdk/FingerprintSdk && dotnet run -- <event_id>

# PHP
php php-sdk/fingerprint.php <event_id>
```

All scripts read `FP_SERVER_API_KEY` from `.env` automatically.

---

## Webhook Verification

`decrypt.js` exposes a single v4 webhook endpoint. Point your Fingerprint webhook settings to:

| Endpoint | Secret env var | Log file |
|---|---|---|
| `POST /api/webhook/v4` | `FP_WEBHOOK_SECRET_V4` | `webhooks.txt` |

Each incoming webhook is HMAC-SHA256 verified against the signature in the `fpjs-event-signature` header before being logged.
