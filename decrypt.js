/**
 * SecureBank — Backend: Fingerprint Sealed Result Decryption
 *
 * Sealed results are AES-256-GCM encrypted by Fingerprint before reaching the client.
 * Decryption MUST happen here on the server — never expose the key to the browser.
 *
 * Payload wire format (after base64 decode):
 *   [4 bytes: magic/version] [12 bytes: nonce] [N bytes: AES-256-GCM ciphertext (deflate-compressed JSON)] [16 bytes: auth tag]
 *
 * Install deps:  npm install @fingerprintjs/fingerprintjs-pro-server-api @fingerprint/node-sdk express
 */

require('dotenv').config();

const express  = require('express');
const fs       = require('fs');
const path     = require('path');
const { unsealEventsResponse, DecryptionAlgorithm, isValidWebhookSignature } = require('@fingerprintjs/fingerprintjs-pro-server-api');
const { unsealEventsResponse: unsealEventsResponseV4, DecryptionAlgorithm: DecryptionAlgorithmV4 } = require('@fingerprint/node-sdk');

const FP_SERVER_API_KEY    = process.env.FP_SERVER_API_KEY;
const FP_WEBHOOK_SECRET_V4 = process.env.FP_WEBHOOK_SECRET_V4;

if (!FP_SERVER_API_KEY || !FP_WEBHOOK_SECRET_V4) {
  console.error('Missing required env vars. Copy .env.example to .env and fill in values.');
  process.exit(1);
}
const FP_SERVER_API_URL     = 'https://ap.api.fpjs.io';
const EVENTS_LOG            = path.join(__dirname, 'events.txt');
const WEBHOOK_LOG           = path.join(__dirname, 'webhooks.txt');
const UNSEALED_LOG          = path.join(__dirname, 'unsealed_results.txt');

// v3 Server API — used by login flow
async function fetchAndLogEvent(requestId) {
  try {
    console.log(`\nCalling Server API: ${FP_SERVER_API_URL}/events/${requestId}`);
    const response = await fetch(`${FP_SERVER_API_URL}/events/${requestId}`, {
      headers: { 'Auth-API-Key': FP_SERVER_API_KEY }
    });
    const data = await response.json();

    const id      = data?.products?.identification?.data;
    const suspect = data?.products?.suspectScore?.data;
    const browser = id?.browserDetails;
    const ipInfo  = data?.products?.ipInfo?.data;
    const city    = ipInfo?.v4?.geolocation?.city?.name ?? ipInfo?.v6?.geolocation?.city?.name ?? 'unknown';
    const bot     = data?.products?.botd?.data;
    const vpn     = data?.products?.vpn?.data;
    const proxy   = data?.products?.proxy?.data;

    console.log('\nServer API response (v3):');
    console.log('  requestId     :', id?.requestId);
    console.log('  visitorId     :', id?.visitorId);
    console.log('  linkedId      :', id?.linkedId);
    console.log('  confidence    :', id?.confidence?.score);
    console.log('  suspectScore  :', suspect?.result);
    console.log('  browserName   :', browser?.browserName);
    console.log('  os            :', browser?.os);
    console.log('  ip            :', id?.ip);
    console.log('  city          :', city);
    console.log('  bot           :', bot?.bot?.result);
    console.log('  vpn           :', vpn?.result);
    console.log('  proxy         :', proxy?.result);

    const entry = [
      `\n${'─'.repeat(60)}`,
      `Timestamp : ${new Date().toISOString()}`,
      `RequestId : ${requestId}`,
      `Status    : ${response.status}`,
      JSON.stringify(data, null, 2),
    ].join('\n');

    fs.appendFileSync(EVENTS_LOG, entry + '\n');
  } catch (err) {
    console.error('Server API call failed:', err.message);
  }
}

// v4 Server API — used by Accounts tab (v4 JS agent, snake_case fields)
async function fetchAndLogEventV4(eventId) {
  try {
    console.log(`\nCalling Server API: ${FP_SERVER_API_URL}/v4/events/${eventId}`);
    const response = await fetch(`${FP_SERVER_API_URL}/v4/events/${eventId}`, {
      headers: { 'Authorization': `Bearer ${FP_SERVER_API_KEY}` }
    });

    const data = await response.json();

    if (!response.ok) {
      console.error('Server API response (error):', JSON.stringify(data));
      fs.appendFileSync(EVENTS_LOG, `\n${'─'.repeat(60)}\nTimestamp : ${new Date().toISOString()}\nEventId   : ${eventId}\nStatus    : ${response.status}\n${JSON.stringify(data, null, 2)}\n`);
      return;
    }

    const identification = data?.identification;
    const browser        = data?.browser_details;
    const ipInfo         = data?.ip_info;
    const city           = ipInfo?.v4?.geolocation?.city_name ?? ipInfo?.v6?.geolocation?.city_name ?? 'unknown';

    console.log('\nServer API response (v4):');
    console.log('  event_id        :', data?.event_id);
    console.log('  visitor_id      :', identification?.visitor_id);
    console.log('  linked_id       :', data?.linked_id);
    console.log('  confidence      :', identification?.confidence?.score);
    console.log('  suspect_score   :', data?.suspect_score);
    console.log('  browser         :', browser?.browser_name);
    console.log('  os              :', browser?.os);
    console.log('  ip              :', data?.ip_address);
    console.log('  city            :', city);
    console.log('  bot             :', data?.bot);
    console.log('  vpn             :', data?.vpn, '| confidence:', data?.vpn_confidence);
    console.log('  proxy           :', data?.proxy, '| confidence:', data?.proxy_confidence, '| type:', data?.proxy_details?.proxy_type);
    console.log('  incognito       :', data?.incognito);
    console.log('  tampering       :', data?.tampering, '| confidence:', data?.tampering_confidence);
    console.log('  virtual_machine :', data?.virtual_machine);
    console.log('  developer_tools :', data?.developer_tools);
    console.log('  high_activity   :', data?.high_activity_device);
    console.log('  ip_blocklist    :', JSON.stringify(data?.ip_blocklist));

    const entry = [
      `\n${'─'.repeat(60)}`,
      `Timestamp : ${new Date().toISOString()}`,
      `EventId   : ${eventId}`,
      `Status    : ${response.status}`,
      JSON.stringify(data, null, 2),
    ].join('\n');

    fs.appendFileSync(EVENTS_LOG, entry + '\n');
  } catch (err) {
    console.error('Server API call failed:', err.message);
  }
}

const app = express();
// Store raw body buffer on req so the webhook route can validate HMAC signatures
app.use(express.json({
  verify: (req, _res, buf) => { req.rawBody = buf; }
}));

// Allow requests from the local HTML file opened directly in the browser.
// file:// pages send Origin: null — must be explicitly allowed (wildcard * doesn't cover it).
app.use((req, res, next) => {
  const origin = req.headers.origin || 'null';
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Vary', 'Origin');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

const SEALED_RESULTS_KEY          = process.env.FP_SEALED_KEY;
const SEALED_RESULTS_KEY_ACCOUNTS = process.env.FP_SEALED_KEY_ACCOUNTS;

if (!SEALED_RESULTS_KEY || !SEALED_RESULTS_KEY_ACCOUNTS) {
  console.error('Missing FP_SEALED_KEY or FP_SEALED_KEY_ACCOUNTS in .env');
  process.exit(1);
}

// v3 decryption keys (login flow)
const decryptionKeys = [
  {
    key: Buffer.from(SEALED_RESULTS_KEY, 'base64'),
    algorithm: DecryptionAlgorithm.Aes256Gcm,
  },
];

// v4 decryption keys — includes both workspace keys so React app (login key) and Accounts tab both work
const decryptionKeysV4 = [
  {
    key: Buffer.from(SEALED_RESULTS_KEY_ACCOUNTS, 'base64'),
    algorithm: DecryptionAlgorithmV4.Aes256Gcm,
  },
  {
    key: Buffer.from(SEALED_RESULTS_KEY, 'base64'),
    algorithm: DecryptionAlgorithmV4.Aes256Gcm,
  },
];

/**
 * POST /api/login
 * Body: { credential, password, sealedResult, requestId }
 *
 * 1. Decrypts the sealedResult using the AES key
 * 2. Extracts the full identification event (same payload as the Server API /events endpoint)
 * 3. Runs your auth logic
 */
app.post('/api/login', async (req, res) => {
  const { credential, password, sealedResult, requestId } = req.body;

  if (!sealedResult) {
    // No sealed result — fall back to Server API using requestId
    fetchAndLogEventV4(requestId);
    return res.json({ success: true });
  }

  const buf = Buffer.from(sealedResult, 'base64');

  // Try v4 decryption first, fall back to v3
  let event;
  let isV4 = false;
  try {
    event = await unsealEventsResponseV4(buf, decryptionKeysV4);
    isV4 = true;
  } catch (errV4) {
    try {
      event = await unsealEventsResponse(buf, decryptionKeys);
    } catch (errV3) {
      console.error('Sealed result decryption failed (v3):', errV3.message);
      console.error('Sealed result decryption failed (v4):', errV4.message);
      return res.status(400).json({ error: 'Invalid or tampered sealed result' });
    }
  }

  if (isV4) {
    // v4 flat structure
    const identification = event?.identification;
    const browser        = event?.browser_details;
    const ipInfo         = event?.ip_info;
    const city           = ipInfo?.v4?.geolocation?.city_name ?? ipInfo?.v6?.geolocation?.city_name ?? 'unknown';

    console.log('\nUnsealed result (v4):');
    console.log('  event_id      :', event?.event_id);
    console.log('  visitor_id    :', identification?.visitor_id);
    console.log('  linked_id     :', event?.linked_id);
    console.log('  confidence    :', identification?.confidence?.score);
    console.log('  suspect_score :', event?.suspect_score);
    console.log('  browser       :', browser?.browser_name);
    console.log('  os            :', browser?.os);
    console.log('  ip            :', event?.ip_address);
    console.log('  city          :', city);
    console.log('  bot           :', event?.bot);
    console.log('  vpn           :', event?.vpn);
    console.log('  proxy         :', event?.proxy);

    const unsealedEntry = [
      `\n${'─'.repeat(60)}`,
      `Timestamp : ${new Date().toISOString()}`,
      `EventId   : ${event?.event_id}`,
      JSON.stringify(event, null, 2),
    ].join('\n');
    fs.appendFileSync(UNSEALED_LOG, unsealedEntry + '\n');

    fetchAndLogEventV4(event?.event_id ?? requestId);
    return res.json({ success: true, visitorId: identification?.visitor_id });

  } else {
    // v3 nested structure
    const id      = event?.products?.identification?.data;
    const suspect = event?.products?.suspectScore?.data;
    const browser = id?.browserDetails;
    const ipInfo  = event?.products?.ipInfo?.data;
    const city    = ipInfo?.v4?.geolocation?.city?.name ?? ipInfo?.v6?.geolocation?.city?.name ?? 'unknown';
    const bot     = event?.products?.botd?.data;
    const vpn     = event?.products?.vpn?.data;
    const proxy   = event?.products?.proxy?.data;

    console.log('\nUnsealed result (v3):');
    console.log('  requestId      :', id?.requestId);
    console.log('  visitorId      :', id?.visitorId);
    console.log('  linkedId       :', id?.linkedId);
    console.log('  confidence     :', id?.confidence?.score);
    console.log('  suspectScore   :', suspect?.result);
    console.log('  browserName    :', browser?.browserName);
    console.log('  os             :', browser?.os);
    console.log('  ip             :', id?.ip);
    console.log('  city           :', city);
    console.log('  bot            :', bot?.bot?.result);
    console.log('  vpn            :', vpn?.result);
    console.log('  proxy          :', proxy?.result);

    const unsealedEntry = [
      `\n${'─'.repeat(60)}`,
      `Timestamp : ${new Date().toISOString()}`,
      `RequestId : ${id?.requestId}`,
      JSON.stringify(event, null, 2),
    ].join('\n');
    fs.appendFileSync(UNSEALED_LOG, unsealedEntry + '\n');

    fetchAndLogEvent(id?.requestId ?? requestId);
    return res.json({ success: true, visitorId: id?.visitorId });
  }
});

/**
 * POST /api/identify
 * Body: { sealedResult, requestId }
 * Generic identification event — used by dashboard page interactions.
 */
app.post('/api/identify', async (req, res) => {
  const { sealedResult, requestId } = req.body;

  if (!requestId) {
    return res.status(400).json({ error: 'requestId is required' });
  }

  // If no sealedResult (e.g. env without encryption configured), skip decryption
  // and go straight to the Server API call using the requestId.
  if (!sealedResult) {
      fetchAndLogEventV4(requestId);
    return res.json({ success: true });
  }

  let event;
  try {
    event = await unsealEventsResponseV4(Buffer.from(sealedResult, 'base64'), decryptionKeysV4);
  } catch (err) {
    console.error('Sealed result decryption failed:', err.message);
    return res.status(400).json({ error: 'Invalid or tampered sealed result' });
  }

  const identification = event?.identification;
  const browser        = event?.browser_details;
  const ipInfo         = event?.ip_info;
  const city           = ipInfo?.v4?.geolocation?.city_name ?? ipInfo?.v6?.geolocation?.city_name ?? 'unknown';

  console.log('\nUnsealed result (v4):');
  console.log('  event_id      :', event?.event_id);
  console.log('  visitor_id    :', identification?.visitor_id);
  console.log('  linked_id     :', event?.linked_id);
  console.log('  confidence    :', identification?.confidence?.score);
  console.log('  suspect_score :', event?.suspect_score);
  console.log('  browser       :', browser?.browser_name);
  console.log('  os            :', browser?.os);
  console.log('  ip            :', event?.ip_address);
  console.log('  city          :', city);
  console.log('  bot           :', event?.bot);
  console.log('  vpn           :', event?.vpn);
  console.log('  proxy         :', event?.proxy);

  const unsealedEntry = [
    `\n${'─'.repeat(60)}`,
    `Timestamp : ${new Date().toISOString()}`,
    `EventId   : ${event?.event_id}`,
    JSON.stringify(event, null, 2),
  ].join('\n');
  fs.appendFileSync(UNSEALED_LOG, unsealedEntry + '\n');

  fetchAndLogEventV4(event?.event_id ?? requestId);

  return res.json({ success: true, visitorId: identification?.visitor_id });
});

// Health-check — Fingerprint Dashboard GETs the URL before activating the webhook
app.get('/api/webhook/v4', (_req, res) => res.sendStatus(200));

/**
 * POST /api/webhook/v4
 * v4 webhook — flat snake_case payload, separate secret and log file.
 * Register <tunnel-url>/api/webhook/v4 in the v4 environment's Fingerprint Dashboard.
 */
app.post('/api/webhook/v4', (req, res) => {
  const signature = req.headers['fpjs-event-signature'];

  if (signature && FP_WEBHOOK_SECRET_V4) {
    const valid = isValidWebhookSignature({
      header: signature,
      data:   req.rawBody,
      secret: FP_WEBHOOK_SECRET_V4,
    });
    if (!valid) {
      return res.status(403).json({ error: 'Invalid signature' });
    }
  }

  const body = req.body;

  if (body?.name === 'TEST') {
    console.log('[Webhook v4] test ping received');
    return res.sendStatus(200);
  }

  // Only handle v4 events — v4 payload has snake_case event_id at top level
  if (!body?.event_id) {
    return res.sendStatus(200); // v3 event — handled by /api/webhook
  }

  // v4 webhook payload is flat with snake_case fields
  const browser = body?.browser_details;
  const ipInfo  = body?.ip_info;
  const city    = ipInfo?.v4?.geolocation?.city_name ?? ipInfo?.v6?.geolocation?.city_name ?? 'unknown';

  console.log('\nWebhook response (v4):');
  console.log('  event_id        :', body?.event_id);
  console.log('  visitor_id      :', body?.identification?.visitor_id);
  console.log('  linked_id       :', body?.linked_id);
  console.log('  tags            :', JSON.stringify(body?.tags ?? {}));
  console.log('  confidence      :', body?.identification?.confidence?.score);
  console.log('  suspect_score   :', body?.suspect_score);
  console.log('  browser         :', browser?.browser_name);
  console.log('  os              :', browser?.os);
  console.log('  ip              :', body?.ip_address);
  console.log('  city            :', city);
  console.log('  bot             :', body?.bot);
  console.log('  vpn             :', body?.vpn, '| confidence:', body?.vpn_confidence);
  console.log('  proxy           :', body?.proxy, '| confidence:', body?.proxy_confidence, '| type:', body?.proxy_details?.proxy_type);
  console.log('  incognito       :', body?.incognito);
  console.log('  tampering       :', body?.tampering, '| confidence:', body?.tampering_confidence);
  console.log('  virtual_machine :', body?.virtual_machine);
  console.log('  developer_tools :', body?.developer_tools);
  console.log('  high_activity   :', body?.high_activity_device);
  console.log('  ip_blocklist    :', JSON.stringify(body?.ip_blocklist));

  const entry = [
    `\n${'─'.repeat(60)}`,
    `Timestamp : ${new Date().toISOString()}`,
    `EventId   : ${body?.event_id}`,
    `VisitorId : ${body?.identification?.visitor_id}`,
    `LinkedId  : ${body?.linked_id ?? '(none)'}`,
    JSON.stringify(body, null, 2),
  ].join('\n');

  fs.appendFileSync(WEBHOOK_LOG, entry + '\n');

  res.sendStatus(200);
});

const PORT = process.env.PORT ?? 3000;
app.listen(PORT, '127.0.0.1', () => console.log(`SecureBank auth server running on http://127.0.0.1:${PORT}`));
