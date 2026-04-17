/**
 * SecureBank — Node Server SDK v4 (FingerprintServerApiClient)
 *
 * Uses @fingerprint/node-sdk's FingerprintServerApiClient to query an event.
 * NOTE: getEvent currently returns the v3 products-nested response structure.
 * A v4 flat response migration is underway per the SDK docs.
 *
 * Usage: node node-sdk.js <event_id>
 */

require('dotenv').config();
const fs   = require('fs');
const path = require('path');
const { FingerprintServerApiClient, Region, RequestError } = require('@fingerprint/node-sdk');

const API_KEY = process.env.FP_SERVER_API_KEY;
if (!API_KEY) { console.error('Missing FP_SERVER_API_KEY in .env'); process.exit(1); }
const NODE_SDK_LOG     = path.join(__dirname, 'node_sdk_response.txt');

const client = new FingerprintServerApiClient({
  apiKey: API_KEY,
  region: Region.AP,
});

async function main() {
  const eventId = process.argv[2];
  if (!eventId) {
    console.error('Usage: node node-sdk.js <event_id>');
    process.exit(1);
  }

  let event;
  try {
    event = await client.getEvent(eventId);
  } catch (err) {
    if (err instanceof RequestError) {
      console.error(`Request failed [${err.statusCode}]:`, err.responseBody);
    } else {
      console.error('Unexpected error:', err.message);
    }
    process.exit(1);
  }

  // getEvent returns v4 flat structure
  const id      = event?.identification;
  const browser = event?.browser_details;
  const ipInfo  = event?.ip_info;
  const city    = ipInfo?.v4?.geolocation?.city_name ?? ipInfo?.v6?.geolocation?.city_name ?? 'unknown';

  console.log('\nNode SDK response (v4):');
  console.log('  event_id      :', event?.event_id);
  console.log('  visitorId     :', id?.visitor_id);
  console.log('  linkedId      :', event?.linked_id);
  console.log('  confidence    :', id?.confidence?.score);
  console.log('  suspectScore  :', event?.suspect_score);
  console.log('  browserName   :', browser?.browser_name);
  console.log('  os            :', browser?.os);
  console.log('  ip            :', event?.ip_address);
  console.log('  city          :', city);
  console.log('  bot           :', event?.bot);
  console.log('  vpn           :', event?.vpn);
  console.log('  proxy         :', event?.proxy);

  const entry = [
    `\n${'─'.repeat(60)}`,
    `Timestamp : ${new Date().toISOString()}`,
    `EventId   : ${eventId}`,
    JSON.stringify(event, null, 2),
  ].join('\n');

  fs.appendFileSync(NODE_SDK_LOG, entry + '\n');
}

main();
