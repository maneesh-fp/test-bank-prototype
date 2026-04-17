<?php
/**
 * SecureBank — PHP Server SDK v4 (fingerprint/server-sdk v7)
 *
 * Uses fingerprint/server-sdk to query an event by event_id.
 * Returns v4 flat response structure via getter methods.
 *
 * Usage: php fingerprint.php <event_id>
 */

require_once __DIR__ . '/vendor/autoload.php';

use Fingerprint\ServerSdk\Api\FingerprintApi;
use Fingerprint\ServerSdk\Configuration;
use GuzzleHttp\Client;

function loadDotEnv(string $path): void {
    if (!file_exists($path)) return;
    foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#')) continue;
        $eq = strpos($line, '=');
        if ($eq < 1) continue;
        $key = trim(substr($line, 0, $eq));
        $val = trim(substr($line, $eq + 1));
        if (!getenv($key)) putenv("$key=$val");
    }
}
loadDotEnv(__DIR__ . '/../.env');
loadDotEnv(__DIR__ . '/.env');

$apiKey = getenv('FP_SERVER_API_KEY');
if (!$apiKey) {
    fwrite(STDERR, "Missing FP_SERVER_API_KEY — set it in .env\n");
    exit(1);
}
const PHP_SDK_LOG  = __DIR__ . '/../php_sdk_response.txt';

$eventId = $argv[1] ?? null;
if (!$eventId) {
    fwrite(STDERR, "Usage: php fingerprint.php <event_id>\n");
    exit(1);
}

$config = new Configuration($apiKey, Configuration::REGION_ASIA);
$client = new FingerprintApi($config, new Client());

try {
    $event = $client->getEvent($eventId);
} catch (Exception $e) {
    fwrite(STDERR, "API error: " . $e->getMessage() . "\n");
    exit(1);
}

// v4 flat structure — access via getters
$ident   = $event->getIdentification();
$browser = $event->getBrowserDetails();
$ipInfo  = $event->getIpInfo();
$city    = $ipInfo?->getV4()?->getGeolocation()?->getCityName()
        ?? $ipInfo?->getV6()?->getGeolocation()?->getCityName()
        ?? 'unknown';

echo "\nPHP SDK response (v4):\n";
echo "  event_id      : " . $event->getEventId()               . "\n";
echo "  visitorId     : " . ($ident?->getVisitorId()   ?? '')   . "\n";
echo "  linkedId      : " . ($event->getLinkedId()     ?? '')   . "\n";
echo "  confidence    : " . ($ident?->getConfidence()?->getScore() ?? '') . "\n";
echo "  suspectScore  : " . ($event->getSuspectScore() ?? 0)    . "\n";
echo "  browserName   : " . ($browser?->getBrowserName() ?? '') . "\n";
echo "  os            : " . ($browser?->getOs()          ?? '') . "\n";
echo "  ip            : " . ($event->getIpAddress()     ?? '')  . "\n";
echo "  city          : " . $city                               . "\n";
echo "  bot           : " . ($event->getBot()?->value     ?? 'unknown') . "\n";
echo "  vpn           : " . ($event->getVpn() ? 'true' : 'false')   . "\n";
echo "  proxy         : " . ($event->getProxy() ? 'true' : 'false') . "\n";

// Serialize to JSON and write to log file
$raw  = json_encode(json_decode($event->__toString()), JSON_PRETTY_PRINT);
$sep  = str_repeat('─', 60);
$entry = "\n{$sep}\nTimestamp : " . date('c') . "\nEventId   : {$eventId}\n{$raw}\n";

file_put_contents(PHP_SDK_LOG, $entry, FILE_APPEND);
echo "\nRaw response written to " . realpath(PHP_SDK_LOG) . "\n";
