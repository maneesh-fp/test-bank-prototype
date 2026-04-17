/**
 * SecureBank — .NET Server SDK v4 (Fingerprint.ServerSdk)
 *
 * Uses Fingerprint.ServerSdk v8.0.2 to query an event by event_id.
 * Returns v4 flat response structure.
 *
 * Usage: dotnet run -- <event_id>
 */

using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Fingerprint.ServerSdk.Api;
using Fingerprint.ServerSdk.Client;
using Fingerprint.ServerSdk.Extensions;
using Fingerprint.ServerSdk.Model;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

static void LoadDotEnv(string path) {
    if (!File.Exists(path)) return;
    foreach (var raw in File.ReadAllLines(path)) {
        var line = raw.Trim();
        if (line.Length == 0 || line.StartsWith("#")) continue;
        var idx = line.IndexOf('=');
        if (idx < 1) continue;
        var key = line[..idx].Trim();
        var val = line[(idx + 1)..].Trim();
        if (Environment.GetEnvironmentVariable(key) == null)
            Environment.SetEnvironmentVariable(key, val);
    }
}
LoadDotEnv(Path.Combine(AppContext.BaseDirectory, "../../.env"));
LoadDotEnv(Path.Combine(Directory.GetCurrentDirectory(), "../../.env"));
LoadDotEnv(".env");

string API_KEY = Environment.GetEnvironmentVariable("FP_SERVER_API_KEY")
    ?? throw new InvalidOperationException("Missing FP_SERVER_API_KEY — set it in .env");
const string DOTNET_LOG = "../../dotnet_sdk_response.txt";

if (args.Length < 1)
{
    Console.Error.WriteLine("Usage: dotnet run -- <event_id>");
    Environment.Exit(1);
}
string eventId = args[0];

// Build host with Fingerprint DI (suppress HTTP logging)
using IHost host = Host.CreateDefaultBuilder()
    .ConfigureServices(services =>
    {
        services.AddFingerprint(options =>
        {
            options.AddTokens(new BearerToken(API_KEY));
            options.Region = Region.Asia;
        });
    })
    .ConfigureLogging(logging =>
    {
        logging.ClearProviders();
    })
    .Build();

var api = host.Services.GetRequiredService<IFingerprintApi>();

var response = await api.GetEventAsync(eventId);

if (!response.IsOk)
{
    if (response.IsNotFound)
        Console.Error.WriteLine("Not found: event ID does not exist");
    else if (response.IsTooManyRequests)
        Console.Error.WriteLine("Rate limited: too many requests");
    else if (response.IsForbidden)
        Console.Error.WriteLine("Forbidden: check your API key");
    else
        Console.Error.WriteLine($"API error (HTTP {response.StatusCode})");
    Environment.Exit(1);
}

Event ev = response.Ok()!;

// v4 flat structure
var ident   = ev.Identification;
var browser = ev.BrowserDetails;
var ipInfo  = ev.IpInfo;

string city = "unknown";
if (ipInfo?.V4?.Geolocation?.CityName is string cn4) city = cn4;
else if (ipInfo?.V6?.Geolocation?.CityName is string cn6) city = cn6;

Console.WriteLine("\n.NET SDK response (v4):");
Console.WriteLine($"  event_id      : {ev.EventId}");
Console.WriteLine($"  visitorId     : {ident?.VisitorId}");
Console.WriteLine($"  linkedId      : {ev.LinkedId}");
Console.WriteLine($"  confidence    : {ident?.Confidence?.Score}");
Console.WriteLine($"  suspectScore  : {ev.SuspectScore}");
Console.WriteLine($"  browserName   : {browser?.BrowserName}");
Console.WriteLine($"  os            : {browser?.Os}");
Console.WriteLine($"  ip            : {ev.IpAddress}");
Console.WriteLine($"  city          : {city}");
Console.WriteLine($"  bot           : {ev.Bot}");
Console.WriteLine($"  vpn           : {ev.Vpn}");
Console.WriteLine($"  proxy         : {ev.Proxy}");

// Write pretty-printed JSON to file
var jsonOptions = new JsonSerializerOptions
{
    WriteIndented          = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    Converters             = { new JsonStringEnumConverter() },
};
string rawJson = JsonSerializer.Serialize(ev, jsonOptions);

string separator = new string('─', 60);
string entry     = $"\n{separator}\nTimestamp : {DateTime.UtcNow:O}\nEventId   : {eventId}\n{rawJson}\n";

string logPath = Path.GetFullPath(DOTNET_LOG);
await File.AppendAllTextAsync(logPath, entry);
Console.WriteLine($"\nRaw response written to {logPath}");
