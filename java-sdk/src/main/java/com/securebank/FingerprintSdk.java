package com.securebank;

import com.fingerprint.v4.api.FingerprintApi;
import com.fingerprint.v4.model.BrowserDetails;
import com.fingerprint.v4.model.Event;
import com.fingerprint.v4.model.IPInfo;
import com.fingerprint.v4.model.Identification;
import com.fingerprint.v4.sdk.ApiClient;
import com.fingerprint.v4.sdk.ApiException;
import com.fingerprint.v4.sdk.Configuration;
import com.fingerprint.v4.sdk.Region;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.nio.file.Paths;
import java.time.Instant;

/**
 * SecureBank — Java Server SDK v4 (FingerprintApi)
 *
 * Uses com.github.fingerprintjs:java-sdk:v8.0.0 to query an event by event_id.
 * Returns v4 flat response structure (getter methods, snake_case field names).
 *
 * Usage: java -jar target/fingerprint-java-sdk-1.0-SNAPSHOT.jar <event_id>
 *   or:  mvn exec:java -Dexec.args="<event_id>"
 */
public class FingerprintSdk {

    private static final String JAVA_SDK_LOG = "../java_sdk_response.txt";

    private static void loadDotEnv(String path) {
        try (BufferedReader br = new BufferedReader(new FileReader(path))) {
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                int eq = line.indexOf('=');
                if (eq < 1) continue;
                String key = line.substring(0, eq).trim();
                String val = line.substring(eq + 1).trim();
                if (System.getenv(key) == null) System.setProperty(key, val);
            }
        } catch (Exception ignored) {}
    }

    private static String getAPIKey() {
        loadDotEnv("../.env");
        loadDotEnv(".env");
        String key = System.getenv("FP_SERVER_API_KEY");
        if (key == null) key = System.getProperty("FP_SERVER_API_KEY");
        if (key == null || key.isEmpty()) {
            System.err.println("Missing FP_SERVER_API_KEY — set it in .env");
            System.exit(1);
        }
        return key;
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: java -jar fingerprint-java-sdk.jar <event_id>");
            System.exit(1);
        }
        String eventId = args[0];

        String API_KEY = getAPIKey();
        ApiClient client = Configuration.getDefaultApiClient(API_KEY, Region.ASIA);
        FingerprintApi api = new FingerprintApi(client);

        Event event;
        try {
            event = api.getEvent(eventId);
        } catch (ApiException e) {
            System.err.println("API error [" + e.getCode() + "]: " + e.getMessage());
            System.exit(1);
            return;
        }

        // v4 flat structure — access via getters
        Identification ident   = event.getIdentification();
        BrowserDetails browser = event.getBrowserDetails();
        IPInfo         ipInfo  = event.getIpInfo();

        String city = "unknown";
        if (ipInfo != null) {
            var v4 = ipInfo.getV4();
            var v6 = ipInfo.getV6();
            var geo = (v4 != null) ? v4.getGeolocation() : (v6 != null ? v6.getGeolocation() : null);
            if (geo != null && geo.getCityName() != null) city = geo.getCityName();
        }

        System.out.println("\nJava SDK response (v4):");
        System.out.println("  event_id      : " + event.getEventId());
        System.out.println("  visitorId     : " + (ident   != null ? ident.getVisitorId() : null));
        System.out.println("  linkedId      : " + event.getLinkedId());
        System.out.println("  confidence    : " + (ident   != null && ident.getConfidence() != null ? ident.getConfidence().getScore() : null));
        System.out.println("  suspectScore  : " + event.getSuspectScore());
        System.out.println("  browserName   : " + (browser != null ? browser.getBrowserName() : null));
        System.out.println("  os            : " + (browser != null ? browser.getOs() : null));
        System.out.println("  ip            : " + event.getIpAddress());
        System.out.println("  city          : " + city);
        System.out.println("  bot           : " + event.getBot());
        System.out.println("  vpn           : " + event.getVpn());
        System.out.println("  proxy         : " + event.getProxy());

        // Write pretty-printed JSON to file
        ObjectMapper mapper = new ObjectMapper();
        String rawJson = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(event);

        String logPath = Paths.get(JAVA_SDK_LOG).toAbsolutePath().normalize().toString();
        String separator = "─".repeat(60);
        String entry = "\n" + separator + "\nTimestamp : " + Instant.now() + "\nEventId   : " + eventId + "\n" + rawJson + "\n";

        try (PrintWriter pw = new PrintWriter(new FileWriter(logPath, true))) {
            pw.print(entry);
        }
        System.out.println("\nRaw response written to " + logPath);
    }
}
