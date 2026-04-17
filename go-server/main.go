package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	fingerprint "github.com/fingerprintjs/go-sdk/v8"
)

func loadEnv(filename string) {
	f, err := os.Open(filename)
	if err != nil {
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			os.Setenv(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}
}

func getAPIKey() string {
	// Load ../.env relative to the binary location
	exe, _ := os.Executable()
	loadEnv(filepath.Join(filepath.Dir(exe), "../.env"))
	// Also try current working directory parent
	loadEnv("../.env")
	loadEnv(".env")
	key := os.Getenv("FP_SERVER_API_KEY")
	if key == "" {
		log.Fatal("Missing FP_SERVER_API_KEY — set it in .env")
	}
	return key
}

func strVal(s *string) string {
	if s == nil {
		return "unknown"
	}
	return *s
}

func boolVal(b *bool) string {
	if b == nil {
		return "unknown"
	}
	if *b {
		return "true"
	}
	return "false"
}

func int32Val(i *int32) string {
	if i == nil {
		return "unknown"
	}
	return fmt.Sprintf("%d", *i)
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: go run main.go <event_id>")
	}
	eventID := os.Args[1]

	apiKey := getAPIKey()
	client := fingerprint.New(
		fingerprint.WithAPIKey(apiKey),
		fingerprint.WithRegion(fingerprint.RegionAsia),
	)

	event, _, err := client.GetEvent(context.Background(), eventID)
	if err != nil {
		if errResp, ok := fingerprint.AsErrorResponse(err); ok {
			log.Fatalf("Fingerprint API error [%s]: %v", errResp.Error.Code, errResp)
		}
		log.Fatalf("Request failed: %v", err)
	}

	// Parse city from ip_info
	city := "unknown"
	if event.IPInfo != nil {
		if event.IPInfo.V4 != nil && event.IPInfo.V4.Geolocation != nil {
			city = strVal(event.IPInfo.V4.Geolocation.CityName)
		} else if event.IPInfo.V6 != nil && event.IPInfo.V6.Geolocation != nil {
			city = strVal(event.IPInfo.V6.Geolocation.CityName)
		}
	}

	// Parse IP address
	ip := "unknown"
	if event.IPInfo != nil && event.IPInfo.V4 != nil {
		ip = event.IPInfo.V4.Address
	} else if event.IPInfo != nil && event.IPInfo.V6 != nil {
		ip = event.IPInfo.V6.Address
	}

	// Parse bot
	bot := "unknown"
	if event.Bot != nil {
		bot = string(*event.Bot)
	}

	fmt.Println("\nServer API response (Go SDK - v4):")
	fmt.Printf("  event_id      : %s\n", event.EventID)
	fmt.Printf("  visitor_id    : %s\n", event.Identification.VisitorID)
	fmt.Printf("  linked_id     : %s\n", strVal(event.LinkedID))
	fmt.Printf("  confidence    : %f\n", event.Identification.Confidence.Score)
	fmt.Printf("  suspect_score : %s\n", int32Val(event.SuspectScore))
	fmt.Printf("  browser       : %s\n", event.BrowserDetails.BrowserName)
	fmt.Printf("  os            : %s\n", event.BrowserDetails.Os)
	fmt.Printf("  ip            : %s\n", ip)
	fmt.Printf("  city          : %s\n", city)
	fmt.Printf("  bot           : %s\n", bot)
	fmt.Printf("  vpn           : %s\n", boolVal(event.VPN))
	fmt.Printf("  proxy         : %s\n", boolVal(event.Proxy))

	// Write raw response to go_server_response.txt in the parent directory
	raw, err := json.MarshalIndent(event, "", "  ")
	if err != nil {
		log.Printf("Failed to marshal response: %v", err)
		return
	}

	logPath := filepath.Join("..", "go_server_response.txt")
	separator := "\n" + fmt.Sprintf("%s", string(make([]byte, 60))) + "\n"
	_ = separator
	entry := fmt.Sprintf("\n%s\nTimestamp : %s\nEventId   : %s\n%s\n",
		"────────────────────────────────────────────────────────────",
		time.Now().UTC().Format(time.RFC3339),
		eventID,
		string(raw),
	)

	logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Failed to open log file: %v", err)
		return
	}
	defer logFile.Close()

	if _, err := logFile.WriteString(entry); err != nil {
		log.Printf("Failed to write log file: %v", err)
	}
}
