package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	DatabaseURL string

	IMAPAddr          string // empty disables the poller
	IMAPUser          string
	IMAPPassword      string
	IMAPTLSSkipVerify bool
	PollInterval      time.Duration

	FolderProcessed string
	FolderIgnored   string
	FolderFailed    string

	APIAddr string
	APIKeys map[string]struct{}

	WebhookURL    string
	WebhookSecret string

	StoreRawXML  bool
	MaxBodyBytes int64
}

func get(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func Load() (*Config, error) {
	c := &Config{
		DatabaseURL:     os.Getenv("PARSER_DATABASE_URL"),
		IMAPAddr:        get("PARSER_IMAP_ADDR", "mailserver:993"),
		IMAPUser:        get("PARSER_IMAP_USER", "dmarc@example.org"),
		FolderProcessed: get("PARSER_FOLDER_PROCESSED", "Processed"),
		FolderIgnored:   get("PARSER_FOLDER_IGNORED", "Ignored"),
		FolderFailed:    get("PARSER_FOLDER_FAILED", "Failed"),
		APIAddr:         get("PARSER_API_ADDR", ":8080"),
		WebhookURL:      os.Getenv("PARSER_WEBHOOK_URL"),
		WebhookSecret:   os.Getenv("PARSER_WEBHOOK_SECRET"),
		APIKeys:         map[string]struct{}{},
	}
	if c.DatabaseURL == "" {
		return nil, fmt.Errorf("PARSER_DATABASE_URL is required")
	}

	c.IMAPTLSSkipVerify = get("PARSER_IMAP_TLS_SKIP_VERIFY", "false") == "true"
	c.StoreRawXML = get("PARSER_STORE_RAW_XML", "true") == "true"

	var err error
	if c.PollInterval, err = time.ParseDuration(get("PARSER_POLL_INTERVAL", "5m")); err != nil {
		return nil, fmt.Errorf("PARSER_POLL_INTERVAL: %w", err)
	}
	if c.MaxBodyBytes, err = strconv.ParseInt(get("PARSER_MAX_BODY_BYTES", "67108864"), 10, 64); err != nil {
		return nil, fmt.Errorf("PARSER_MAX_BODY_BYTES: %w", err)
	}

	c.IMAPPassword = os.Getenv("PARSER_IMAP_PASSWORD")
	if file := get("PARSER_IMAP_PASSWORD_FILE", "/run/secrets/mailbox-password"); c.IMAPPassword == "" && file != "" {
		if b, err := os.ReadFile(file); err == nil {
			c.IMAPPassword = strings.TrimSpace(string(b))
		} else if c.IMAPAddr != "" {
			return nil, fmt.Errorf("reading %s: %w", file, err)
		}
	}
	if c.IMAPAddr != "" && c.IMAPPassword == "" {
		return nil, fmt.Errorf("IMAP enabled but no password (PARSER_IMAP_PASSWORD or PARSER_IMAP_PASSWORD_FILE)")
	}

	for _, k := range strings.Split(os.Getenv("PARSER_API_KEYS"), ",") {
		if k = strings.TrimSpace(k); k != "" {
			c.APIKeys[k] = struct{}{}
		}
	}
	return c, nil
}
