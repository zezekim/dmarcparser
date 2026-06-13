package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Scope names accepted in PARSER_API_KEYS.
const (
	ScopeRead   = "read"
	ScopeIngest = "ingest"
	ScopeAdmin  = "admin"
)

// APIKey is one entry from PARSER_API_KEYS (`name=key=scopes`, scopes
// pipe-separated from {read, ingest, admin}, `*` = all). A bare `key` entry
// is accepted for backward compatibility as name "default" with all scopes.
type APIKey struct {
	Name   string
	Key    string
	Scopes map[string]bool
}

func (k APIKey) HasScope(scope string) bool { return k.Scopes[scope] }

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
	APIKeys []APIKey

	RateLimitRPS float64

	WebhookURLs   []string
	WebhookSecret string

	AlertURL         string
	AlertSilence     time.Duration
	AlertFailedSpike int64

	AnomalySigma     float64
	AnomalyMinFails  int64
	NewSenderMinMsgs int64

	RawXMLRetention time.Duration // 0 = keep forever
	MailRetention   time.Duration // 0 = keep forever

	RUFRedact     bool
	EnrichWorkers int

	DigestEnabled  bool
	DigestSMTPAddr string
	DigestSMTPUser string
	DigestFrom     string
	DigestDay      time.Weekday
	DigestHour     int

	ViewerURL string

	StoreRawXML  bool
	MaxBodyBytes int64
}

func get(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func getDuration(key, def string) (time.Duration, error) {
	d, err := time.ParseDuration(get(key, def))
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return d, nil
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
		WebhookSecret:   os.Getenv("PARSER_WEBHOOK_SECRET"),
		AlertURL:        os.Getenv("PARSER_ALERT_URL"),
		ViewerURL:       os.Getenv("PARSER_VIEWER_URL"),
		DigestSMTPAddr:  get("PARSER_DIGEST_SMTP_ADDR", "mailserver:587"),
	}
	if c.DatabaseURL == "" {
		return nil, fmt.Errorf("PARSER_DATABASE_URL is required")
	}

	c.IMAPTLSSkipVerify = get("PARSER_IMAP_TLS_SKIP_VERIFY", "false") == "true"
	c.StoreRawXML = get("PARSER_STORE_RAW_XML", "true") == "true"
	c.RUFRedact = get("PARSER_RUF_REDACT", "true") == "true"
	c.DigestEnabled = get("PARSER_DIGEST_ENABLED", "false") == "true"
	c.DigestSMTPUser = get("PARSER_DIGEST_SMTP_USER", c.IMAPUser)
	c.DigestFrom = get("PARSER_DIGEST_FROM", c.IMAPUser)

	var err error
	if c.PollInterval, err = getDuration("PARSER_POLL_INTERVAL", "5m"); err != nil {
		return nil, err
	}
	if c.AlertSilence, err = getDuration("PARSER_ALERT_SILENCE", "36h"); err != nil {
		return nil, err
	}
	if c.RawXMLRetention, err = getDuration("PARSER_RAW_XML_RETENTION", "2160h"); err != nil {
		return nil, err
	}
	if c.MailRetention, err = getDuration("PARSER_MAIL_RETENTION", "720h"); err != nil {
		return nil, err
	}
	if c.MaxBodyBytes, err = strconv.ParseInt(get("PARSER_MAX_BODY_BYTES", "67108864"), 10, 64); err != nil {
		return nil, fmt.Errorf("PARSER_MAX_BODY_BYTES: %w", err)
	}
	if c.RateLimitRPS, err = strconv.ParseFloat(get("PARSER_RATE_LIMIT_RPS", "10"), 64); err != nil {
		return nil, fmt.Errorf("PARSER_RATE_LIMIT_RPS: %w", err)
	}
	if c.AnomalySigma, err = strconv.ParseFloat(get("PARSER_ANOMALY_SIGMA", "3"), 64); err != nil {
		return nil, fmt.Errorf("PARSER_ANOMALY_SIGMA: %w", err)
	}
	if c.AlertFailedSpike, err = strconv.ParseInt(get("PARSER_ALERT_FAILED_SPIKE", "10"), 10, 64); err != nil {
		return nil, fmt.Errorf("PARSER_ALERT_FAILED_SPIKE: %w", err)
	}
	if c.AnomalyMinFails, err = strconv.ParseInt(get("PARSER_ANOMALY_MIN_FAILS", "50"), 10, 64); err != nil {
		return nil, fmt.Errorf("PARSER_ANOMALY_MIN_FAILS: %w", err)
	}
	if c.NewSenderMinMsgs, err = strconv.ParseInt(get("PARSER_NEWSENDER_MIN_MSGS", "5"), 10, 64); err != nil {
		return nil, fmt.Errorf("PARSER_NEWSENDER_MIN_MSGS: %w", err)
	}
	if c.EnrichWorkers, err = strconv.Atoi(get("PARSER_ENRICH_WORKERS", "4")); err != nil {
		return nil, fmt.Errorf("PARSER_ENRICH_WORKERS: %w", err)
	}
	if c.DigestHour, err = strconv.Atoi(get("PARSER_DIGEST_HOUR", "7")); err != nil || c.DigestHour < 0 || c.DigestHour > 23 {
		return nil, fmt.Errorf("PARSER_DIGEST_HOUR: must be 0-23")
	}
	if c.DigestDay, err = parseWeekday(get("PARSER_DIGEST_DAY", "Monday")); err != nil {
		return nil, err
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

	if c.APIKeys, err = parseAPIKeys(os.Getenv("PARSER_API_KEYS")); err != nil {
		return nil, err
	}

	c.WebhookURLs = splitNonEmpty(os.Getenv("PARSER_WEBHOOK_URLS"))
	if len(c.WebhookURLs) == 0 {
		c.WebhookURLs = splitNonEmpty(os.Getenv("PARSER_WEBHOOK_URL"))
	}
	return c, nil
}

func parseAPIKeys(raw string) ([]APIKey, error) {
	var keys []APIKey
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, "=", 3)
		k := APIKey{Scopes: map[string]bool{}}
		switch len(parts) {
		case 1: // legacy bare key: all scopes
			k.Name, k.Key = "default", parts[0]
			k.Scopes[ScopeRead], k.Scopes[ScopeIngest], k.Scopes[ScopeAdmin] = true, true, true
		case 3:
			k.Name, k.Key = parts[0], parts[1]
			for _, sc := range strings.Split(parts[2], "|") {
				switch sc = strings.TrimSpace(sc); sc {
				case "*":
					k.Scopes[ScopeRead], k.Scopes[ScopeIngest], k.Scopes[ScopeAdmin] = true, true, true
				case ScopeRead, ScopeIngest, ScopeAdmin:
					k.Scopes[sc] = true
				case "":
				default:
					return nil, fmt.Errorf("PARSER_API_KEYS: unknown scope %q for key %q", sc, k.Name)
				}
			}
		default:
			return nil, fmt.Errorf("PARSER_API_KEYS: entry %q: want key or name=key=scopes", k.Name)
		}
		if k.Key == "" || len(k.Scopes) == 0 {
			return nil, fmt.Errorf("PARSER_API_KEYS: entry for %q has empty key or no scopes", k.Name)
		}
		keys = append(keys, k)
	}
	return keys, nil
}

func parseWeekday(s string) (time.Weekday, error) {
	for d := time.Sunday; d <= time.Saturday; d++ {
		if strings.EqualFold(d.String(), s) {
			return d, nil
		}
	}
	return 0, fmt.Errorf("PARSER_DIGEST_DAY: unknown weekday %q", s)
}

func splitNonEmpty(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
