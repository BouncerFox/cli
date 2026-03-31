package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SupersededError is returned when the platform indicates a newer commit exists.
type SupersededError struct {
	Message string
}

func (e *SupersededError) Error() string {
	return "scan superseded: " + e.Message
}

// PaymentRequiredError is returned when the org's subscription has lapsed.
type PaymentRequiredError struct{}

func (e *PaymentRequiredError) Error() string {
	return "subscription lapsed"
}

// Client abstracts platform API calls for testability.
type Client interface {
	Upload(ctx context.Context, req UploadRequest) (*VerdictResponse, error)
	PullConfig(ctx context.Context, req PullConfigRequest) (*PullConfigResponse, error)
}

// SkillMetadata holds extracted metadata from a SKILL.md document.
type SkillMetadata struct {
	File        string `json:"file"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Status      string `json:"status,omitempty"`
	Model       string `json:"model,omitempty"`
}

// UploadRequest is the full upload payload.
type UploadRequest struct {
	Version        string          `json:"version"`
	CLIVersion     string          `json:"cli_version"`
	CLIChecksum    string          `json:"cli_checksum,omitempty"`
	Target         string          `json:"target,omitempty"`
	TargetLabel    string          `json:"target_label,omitempty"`
	CommitSHA      string          `json:"commit_sha,omitempty"`
	Branch         string          `json:"branch,omitempty"`
	Trigger        string          `json:"trigger"`
	Timestamp      string          `json:"timestamp"`
	DurationMs     int             `json:"duration_ms"`
	TotalFiles     int             `json:"total_files"`
	ScannedFiles   int             `json:"scanned_files"`
	Profile        string          `json:"profile,omitempty"`
	ConfigHash     string          `json:"config_hash,omitempty"`
	Findings       []WireFinding   `json:"findings"`
	PRNumber       int             `json:"pr_number,omitempty"`
	Skills         []SkillMetadata `json:"skills,omitempty"`
	IdempotencyKey string          `json:"-"` // sent as header, not body
}

// WireFinding is the flat finding format sent over the wire.
// Only allowlisted fields — no evidence map, no snippet.
type WireFinding struct {
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Message     string `json:"message"`
	File        string `json:"file,omitempty"`
	Line        int    `json:"line,omitempty"`
	Fingerprint string `json:"fingerprint"`
	Remediation string `json:"remediation,omitempty"`
}

// PullConfigRequest is the input for config pull.
type PullConfigRequest struct {
	Target string
	ETag   string // If-None-Match header value
}

// PullConfigResponse is the result of a config pull.
type PullConfigResponse struct {
	Body        string // raw YAML
	ETag        string
	NotModified bool // true if server returned 304
}

const (
	maxUploadBytes   = 10 * 1024 * 1024 // 10 MB request payload limit
	maxResponseBytes = 1 * 1024 * 1024  // 1 MB response body limit
)

// HTTPClient implements Client using net/http.
type HTTPClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// NewHTTPClient creates a platform HTTP client.
// Accepts http:// for testing; ValidateHTTPS should be called at CLI entry point.
func NewHTTPClient(baseURL, apiKey string) *HTTPClient {
	return &HTTPClient{
		baseURL:    strings.TrimRight(baseURL, "/"),
		apiKey:     apiKey,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// ValidateHTTPS returns an error if the URL does not use HTTPS.
// Localhost and 127.0.0.1 are exempt (safe for testing and local development).
func ValidateHTTPS(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid platform URL %q: %w", rawURL, err)
	}
	if u.Scheme == "https" {
		return nil
	}
	host := u.Hostname()
	if host == "localhost" || host == "127.0.0.1" {
		return nil
	}
	return fmt.Errorf("platform URL must use HTTPS (got %q)", rawURL)
}

func (c *HTTPClient) Upload(ctx context.Context, req UploadRequest) (*VerdictResponse, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("upload: marshal: %w", err)
	}

	if len(data) > maxUploadBytes {
		return nil, fmt.Errorf("upload: payload exceeds 10MB limit (%d bytes)", len(data))
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/scans/upload", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("upload: build request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	httpReq.Header.Set("Content-Type", "application/json")
	if req.IdempotencyKey != "" {
		httpReq.Header.Set("X-Idempotency-Key", req.IdempotencyKey)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("upload: request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode == 409 {
		return nil, &SupersededError{Message: string(body)}
	}
	if resp.StatusCode == 402 {
		return nil, &PaymentRequiredError{}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("upload: server returned %d: %s", resp.StatusCode, string(body))
	}

	var verdict VerdictResponse
	if err := json.Unmarshal(body, &verdict); err != nil {
		return nil, fmt.Errorf("upload: parse verdict: %w", err)
	}
	return &verdict, nil
}

func (c *HTTPClient) PullConfig(ctx context.Context, req PullConfigRequest) (*PullConfigResponse, error) {
	endpoint := c.baseURL + "/api/v1/config/pull"
	if req.Target != "" {
		endpoint += "?target=" + url.QueryEscape(req.Target)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("config pull: build request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	if req.ETag != "" {
		httpReq.Header.Set("If-None-Match", req.ETag)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("config pull: request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotModified {
		return &PullConfigResponse{NotModified: true, ETag: resp.Header.Get("ETag")}, nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("config pull: read body: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("config pull: server returned %d: %s", resp.StatusCode, string(body))
	}

	return &PullConfigResponse{
		Body: string(body),
		ETag: resp.Header.Get("ETag"),
	}, nil
}
