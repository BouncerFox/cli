// Package upload provides the BouncerFox platform upload client and config pull.
package upload

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/bouncerfox/cli/pkg/document"
)

// httpClient is used for all platform API requests (with a 30-second timeout).
var httpClient = &http.Client{Timeout: 30 * time.Second}

// Version is the payload schema version.
const Version = "1.0"

// ScannerVersion and CLIVersion identify the tool in upload payloads.
const (
	ScannerVersion = "0.1.0"
	CLIVersion     = "0.1.0"
)

// UploadOptions contains all inputs for Upload.
type UploadOptions struct {
	PlatformURL string // e.g., "https://api.bouncerfox.dev"
	APIKey      string
	Repo        string // from git remote
	CommitSHA   string // from git rev-parse HEAD
	StripPaths  bool   // send filenames only (filepath.Base)
	Anonymous   bool   // strip all identifying info (repo + file paths)
	DryRun      bool   // print payload to w, don't send
	Findings    []document.ScanFinding
	ScanMeta    ScanMeta
}

// ScanMeta holds scan timing and count metadata.
type ScanMeta struct {
	Timestamp    string
	DurationMs   int
	TotalFiles   int
	ScannedFiles int
	Profile      string
}

// uploadFinding is the wire representation of a finding in the upload payload.
type uploadFinding struct {
	RuleID      string         `json:"rule_id"`
	Severity    string         `json:"severity"`
	Message     string         `json:"message"`
	Evidence    map[string]any `json:"evidence,omitempty"`
	Remediation string         `json:"remediation,omitempty"`
}

// uploadPayload is the full JSON body sent to the platform.
type uploadPayload struct {
	Version        string          `json:"version"`
	ScannerVersion string          `json:"scanner_version"`
	CLIVersion     string          `json:"cli_version"`
	Repo           string          `json:"repo,omitempty"`
	CommitSHA      string          `json:"commit_sha,omitempty"`
	Timestamp      string          `json:"timestamp,omitempty"`
	DurationMs     int             `json:"duration_ms"`
	TotalFiles     int             `json:"total_files"`
	ScannedFiles   int             `json:"scanned_files"`
	Profile        string          `json:"profile,omitempty"`
	Findings       []uploadFinding `json:"findings"`
}

// Upload builds a scan payload and either prints it (DryRun) or POSTs it to
// {PlatformURL}/api/v1/scans/upload.
func Upload(ctx context.Context, opts UploadOptions, w io.Writer) error {
	findings := buildFindings(opts.Findings, opts.StripPaths, opts.Anonymous)

	payload := uploadPayload{
		Version:        Version,
		ScannerVersion: ScannerVersion,
		CLIVersion:     CLIVersion,
		CommitSHA:      opts.CommitSHA,
		Timestamp:      opts.ScanMeta.Timestamp,
		DurationMs:     opts.ScanMeta.DurationMs,
		TotalFiles:     opts.ScanMeta.TotalFiles,
		ScannedFiles:   opts.ScanMeta.ScannedFiles,
		Profile:        opts.ScanMeta.Profile,
		Findings:       findings,
	}

	if !opts.Anonymous {
		payload.Repo = opts.Repo
	}

	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("upload: marshalling payload: %w", err)
	}

	if opts.DryRun {
		_, err = w.Write(data)
		return err
	}

	if err := validateHTTPS(opts.PlatformURL); err != nil {
		return err
	}

	endpoint := opts.PlatformURL + "/api/v1/scans/upload"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("upload: building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+opts.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("upload: executing request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("upload: server returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// PullConfig fetches the organisation config from the platform and writes it
// to outputPath. If the file already exists a warning is printed to stderr.
func PullConfig(ctx context.Context, platformURL, apiKey, outputPath string) error {
	if err := validateHTTPS(platformURL); err != nil {
		return err
	}

	if _, err := os.Stat(outputPath); err == nil {
		fmt.Fprintf(os.Stderr, "warning: %s already exists, overwriting\n", outputPath)
	}

	endpoint := platformURL + "/api/v1/config/pull"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return fmt.Errorf("config pull: building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("config pull: executing request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return fmt.Errorf("config pull: reading response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("config pull: server returned %d: %s", resp.StatusCode, string(body))
	}

	if err := os.WriteFile(outputPath, body, 0o600); err != nil {
		return fmt.Errorf("config pull: writing %s: %w", outputPath, err)
	}

	return nil
}

// --- internal helpers -------------------------------------------------------

// validateHTTPS returns an error if rawURL does not use the https scheme.
func validateHTTPS(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("upload: invalid URL %q: %w", rawURL, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("upload: platform URL must use HTTPS (got %q)", rawURL)
	}
	return nil
}

// buildFindings converts ScanFindings to the wire format, applying path
// transformations according to stripPaths and anonymous flags.
func buildFindings(findings []document.ScanFinding, stripPaths, anonymous bool) []uploadFinding {
	out := make([]uploadFinding, 0, len(findings))
	for _, f := range findings {
		ev := transformEvidence(f.Evidence, stripPaths, anonymous)
		out = append(out, uploadFinding{
			RuleID:      f.RuleID,
			Severity:    string(f.Severity),
			Message:     f.Message,
			Evidence:    ev,
			Remediation: f.Remediation,
		})
	}
	return out
}

// transformEvidence applies path transformations to an evidence map.
func transformEvidence(ev map[string]any, stripPaths, anonymous bool) map[string]any {
	if ev == nil {
		return nil
	}
	cp := make(map[string]any, len(ev))
	for k, v := range ev {
		cp[k] = v
	}
	if anonymous {
		delete(cp, "file")
	} else if stripPaths {
		if file, ok := cp["file"].(string); ok && file != "" {
			cp["file"] = filepath.Base(file)
		}
	}
	return cp
}
