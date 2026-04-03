package platform

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func mustNewHTTPClient(t *testing.T, baseURL, apiKey string) *HTTPClient {
	t.Helper()
	c, err := NewHTTPClient(baseURL, apiKey)
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	return c
}

func TestHTTPClient_Upload_ReturnsVerdict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/scans/upload" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer bf_test" {
			w.WriteHeader(401)
			return
		}
		if r.Header.Get("X-Idempotency-Key") == "" {
			t.Error("missing idempotency key header")
		}
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(VerdictResponse{
			ScanID:  "uuid-1",
			Verdict: "pass",
		})
	}))
	defer srv.Close()

	c := mustNewHTTPClient(t, srv.URL, "bf_test")
	resp, err := c.Upload(context.Background(), UploadRequest{
		IdempotencyKey: "test-key",
	})
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if resp.Verdict != "pass" {
		t.Errorf("expected pass, got %q", resp.Verdict)
	}
}

func TestHTTPClient_Upload_Non2xxError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(422)
		w.Write([]byte(`{"error":"invalid_payload","message":"bad"}`))
	}))
	defer srv.Close()

	c := mustNewHTTPClient(t, srv.URL, "bf_test")
	_, err := c.Upload(context.Background(), UploadRequest{})
	if err == nil {
		t.Fatal("expected error for 422")
	}
}

func TestHTTPClient_PullConfig_ReturnsYAML(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/config/pull" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("target") != "github:test/repo" {
			t.Errorf("unexpected target param: %q", r.URL.Query().Get("target"))
		}
		w.Header().Set("ETag", `"abc123"`)
		w.WriteHeader(200)
		io.WriteString(w, "profile: recommended\n")
	}))
	defer srv.Close()

	c := mustNewHTTPClient(t, srv.URL, "bf_test")
	resp, err := c.PullConfig(context.Background(), PullConfigRequest{Target: "github:test/repo"})
	if err != nil {
		t.Fatalf("PullConfig: %v", err)
	}
	if resp.Body != "profile: recommended\n" {
		t.Errorf("unexpected body: %q", resp.Body)
	}
	if resp.ETag != `"abc123"` {
		t.Errorf("unexpected etag: %q", resp.ETag)
	}
}

func TestHTTPClient_PullConfig_304NotModified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"cached"` {
			w.WriteHeader(304)
			return
		}
		w.WriteHeader(200)
		io.WriteString(w, "profile: all_rules\n")
	}))
	defer srv.Close()

	c := mustNewHTTPClient(t, srv.URL, "bf_test")
	resp, err := c.PullConfig(context.Background(), PullConfigRequest{ETag: `"cached"`})
	if err != nil {
		t.Fatalf("PullConfig: %v", err)
	}
	if !resp.NotModified {
		t.Error("expected NotModified=true for 304")
	}
}

func TestValidateHTTPS_RejectsHTTP(t *testing.T) {
	err := ValidateHTTPS("http://example.com")
	if err == nil {
		t.Fatal("expected error for HTTP URL")
	}
}

func TestValidateHTTPS_AcceptsHTTPS(t *testing.T) {
	err := ValidateHTTPS("https://example.com")
	if err != nil {
		t.Fatalf("unexpected error for HTTPS: %v", err)
	}
}

func TestValidateHTTPS_AllowsLocalhost(t *testing.T) {
	for _, u := range []string{
		"http://localhost:8080",
		"http://127.0.0.1:9090",
		"http://localhost",
	} {
		if err := ValidateHTTPS(u); err != nil {
			t.Errorf("ValidateHTTPS(%q) should allow localhost, got: %v", u, err)
		}
	}
}

func TestNewHTTPClient_AllowedDomain(t *testing.T) {
	_, err := NewHTTPClient("https://api.bouncerfox.dev", "key")
	if err != nil {
		t.Fatalf("expected success for allowed domain: %v", err)
	}
}

func TestNewHTTPClient_AllowedDomainTrailingSlash(t *testing.T) {
	_, err := NewHTTPClient("https://api.bouncerfox.dev/", "key")
	if err != nil {
		t.Fatalf("expected success for allowed domain with trailing slash: %v", err)
	}
}

func TestNewHTTPClient_LocalhostHTTP(t *testing.T) {
	_, err := NewHTTPClient("http://localhost:8080", "key")
	if err != nil {
		t.Fatalf("expected success for localhost HTTP: %v", err)
	}
}

func TestNewHTTPClient_127001HTTP(t *testing.T) {
	_, err := NewHTTPClient("http://127.0.0.1:9090", "key")
	if err != nil {
		t.Fatalf("expected success for 127.0.0.1 HTTP: %v", err)
	}
}

func TestNewHTTPClient_RejectsHTTP(t *testing.T) {
	_, err := NewHTTPClient("http://api.bouncerfox.dev", "key")
	if err == nil {
		t.Fatal("expected error for HTTP non-localhost URL")
	}
}

func TestNewHTTPClient_RejectsUnknownDomain(t *testing.T) {
	_, err := NewHTTPClient("https://evil.com", "key")
	if err == nil {
		t.Fatal("expected error for unknown domain")
	}
}

func TestNewHTTPClient_RejectsDomainSquatting(t *testing.T) {
	_, err := NewHTTPClient("https://api.bouncerfox.dev.evil.com", "key")
	if err == nil {
		t.Fatal("expected error for domain squatting attempt")
	}
}

func TestNewHTTPClient_RejectsInvalidURL(t *testing.T) {
	_, err := NewHTTPClient("not-a-url://???", "key")
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

func TestHTTPClient_Upload_IncludesPRNumber(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		json.Unmarshal(body, &req)
		if req["pr_number"] != float64(42) {
			t.Errorf("expected pr_number=42, got %v", req["pr_number"])
		}
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(VerdictResponse{ScanID: "s1", Verdict: "pass"})
	}))
	defer srv.Close()

	c := mustNewHTTPClient(t, srv.URL, "bf_test")
	_, err := c.Upload(context.Background(), UploadRequest{
		PRNumber:       42,
		IdempotencyKey: "test",
	})
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
}

func TestValidateHTTPS_StillRejectsRemoteHTTP(t *testing.T) {
	for _, u := range []string{
		"http://example.com",
		"http://api.bouncerfox.dev",
	} {
		if err := ValidateHTTPS(u); err == nil {
			t.Errorf("ValidateHTTPS(%q) should reject remote HTTP", u)
		}
	}
}

func TestHTTPClient_Upload_409Superseded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(409)
		w.Write([]byte(`{"error":"scan_superseded","message":"newer commit exists"}`))
	}))
	defer srv.Close()

	c := mustNewHTTPClient(t, srv.URL, "bf_test")
	_, err := c.Upload(context.Background(), UploadRequest{})
	if err == nil {
		t.Fatal("expected error for 409")
	}
	var superErr *SupersededError
	if !errors.As(err, &superErr) {
		t.Errorf("expected SupersededError, got %T: %v", err, err)
	}
}

func TestHTTPClient_Upload_BrokenResponseBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set Content-Length to promise more bytes than we actually send,
		// which causes io.ReadAll to return an unexpected EOF error.
		w.Header().Set("Content-Length", "9999")
		w.WriteHeader(201)
		w.Write([]byte(`{"scan_id"`))
		// Deliberately close without sending all promised bytes.
	}))
	defer srv.Close()

	c := mustNewHTTPClient(t, srv.URL, "bf_test")
	_, err := c.Upload(context.Background(), UploadRequest{})
	if err == nil {
		t.Fatal("expected error for broken response body")
	}
	if !strings.Contains(err.Error(), "reading upload response") {
		t.Errorf("expected 'reading upload response' in error, got: %v", err)
	}
}

func TestHTTPClient_Upload_402PaymentRequired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(402)
		w.Write([]byte(`{"error":"payment_required"}`))
	}))
	defer srv.Close()

	c := mustNewHTTPClient(t, srv.URL, "bf_test")
	_, err := c.Upload(context.Background(), UploadRequest{})
	if err == nil {
		t.Fatal("expected error for 402")
	}
	var payErr *PaymentRequiredError
	if !errors.As(err, &payErr) {
		t.Errorf("expected PaymentRequiredError, got %T: %v", err, err)
	}
}
