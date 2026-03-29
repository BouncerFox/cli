package platform

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

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

	c := NewHTTPClient(srv.URL, "bf_test")
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

	c := NewHTTPClient(srv.URL, "bf_test")
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

	c := NewHTTPClient(srv.URL, "bf_test")
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

	c := NewHTTPClient(srv.URL, "bf_test")
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

	c := NewHTTPClient(srv.URL, "bf_test")
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
