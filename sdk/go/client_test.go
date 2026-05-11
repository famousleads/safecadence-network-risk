package safecadence

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func mockServer(t *testing.T, status int, body []byte, contentType string,
	extraHeaders map[string]string, verifier func(r *http.Request)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if verifier != nil {
			verifier(r)
		}
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		for k, v := range extraHeaders {
			w.Header().Set(k, v)
		}
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
}

func mustJSON(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestListInventory(t *testing.T) {
	body := mustJSON(t, []Asset{{ID: "a1", Hostname: "core-sw-1"}})
	srv := mockServer(t, 200, body, "application/json", nil, func(r *http.Request) {
		if r.URL.Path != "/api/v1/inventory" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer k" {
			t.Errorf("missing bearer auth")
		}
	})
	defer srv.Close()

	c := NewClient(srv.URL, "k")
	hosts, err := c.ListInventory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || hosts[0].Hostname != "core-sw-1" {
		t.Errorf("unexpected hosts: %+v", hosts)
	}
}

func TestListInventoryItemsEnvelope(t *testing.T) {
	body := mustJSON(t, map[string]interface{}{
		"items": []Asset{{ID: "x"}, {ID: "y"}},
		"total": 2,
	})
	srv := mockServer(t, 200, body, "application/json", nil, nil)
	defer srv.Close()
	c := NewClient(srv.URL, "")
	hosts, err := c.ListInventory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 2 {
		t.Errorf("expected 2 hosts, got %d", len(hosts))
	}
}

func TestGetAsset(t *testing.T) {
	body := mustJSON(t, Asset{ID: "a1", Hostname: "h"})
	srv := mockServer(t, 200, body, "application/json", nil, func(r *http.Request) {
		if r.URL.Path != "/api/v1/inventory/a1" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
	})
	defer srv.Close()
	c := NewClient(srv.URL, "")
	a, err := c.GetAsset(context.Background(), "a1")
	if err != nil {
		t.Fatal(err)
	}
	if a.Hostname != "h" {
		t.Errorf("wrong asset")
	}
}

func TestComposeReportReturnsBytes(t *testing.T) {
	pdfBody := []byte("%PDF-1.4 fake bytes")
	srv := mockServer(t, 200, pdfBody, "application/pdf", nil, func(r *http.Request) {
		if r.URL.Path != "/api/reports/render-download" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("expected POST")
		}
		var body map[string]interface{}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		if body["preset_id"] != "exec_brief" || body["format"] != "pdf" {
			t.Errorf("wrong body: %+v", body)
		}
	})
	defer srv.Close()
	c := NewClient(srv.URL, "")
	out, err := c.ComposeReport(context.Background(),
		ComposeOptions{Preset: "exec_brief", Format: "pdf"})
	if err != nil {
		t.Fatal(err)
	}
	if string(out[:4]) != "%PDF" {
		t.Errorf("expected PDF bytes")
	}
}

func TestGenerateReport(t *testing.T) {
	body := mustJSON(t, GenerateJob{ID: "job_1", Status: "queued"})
	srv := mockServer(t, 200, body, "application/json", nil, nil)
	defer srv.Close()
	c := NewClient(srv.URL, "")
	j, err := c.GenerateReport(context.Background(), "technical_deepdive", "docx")
	if err != nil {
		t.Fatal(err)
	}
	if j.ID != "job_1" {
		t.Errorf("wrong id")
	}
}

func TestGetFindingsFilter(t *testing.T) {
	body := mustJSON(t, []Finding{{ID: "f1", Severity: "critical"}})
	srv := mockServer(t, 200, body, "application/json", nil, func(r *http.Request) {
		if r.URL.Query().Get("severity") != "critical" {
			t.Errorf("missing severity filter")
		}
	})
	defer srv.Close()
	c := NewClient(srv.URL, "")
	f, err := c.GetFindings(context.Background(), FindingFilters{Severity: "critical"})
	if err != nil {
		t.Fatal(err)
	}
	if len(f) != 1 || f[0].Severity != "critical" {
		t.Errorf("unexpected findings")
	}
}

func TestSaveTemplate(t *testing.T) {
	body := mustJSON(t, Template{ID: "t9", Name: "Board", Sections: []string{"risk_register"}})
	srv := mockServer(t, 200, body, "application/json", nil, func(r *http.Request) {
		var body map[string]interface{}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		if body["name"] != "Board" {
			t.Errorf("wrong name")
		}
	})
	defer srv.Close()
	c := NewClient(srv.URL, "")
	tpl, err := c.SaveTemplate(context.Background(), "Board", []string{"risk_register"},
		map[string]interface{}{"sites": []string{"nyc"}})
	if err != nil {
		t.Fatal(err)
	}
	if tpl.ID != "t9" {
		t.Errorf("wrong id")
	}
}

func TestAuthError(t *testing.T) {
	srv := mockServer(t, 401, []byte(`{"detail":"no"}`), "application/json", nil, nil)
	defer srv.Close()
	c := NewClient(srv.URL, "")
	_, err := c.ListInventory(context.Background())
	var ae *AuthError
	if !errors.As(err, &ae) {
		t.Fatalf("expected AuthError, got %T", err)
	}
}

func TestNotFound(t *testing.T) {
	srv := mockServer(t, 404, []byte(`{"detail":"no"}`), "application/json", nil, nil)
	defer srv.Close()
	c := NewClient(srv.URL, "")
	_, err := c.GetAsset(context.Background(), "missing")
	var nfe *NotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("expected NotFoundError, got %T", err)
	}
}

func TestRateLimit(t *testing.T) {
	srv := mockServer(t, 429, []byte(`{"detail":"slow"}`),
		"application/json", map[string]string{"Retry-After": "30"}, nil)
	defer srv.Close()
	c := NewClient(srv.URL, "")
	_, err := c.ListInventory(context.Background())
	var re *RateLimitError
	if !errors.As(err, &re) {
		t.Fatalf("expected RateLimitError, got %T", err)
	}
	if re.RetryAfter.Seconds() != 30 {
		t.Errorf("retry-after not parsed")
	}
}
