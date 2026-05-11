// Package safecadence is the official Go SDK for the SafeCadence NetRisk REST API.
//
// Example:
//
//	cli := safecadence.NewClient("https://demo.safecadence.com", "scapi_xxx")
//	hosts, err := cli.ListInventory(ctx)
//	if err != nil { log.Fatal(err) }
//	for _, h := range hosts { fmt.Println(h.Hostname) }
package safecadence

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Version of the SDK itself.
const Version = "0.1.0"

// Error is the base error type for SDK errors.
type Error struct {
	Message    string
	StatusCode int
	Body       string
}

func (e *Error) Error() string { return e.Message }

// AuthError is returned for 401/403 responses.
type AuthError struct{ *Error }

// NotFoundError is returned for 404 responses.
type NotFoundError struct{ *Error }

// RateLimitError is returned for 429 responses.
type RateLimitError struct {
	*Error
	RetryAfter time.Duration
}

// Client is the SafeCadence NetRisk API client.
type Client struct {
	BaseURL    string
	APIKey     string
	HTTPClient *http.Client
}

// NewClient constructs a Client with sensible defaults.
func NewClient(baseURL, apiKey string) *Client {
	return &Client{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		APIKey:     apiKey,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *Client) do(ctx context.Context, method, path string, params map[string]string,
	body interface{}, out interface{}, expectBytes bool) ([]byte, error) {

	u := c.BaseURL + path
	if len(params) > 0 {
		q := url.Values{}
		for k, v := range params {
			if v != "" {
				q.Set(k, v)
			}
		}
		if len(q) > 0 {
			u = u + "?" + q.Encode()
		}
	}

	var reqBody io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("encode body: %w", err)
		}
		reqBody = bytes.NewReader(buf)
	}

	req, err := http.NewRequestWithContext(ctx, method, u, reqBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "safecadence-sdk-go/"+Version)
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, &Error{Message: fmt.Sprintf("network error: %v", err)}
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	switch {
	case resp.StatusCode == 401, resp.StatusCode == 403:
		return nil, &AuthError{&Error{
			Message:    fmt.Sprintf("auth failed (%d)", resp.StatusCode),
			StatusCode: resp.StatusCode,
			Body:       string(raw),
		}}
	case resp.StatusCode == 404:
		return nil, &NotFoundError{&Error{
			Message:    fmt.Sprintf("not found: %s", path),
			StatusCode: resp.StatusCode,
			Body:       string(raw),
		}}
	case resp.StatusCode == 429:
		ra := time.Duration(0)
		if s := resp.Header.Get("Retry-After"); s != "" {
			if secs, err2 := strconv.Atoi(s); err2 == nil {
				ra = time.Duration(secs) * time.Second
			}
		}
		return nil, &RateLimitError{
			Error: &Error{
				Message:    "rate limited",
				StatusCode: resp.StatusCode,
				Body:       string(raw),
			},
			RetryAfter: ra,
		}
	case resp.StatusCode >= 400:
		return nil, &Error{
			Message:    fmt.Sprintf("HTTP %d: %s", resp.StatusCode, truncate(string(raw), 200)),
			StatusCode: resp.StatusCode,
			Body:       string(raw),
		}
	}

	if expectBytes {
		return raw, nil
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return raw, fmt.Errorf("decode response: %w", err)
		}
	}
	return raw, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// listEnvelope handles APIs that return either a bare array or {items: [...]}.
type listEnvelope struct {
	Items json.RawMessage `json:"items"`
}

func unmarshalList[T any](raw []byte) ([]T, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if raw[0] == '[' {
		var out []T
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, err
		}
		return out, nil
	}
	var env listEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	if len(env.Items) == 0 {
		return nil, nil
	}
	var out []T
	if err := json.Unmarshal(env.Items, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ---------------- Inventory ---------------- //

func (c *Client) ListInventory(ctx context.Context) ([]Asset, error) {
	raw, err := c.do(ctx, http.MethodGet, "/api/v1/inventory", nil, nil, nil, false)
	if err != nil {
		return nil, err
	}
	return unmarshalList[Asset](raw)
}

func (c *Client) GetAsset(ctx context.Context, id string) (*Asset, error) {
	var a Asset
	_, err := c.do(ctx, http.MethodGet, "/api/v1/inventory/"+url.PathEscape(id), nil, nil, &a, false)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// ---------------- Findings + compliance ---------------- //

func (c *Client) GetFindings(ctx context.Context, f FindingFilters) ([]Finding, error) {
	params := map[string]string{"severity": f.Severity, "asset_id": f.AssetID}
	raw, err := c.do(ctx, http.MethodGet, "/api/v1/findings", params, nil, nil, false)
	if err != nil {
		return nil, err
	}
	return unmarshalList[Finding](raw)
}

func (c *Client) GetComplianceStatus(ctx context.Context, framework string) (map[string]interface{}, error) {
	out := map[string]interface{}{}
	params := map[string]string{}
	if framework != "" {
		params["framework"] = framework
	}
	_, err := c.do(ctx, http.MethodGet, "/api/v1/compliance/status", params, nil, &out, false)
	return out, err
}

// ---------------- Reports ---------------- //

func (c *Client) ListReports(ctx context.Context) ([]Report, error) {
	raw, err := c.do(ctx, http.MethodGet, "/api/v1/reports", nil, nil, nil, false)
	if err != nil {
		return nil, err
	}
	return unmarshalList[Report](raw)
}

// ComposeReport runs the one-shot compose-and-download endpoint and returns the bytes.
func (c *Client) ComposeReport(ctx context.Context, opts ComposeOptions) ([]byte, error) {
	if opts.Format == "" {
		opts.Format = "html"
	}
	raw, err := c.do(ctx, http.MethodPost, "/api/reports/render-download", nil, opts, nil, true)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// GenerateReport kicks off the async report generation pipeline.
func (c *Client) GenerateReport(ctx context.Context, preset, format string) (*GenerateJob, error) {
	if format == "" {
		format = "pdf"
	}
	var job GenerateJob
	_, err := c.do(ctx, http.MethodPost, "/api/v1/reports/generate", nil,
		map[string]string{"preset": preset, "format": format}, &job, false)
	if err != nil {
		return nil, err
	}
	return &job, nil
}

// ---------------- Templates ---------------- //

func (c *Client) ListTemplates(ctx context.Context) ([]Template, error) {
	raw, err := c.do(ctx, http.MethodGet, "/api/reports/templates", nil, nil, nil, false)
	if err != nil {
		return nil, err
	}
	return unmarshalList[Template](raw)
}

func (c *Client) SaveTemplate(ctx context.Context, name string, sections []string,
	scope map[string]interface{}) (*Template, error) {
	body := map[string]interface{}{
		"name":     name,
		"sections": sections,
		"scope":    scope,
	}
	if scope == nil {
		body["scope"] = map[string]interface{}{}
	}
	var t Template
	_, err := c.do(ctx, http.MethodPost, "/api/reports/templates", nil, body, &t, false)
	if err != nil {
		return nil, err
	}
	return &t, nil
}
