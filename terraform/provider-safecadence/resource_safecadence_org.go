package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceOrg() *schema.Resource {
	return &schema.Resource{
		Description:   "Manages a SafeCadence organization.",
		CreateContext: resourceOrgCreate,
		ReadContext:   resourceOrgRead,
		UpdateContext: resourceOrgUpdate,
		DeleteContext: resourceOrgDelete,
		Importer:      &schema.ResourceImporter{StateContext: schema.ImportStatePassthroughContext},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Human-readable org name.",
			},
			"slug": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "URL-safe org slug. Auto-generated from name when omitted.",
			},
			"plan": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "starter",
				Description: "Subscription plan id (free, starter, professional, enterprise).",
			},
			"primary_domain": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Primary email domain for SSO + invites.",
			},
		},
	}
}

func orgPayload(d *schema.ResourceData) map[string]interface{} {
	p := map[string]interface{}{
		"name": d.Get("name").(string),
		"plan": d.Get("plan").(string),
	}
	if v, ok := d.GetOk("slug"); ok {
		p["slug"] = v.(string)
	}
	if v, ok := d.GetOk("primary_domain"); ok {
		p["primary_domain"] = v.(string)
	}
	return p
}

func resourceOrgCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	cli := meta.(*providerClient)
	body, _ := json.Marshal(orgPayload(d))
	resp, err := cli.do(ctx, http.MethodPost, "/api/v1/orgs", body)
	if err != nil {
		return diag.FromErr(err)
	}
	var out struct {
		ID            string `json:"id"`
		Slug          string `json:"slug"`
		PrimaryDomain string `json:"primary_domain"`
	}
	if err := json.Unmarshal(resp, &out); err != nil {
		return diag.FromErr(err)
	}
	d.SetId(out.ID)
	_ = d.Set("slug", out.Slug)
	return resourceOrgRead(ctx, d, meta)
}

func resourceOrgRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	cli := meta.(*providerClient)
	resp, err := cli.do(ctx, http.MethodGet, "/api/v1/orgs/"+d.Id(), nil)
	if err != nil {
		return diag.FromErr(err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(resp, &out); err != nil {
		return diag.FromErr(err)
	}
	if v, ok := out["name"].(string); ok {
		_ = d.Set("name", v)
	}
	if v, ok := out["slug"].(string); ok {
		_ = d.Set("slug", v)
	}
	if v, ok := out["plan"].(string); ok {
		_ = d.Set("plan", v)
	}
	if v, ok := out["primary_domain"].(string); ok {
		_ = d.Set("primary_domain", v)
	}
	return nil
}

func resourceOrgUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	cli := meta.(*providerClient)
	body, _ := json.Marshal(orgPayload(d))
	if _, err := cli.do(ctx, http.MethodPatch, "/api/v1/orgs/"+d.Id(), body); err != nil {
		return diag.FromErr(err)
	}
	return resourceOrgRead(ctx, d, meta)
}

func resourceOrgDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	cli := meta.(*providerClient)
	if _, err := cli.do(ctx, http.MethodDelete, "/api/v1/orgs/"+d.Id(), nil); err != nil {
		return diag.FromErr(err)
	}
	d.SetId("")
	return nil
}

// do is a small HTTP helper attached to providerClient.
func (c *providerClient) do(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.APIURL+path, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return raw, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(raw))
	}
	return raw, nil
}
