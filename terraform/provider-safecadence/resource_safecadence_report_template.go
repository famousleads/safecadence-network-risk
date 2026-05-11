package main

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceReportTemplate() *schema.Resource {
	return &schema.Resource{
		Description:   "Manages a SafeCadence report template.",
		CreateContext: resourceReportTemplateCreate,
		ReadContext:   resourceReportTemplateRead,
		UpdateContext: resourceReportTemplateUpdate,
		DeleteContext: resourceReportTemplateDelete,
		Importer:      &schema.ResourceImporter{StateContext: schema.ImportStatePassthroughContext},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Display name of the template.",
			},
			"sections": {
				Type:        schema.TypeList,
				Required:    true,
				Description: "Ordered list of section ids to include.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"scope": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Scope filters (sites, severities, asset_ids) as a string map.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"preset_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Optional preset id this template extends.",
			},
		},
	}
}

func templatePayload(d *schema.ResourceData) map[string]interface{} {
	sections := []string{}
	for _, s := range d.Get("sections").([]interface{}) {
		sections = append(sections, s.(string))
	}
	scope := map[string]interface{}{}
	if v, ok := d.GetOk("scope"); ok {
		for k, vv := range v.(map[string]interface{}) {
			scope[k] = vv
		}
	}
	payload := map[string]interface{}{
		"name":     d.Get("name").(string),
		"sections": sections,
		"scope":    scope,
	}
	if v, ok := d.GetOk("preset_id"); ok {
		payload["preset_id"] = v.(string)
	}
	return payload
}

func resourceReportTemplateCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	cli := meta.(*providerClient)
	body, _ := json.Marshal(templatePayload(d))
	resp, err := cli.do(ctx, http.MethodPost, "/api/reports/templates", body)
	if err != nil {
		return diag.FromErr(err)
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(resp, &out); err != nil {
		return diag.FromErr(err)
	}
	d.SetId(out.ID)
	return resourceReportTemplateRead(ctx, d, meta)
}

func resourceReportTemplateRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	cli := meta.(*providerClient)
	resp, err := cli.do(ctx, http.MethodGet, "/api/reports/templates/"+d.Id(), nil)
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
	if v, ok := out["sections"].([]interface{}); ok {
		_ = d.Set("sections", v)
	}
	return nil
}

func resourceReportTemplateUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	cli := meta.(*providerClient)
	body, _ := json.Marshal(templatePayload(d))
	if _, err := cli.do(ctx, http.MethodPatch, "/api/reports/templates/"+d.Id(), body); err != nil {
		return diag.FromErr(err)
	}
	return resourceReportTemplateRead(ctx, d, meta)
}

func resourceReportTemplateDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	cli := meta.(*providerClient)
	if _, err := cli.do(ctx, http.MethodDelete, "/api/reports/templates/"+d.Id(), nil); err != nil {
		return diag.FromErr(err)
	}
	d.SetId("")
	return nil
}
