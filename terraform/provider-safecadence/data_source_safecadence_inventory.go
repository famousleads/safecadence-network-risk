package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceInventory() *schema.Resource {
	return &schema.Resource{
		Description: "Read-only data source returning the current SafeCadence inventory.",
		ReadContext: dataSourceInventoryRead,
		Schema: map[string]*schema.Schema{
			"site": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Filter to a single site.",
			},
			"items": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id":          {Type: schema.TypeString, Computed: true},
						"hostname":    {Type: schema.TypeString, Computed: true},
						"vendor":      {Type: schema.TypeString, Computed: true},
						"site":        {Type: schema.TypeString, Computed: true},
						"criticality": {Type: schema.TypeString, Computed: true},
						"risk_score":  {Type: schema.TypeFloat, Computed: true},
					},
				},
			},
		},
	}
}

func dataSourceInventoryRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	cli := meta.(*providerClient)
	path := "/api/v1/inventory"
	if s, ok := d.GetOk("site"); ok {
		q := url.Values{}
		q.Set("site", s.(string))
		path = path + "?" + q.Encode()
	}
	resp, err := cli.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return diag.FromErr(err)
	}
	// Accept either bare array or {items: [...]}.
	var bare []map[string]interface{}
	if err := json.Unmarshal(resp, &bare); err != nil {
		var env struct {
			Items []map[string]interface{} `json:"items"`
		}
		if err2 := json.Unmarshal(resp, &env); err2 == nil {
			bare = env.Items
		} else {
			return diag.FromErr(err)
		}
	}

	items := make([]map[string]interface{}, 0, len(bare))
	for _, b := range bare {
		row := map[string]interface{}{
			"id":          asString(b["id"]),
			"hostname":    asString(b["hostname"]),
			"vendor":      asString(b["vendor"]),
			"site":        asString(b["site"]),
			"criticality": asString(b["criticality"]),
		}
		if v, ok := b["risk_score"].(float64); ok {
			row["risk_score"] = v
		}
		items = append(items, row)
	}
	_ = d.Set("items", items)
	d.SetId(time.Now().UTC().Format(time.RFC3339Nano))
	return nil
}

func asString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
