package main

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// providerClient is the runtime client passed via meta.
type providerClient struct {
	APIURL     string
	APIKey     string
	HTTPClient *http.Client
}

// Provider returns the SafeCadence Terraform provider schema.
func Provider() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"api_url": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("SAFECADENCE_API_URL", nil),
				Description: "Base URL of the SafeCadence NetRisk API (e.g. https://app.safecadence.com).",
			},
			"api_key": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				DefaultFunc: schema.EnvDefaultFunc("SAFECADENCE_API_KEY", nil),
				Description: "API key with at least 'write' scope.",
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"safecadence_org":             resourceOrg(),
			"safecadence_report_template": resourceReportTemplate(),
		},
		DataSourcesMap: map[string]*schema.Resource{
			"safecadence_inventory": dataSourceInventory(),
		},
		ConfigureContextFunc: configureProvider,
	}
}

func configureProvider(_ context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
	apiURL := strings.TrimRight(d.Get("api_url").(string), "/")
	apiKey := d.Get("api_key").(string)
	if apiURL == "" {
		return nil, diag.Errorf("api_url is required")
	}
	if apiKey == "" {
		return nil, diag.Errorf("api_key is required")
	}
	return &providerClient{
		APIURL:     apiURL,
		APIKey:     apiKey,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}, nil
}
