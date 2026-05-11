# terraform-provider-safecadence

Terraform provider for SafeCadence NetRisk.

> **Scaffold.** This is the initial public scaffold. The `terraform-plugin-sdk/v2`
> dependency is referenced in `go.mod` but commented out — run `go mod tidy`
> the first time you build to fetch it.

## Resources

| Type | Description |
|---|---|
| `safecadence_org` | A SafeCadence organization (tenant). |
| `safecadence_report_template` | A persisted report template. |

## Data sources

| Type | Description |
|---|---|
| `safecadence_inventory` | Read-only inventory, optionally filtered by site. |

## Usage

```hcl
terraform {
  required_providers {
    safecadence = {
      source  = "famousleads/safecadence"
      version = "~> 0.1"
    }
  }
}

provider "safecadence" {
  api_url = "https://app.safecadence.com"
  api_key = var.safecadence_api_key
}

resource "safecadence_org" "acme" {
  name           = "Acme Corp"
  plan           = "professional"
  primary_domain = "acme.com"
}

resource "safecadence_report_template" "board_pack" {
  name     = "Monthly board pack"
  sections = [
    "compliance_executive_summary",
    "risk_register",
    "kev_priority",
  ]
  scope = {
    sites = "nyc-dc-1"
  }
}

data "safecadence_inventory" "all" {}

output "host_count" {
  value = length(data.safecadence_inventory.all.items)
}
```

## Build

```
cd terraform/provider-safecadence
go mod tidy
go build -o terraform-provider-safecadence
```

Install into your local Terraform plugin cache for development.

## License

MIT
