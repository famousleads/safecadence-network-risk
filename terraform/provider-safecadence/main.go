// Terraform provider for SafeCadence NetRisk.
//
// Entrypoint registered with the Terraform plugin SDK v2.
// Build with:   go build -o terraform-provider-safecadence
package main

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: Provider,
	})
}
