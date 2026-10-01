// Command terraform-provider-pcdn is the Terraform provider for the Pasargad CDN customer API.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/namesissr/whmcs-cdn/terraform-provider-pcdn/internal/provider"
)

// version is set at build time: go build -ldflags "-X main.version=0.1.0".
var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run the provider with support for debuggers like delve")
	flag.Parse()

	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address:         "registry.terraform.io/namesissr/pcdn",
		Debug:           debug,
		ProtocolVersion: 6,
	})
	if err != nil {
		log.Fatal(err.Error())
	}
}
