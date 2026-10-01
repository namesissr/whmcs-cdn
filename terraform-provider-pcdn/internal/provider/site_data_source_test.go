package provider

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccSiteDataSource(t *testing.T) {
	requireTerraform(t)
	f := newFakeController(t)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		Steps: []resource.TestStep{{
			Config: providerConfig(f) + `
data "pcdn_site" "this" {}

output "max_records" {
  value = jsondecode(data.pcdn_site.this.plan_json).max_records
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr("data.pcdn_site.this", "id", "example.com"),
				resource.TestCheckResourceAttr("data.pcdn_site.this", "domain", "example.com"),
				resource.TestCheckResourceAttr("data.pcdn_site.this", "status", "active"),
				resource.TestCheckResourceAttr("data.pcdn_site.this", "suspended", "false"),
				resource.TestCheckResourceAttr("data.pcdn_site.this", "nameservers.#", "2"),
				resource.TestCheckResourceAttr("data.pcdn_site.this", "nameservers.0", "ns1.pcdn.test"),
				resource.TestCheckNoResourceAttr("data.pcdn_site.this", "cname_target"),
				resource.TestCheckResourceAttr("data.pcdn_site.this", "ssl_status", "active"),
				resource.TestCheckOutput("max_records", "100"),
			),
		}},
	})
}

func TestAccSiteDataSource_badKey(t *testing.T) {
	requireTerraform(t)
	f := newFakeController(t)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		Steps: []resource.TestStep{{
			Config: `
provider "pcdn" {
  endpoint = "` + f.URL() + `"
  api_key  = "pcdn_ffffffffffffffffffffffffffffffffffffffff"
}
data "pcdn_site" "this" {}
`,
			ExpectError: regexp.MustCompile(`(?s)HTTP 401.*invalid api key`),
		}},
	})
}
