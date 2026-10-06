package provider

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// The resource tests below run real `terraform plan/apply/import/destroy` cycles (terraform-plugin-testing,
// resource.UnitTest) with the provider served in-process against the httptest fake controller —
// no network access. They need a Terraform CLI: TF_ACC_TERRAFORM_PATH, or `terraform` on PATH.
// Without one they are skipped, unless PCDN_REQUIRE_TERRAFORM=1 (set in CI) makes that a failure.
func requireTerraform(t *testing.T) {
	t.Helper()
	if p := os.Getenv("TF_ACC_TERRAFORM_PATH"); p != "" {
		return
	}
	if _, err := exec.LookPath("terraform"); err == nil {
		return
	}
	if os.Getenv("PCDN_REQUIRE_TERRAFORM") == "1" {
		t.Fatal("PCDN_REQUIRE_TERRAFORM=1 but no Terraform CLI found (set TF_ACC_TERRAFORM_PATH or put terraform on PATH)")
	}
	t.Skip("Terraform CLI not found; set TF_ACC_TERRAFORM_PATH or put terraform on PATH to run the plan/apply tests")
}

func testProviderFactories() map[string]func() (tfprotov6.ProviderServer, error) {
	return map[string]func() (tfprotov6.ProviderServer, error){
		"pcdn": providerserver.NewProtocol6WithError(&pcdnProvider{version: "test", testBackoff: 5 * time.Millisecond}),
	}
}

func providerConfig(f *fakeController) string {
	return fmt.Sprintf(`
provider "pcdn" {
  endpoint = %q
  api_key  = %q
}
`, f.URL(), f.key)
}

func TestProviderSchemaIsValid(t *testing.T) {
	ctx := context.Background()
	p := New("test")()
	var resp provider.SchemaResponse
	p.Schema(ctx, provider.SchemaRequest{}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("schema diagnostics: %v", resp.Diagnostics)
	}
	if d := resp.Schema.ValidateImplementation(ctx); d.HasError() {
		t.Fatalf("schema implementation: %v", d)
	}
	// every resource / data source schema must validate too
	server, err := providerserver.NewProtocol6WithError(p)()
	if err != nil {
		t.Fatal(err)
	}
	sr, err := server.GetProviderSchema(ctx, &tfprotov6.GetProviderSchemaRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range sr.Diagnostics {
		t.Errorf("provider schema diagnostic: %s: %s", d.Summary, d.Detail)
	}
	for _, name := range []string{"pcdn_record", "pcdn_config_section", "pcdn_purge"} {
		if _, ok := sr.ResourceSchemas[name]; !ok {
			t.Errorf("resource %s not registered", name)
		}
	}
	if _, ok := sr.DataSourceSchemas["pcdn_site"]; !ok {
		t.Error("data source pcdn_site not registered")
	}
	if !sr.Provider.Block.Attributes[findAttr(sr.Provider.Block.Attributes, "api_key")].Sensitive {
		t.Error("api_key must be sensitive")
	}
	secrets := sr.ResourceSchemas["pcdn_config_section"].Block.Attributes
	if !secrets[findAttr(secrets, "secrets")].Sensitive {
		t.Error("pcdn_config_section.secrets must be sensitive")
	}
}

func findAttr(attrs []*tfprotov6.SchemaAttribute, name string) int {
	for i, a := range attrs {
		if a.Name == name {
			return i
		}
	}
	return -1
}

func TestAccProvider_configFromEnvironment(t *testing.T) {
	requireTerraform(t)
	f := newFakeController(t)
	t.Setenv(envEndpoint, f.URL()+"/capi/v1/")
	t.Setenv(envAPIKey, f.key)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		Steps: []resource.TestStep{{
			Config: `
provider "pcdn" {}
data "pcdn_site" "this" {}
`,
			Check: resource.TestCheckResourceAttr("data.pcdn_site.this", "domain", "example.com"),
		}},
	})
	if !f.userAgents["terraform-provider-pcdn/test"] {
		t.Errorf("User-Agent not sent; saw %v", f.userAgents)
	}
}

func TestAccProvider_invalidConfiguration(t *testing.T) {
	requireTerraform(t)
	f := newFakeController(t)
	adminKey := "this-is-the-admin-key-123"
	cases := []struct {
		name, config string
		want         *regexp.Regexp
	}{
		{"plain http to a public host", `provider "pcdn" {
  endpoint = "http://cdn-api.example.com"
  api_key  = "` + f.key + `"
}`, regexp.MustCompile(`endpoint must use https`)},
		{"admin key instead of a customer key", `provider "pcdn" {
  endpoint = "` + f.URL() + `"
  api_key  = "` + adminKey + `"
}`, regexp.MustCompile(`customer API key starting with "pcdn_"`)},
		{"missing key", `provider "pcdn" {
  endpoint = "` + f.URL() + `"
}`, regexp.MustCompile(`Missing pcdn API key`)},
		{"timeout out of range", `provider "pcdn" {
  endpoint        = "` + f.URL() + `"
  api_key         = "` + f.key + `"
  timeout_seconds = 0
}`, regexp.MustCompile(`timeout_seconds`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(envAPIKey, "")
			t.Setenv(envEndpoint, "")
			resource.UnitTest(t, resource.TestCase{
				ProtoV6ProviderFactories: testProviderFactories(),
				Steps: []resource.TestStep{{
					Config:      tc.config + "\ndata \"pcdn_site\" \"this\" {}\n",
					ExpectError: tc.want,
				}},
			})
		})
	}
}

// TestConfigureErrors drives ConfigureProvider over the plugin protocol (no Terraform CLI needed).
func TestConfigureErrors(t *testing.T) {
	t.Setenv(envAPIKey, "")
	t.Setenv(envEndpoint, "")
	adminKey := "this-is-the-admin-key-123"
	errs := configureErr(t, "https://cdn-api.example.com", adminKey)
	if strings.Contains(strings.Join(errs, "\n"), adminKey) {
		t.Errorf("configure error leaks the api key: %v", errs)
	}
	if !strings.Contains(strings.Join(errs, "\n"), `starting with "pcdn_"`) {
		t.Errorf("unexpected errors: %v", errs)
	}
	errs = configureErr(t, "http://cdn-api.example.com", testKey)
	if !strings.Contains(strings.Join(errs, "\n"), "must use https") {
		t.Errorf("unexpected errors: %v", errs)
	}
	errs = configureErr(t, "", testKey)
	if !strings.Contains(strings.Join(errs, "\n"), "Missing pcdn endpoint") {
		t.Errorf("unexpected errors: %v", errs)
	}
}

func configureErr(t *testing.T, endpoint, key string) []string {
	t.Helper()
	ctx := context.Background()
	server, err := providerserver.NewProtocol6WithError(New("test")())()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := tfprotov6.NewDynamicValue(providerType(), providerValue(endpoint, key))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := server.ConfigureProvider(ctx, &tfprotov6.ConfigureProviderRequest{Config: &cfg})
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, d := range resp.Diagnostics {
		out = append(out, d.Summary+": "+d.Detail)
	}
	if len(out) == 0 {
		t.Fatal("expected a configure error")
	}
	return out
}

func providerType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"endpoint": tftypes.String, "api_key": tftypes.String, "timeout_seconds": tftypes.Number, "max_retries": tftypes.Number,
	}}
}

func providerValue(endpoint, key string) tftypes.Value {
	return tftypes.NewValue(providerType(), map[string]tftypes.Value{
		"endpoint":        tftypes.NewValue(tftypes.String, endpoint),
		"api_key":         tftypes.NewValue(tftypes.String, key),
		"timeout_seconds": tftypes.NewValue(tftypes.Number, nil),
		"max_retries":     tftypes.NewValue(tftypes.Number, nil),
	})
}
