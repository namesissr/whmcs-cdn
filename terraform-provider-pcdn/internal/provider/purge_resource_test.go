package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func expectPurges(f *fakeController, n int) resource.TestCheckFunc {
	return func(*terraform.State) error {
		if got := f.purgeCount(); got != n {
			return fmt.Errorf("controller received %d purges, want %d", got, n)
		}
		return nil
	}
}

func TestAccPurge_lifecycle(t *testing.T) {
	requireTerraform(t)
	f := newFakeController(t)
	purge := func(body string) string {
		return providerConfig(f) + "resource \"pcdn_purge\" \"p\" {\n" + body + "\n}\n"
	}
	urls := `
  urls     = ["https://example.com/app.css", "https://example.com/app.js"]
  triggers = { release = "v1" }`
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		CheckDestroy:             func(*terraform.State) error { return expectPurges(f, 4)(nil) }, // destroy calls nothing
		Steps: []resource.TestStep{
			{
				Config: purge(urls),
				Check: resource.ComposeAggregateTestCheckFunc(
					expectPurges(f, 1),
					resource.TestCheckResourceAttr("pcdn_purge.p", "queued", "2"),
					resource.TestCheckResourceAttr("pcdn_purge.p", "everything", "false"),
					resource.TestCheckResourceAttrSet("pcdn_purge.p", "id"),
					resource.TestCheckResourceAttrSet("pcdn_purge.p", "purged_at"),
				),
			},
			{
				// unchanged config: refresh is a no-op, nothing is purged again
				Config: purge(urls),
				Check:  expectPurges(f, 1),
			},
			{
				// a new trigger value replaces the resource -> a new purge
				Config: purge(`
  urls     = ["https://example.com/app.css", "https://example.com/app.js"]
  triggers = { release = "v2" }`),
				Check: expectPurges(f, 2),
			},
			{
				Config: purge(`
  prefixes = ["/blog/", "https://example.com/img/"]
  urls     = ["https://example.com/"]`),
				Check: resource.ComposeAggregateTestCheckFunc(
					expectPurges(f, 3),
					resource.TestCheckResourceAttr("pcdn_purge.p", "queued", "3"),
					func(*terraform.State) error {
						last := f.lastPurge()
						if fmt.Sprint(last["prefixes"]) != "[/blog/ https://example.com/img/]" || last["everything"] != false {
							return fmt.Errorf("last purge: %v", last)
						}
						return nil
					},
				),
			},
			{
				Config: purge(`  everything = true`),
				Check: resource.ComposeAggregateTestCheckFunc(
					expectPurges(f, 4),
					resource.TestCheckResourceAttr("pcdn_purge.p", "queued", "all"),
					func(*terraform.State) error {
						if f.lastPurge()["everything"] != true {
							return fmt.Errorf("last purge: %v", f.lastPurge())
						}
						return nil
					},
				),
			},
		},
	})
}

func TestAccPurge_validation(t *testing.T) {
	requireTerraform(t)
	f := newFakeController(t)
	many := `["/0"`
	for i := 1; i < 21; i++ {
		many += fmt.Sprintf(`, "/%d"`, i)
	}
	many += "]"
	cases := []struct {
		name, body string
		want       string
	}{
		{"empty", ``, `Nothing to purge`},
		{"empty lists", `urls = []
  prefixes = []`, `Nothing to purge`},
		{"everything with urls", `everything = true
  urls = ["https://example.com/a"]`, `everything conflicts with urls and prefixes`},
		{"relative url", `urls = ["/a.css"]`, `must be a full URL`},
		{"bad prefix", `prefixes = ["blog/"]`, `must start with /`},
		{"too many prefixes", `prefixes = ` + many, `prefixes`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resource.UnitTest(t, resource.TestCase{
				ProtoV6ProviderFactories: testProviderFactories(),
				Steps: []resource.TestStep{{
					Config:      providerConfig(f) + "resource \"pcdn_purge\" \"p\" {\n  " + tc.body + "\n}\n",
					ExpectError: regexp.MustCompile(regexp.QuoteMeta(tc.want)),
				}},
			})
		})
	}
	if n := f.purgeCount(); n != 0 {
		t.Errorf("invalid purges reached the controller: %d", n)
	}
}

func TestAccPurge_scopeAndRateLimit(t *testing.T) {
	requireTerraform(t)
	f := newFakeController(t)
	// 429 is retried even for the non-idempotent POST /purge (the controller rejects before acting)
	f.injectStatus("POST /capi/v1/purge", 429)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		Steps: []resource.TestStep{{
			Config: providerConfig(f) + `
resource "pcdn_purge" "p" {
  everything = true
}
`,
			Check: expectPurges(f, 1),
		}},
	})
	f.setScopes("dns")
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		Steps: []resource.TestStep{{
			Config: providerConfig(f) + `
resource "pcdn_purge" "p" {
  everything = true
}
`,
			ExpectError: regexp.MustCompile(`(?s)HTTP 403.*«purge»`),
		}},
	})
}
