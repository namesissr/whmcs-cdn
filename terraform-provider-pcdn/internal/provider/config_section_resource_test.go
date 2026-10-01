package provider

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func checkFakeSection(f *fakeController, section, field string, want any) resource.TestCheckFunc {
	return func(*terraform.State) error {
		got := f.sectionField(section, field)
		if fmt.Sprint(got) != fmt.Sprint(want) {
			return fmt.Errorf("controller %s.%s = %v, want %v", section, field, got, want)
		}
		return nil
	}
}

func TestAccConfigSection_cache(t *testing.T) {
	requireTerraform(t)
	f := newFakeController(t)
	puts := func() int { return f.count("PUT /capi/v1/config/cache") }
	var putsAfterCreate int

	hcl := providerConfig(f) + `
resource "pcdn_config_section" "cache" {
  section = "cache"
  config = jsonencode({
    enabled  = true
    edge_ttl = 600
  })
}
`
	// the same JSON with other key order, whitespace and number spelling
	reformatted := providerConfig(f) + `
resource "pcdn_config_section" "cache" {
  section = "cache"
  config  = <<-EOT
    {
      "edge_ttl" : 600.0,
      "enabled"  : true
    }
  EOT
}
`
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		CheckDestroy: func(*terraform.State) error {
			// destroy is a no-op: the section stays as last applied
			if got := f.sectionField("cache", "edge_ttl"); fmt.Sprint(got) != "86400" {
				return fmt.Errorf("edge_ttl after destroy = %v", got)
			}
			return nil
		},
		Steps: []resource.TestStep{
			{
				// partial config: the controller fills defaults; no perpetual diff (post-apply plan is empty)
				Config: hcl,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("pcdn_config_section.cache", "id", "cache"),
					resource.TestCheckResourceAttr("pcdn_config_section.cache", "config", `{"edge_ttl":600,"enabled":true}`),
					resource.TestCheckResourceAttrWith("pcdn_config_section.cache", "result", func(v string) error {
						var m map[string]any
						if err := json.Unmarshal([]byte(v), &m); err != nil {
							return err
						}
						if m["edge_ttl"] != 600.0 || m["level"] != "standard" || m["always_online"] != true {
							return fmt.Errorf("result lacks stored values/defaults: %s", v)
						}
						return nil
					}),
					resource.TestCheckNoResourceAttr("pcdn_config_section.cache", "secrets"),
					checkFakeSection(f, "cache", "edge_ttl", 600),
					func(*terraform.State) error { putsAfterCreate = puts(); return nil },
				),
			},
			{
				// semantic equality: reformatting the JSON plans nothing
				Config:   reformatted,
				PlanOnly: true,
			},
			{
				// drift on a configured key (panel edit) -> re-applied
				PreConfig: func() { f.setSectionField("cache", "edge_ttl", 999.0) },
				Config:    hcl,
				Check:     checkFakeSection(f, "cache", "edge_ttl", 600),
			},
			{
				// drift on a key that is NOT in config -> also corrected (PUT replaces the whole section)
				PreConfig: func() { f.setSectionField("cache", "dev_mode", true) },
				Config:    hcl,
				Check:     checkFakeSection(f, "cache", "dev_mode", false),
			},
			{
				// removing a key from config is a change: it returns to the controller default
				Config: providerConfig(f) + `
resource "pcdn_config_section" "cache" {
  section = "cache"
  config  = jsonencode({ enabled = true })
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					checkFakeSection(f, "cache", "edge_ttl", 86400),
					func(*terraform.State) error {
						if puts() != putsAfterCreate+3 {
							return fmt.Errorf("PUT count %d, want %d (create + 2 drift fixes + 1 change)", puts(), putsAfterCreate+3)
						}
						return nil
					},
				),
			},
			{
				ResourceName:            "pcdn_config_section.cache",
				ImportState:             true,
				ImportStateId:           "cache",
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"config"}, // import stores the full controller section
			},
		},
	})
}

func TestAccConfigSection_writeOnlySecret(t *testing.T) {
	requireTerraform(t)
	f := newFakeController(t)
	hcl := providerConfig(f) + `
resource "pcdn_config_section" "logs" {
  section = "logs"
  config = jsonencode({
    enabled     = true
    s3_endpoint = "https://s3.example.net"
    bucket      = "cdn-logs"
    access_key  = "AKIAEXAMPLE"
    secret_key  = "s3cr3t-value"
    sample_rate = 0.5
  })
}
`
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		Steps: []resource.TestStep{
			{
				// GET returns secret_key "" + secret_key_set: the configured secret is kept in config,
				// never shows up in result, and the post-apply plan is empty
				Config: hcl,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrWith("pcdn_config_section.logs", "result", func(v string) error {
						if strings.Contains(v, "s3cr3t-value") {
							return fmt.Errorf("secret leaked into result: %s", v)
						}
						if !strings.Contains(v, `"secret_key_set":true`) {
							return fmt.Errorf("result: %s", v)
						}
						return nil
					}),
					func(*terraform.State) error {
						if got := f.storedLogsSecret(); got != "s3cr3t-value" {
							return fmt.Errorf("controller secret = %q", got)
						}
						return nil
					},
				),
			},
			{
				// a refresh-only cycle sees no drift either
				RefreshState: true,
			},
			{
				Config:   hcl,
				PlanOnly: true,
			},
		},
	})
}

func TestAccConfigSection_webhookSecrets(t *testing.T) {
	requireTerraform(t)
	f := newFakeController(t)
	hooks := func(items string) string {
		return providerConfig(f) + `
resource "pcdn_config_section" "webhooks" {
  section = "webhooks"
  config  = jsonencode({ items = [` + items + `] })
}
output "hook_ids" {
  value = [for h in jsondecode(pcdn_config_section.webhooks.result).items : h.id]
}
`
	}
	var firstID, firstSecret string
	captureFirst := func(s *terraform.State) error {
		rs := s.RootModule().Resources["pcdn_config_section.webhooks"].Primary.Attributes
		ids := s.RootModule().Outputs["hook_ids"].Value.([]any)
		if len(ids) != 1 {
			return fmt.Errorf("hook ids: %v", ids)
		}
		firstID = ids[0].(string)
		firstSecret = rs["secrets."+firstID]
		if !strings.HasPrefix(firstSecret, "whsec_") {
			return fmt.Errorf("secret for %s not captured: %v", firstID, rs)
		}
		return nil
	}
	sameFirst := func(s *terraform.State) error {
		rs := s.RootModule().Resources["pcdn_config_section.webhooks"].Primary.Attributes
		if rs["secrets."+firstID] != firstSecret {
			return fmt.Errorf("secret of %s changed or vanished: %v", firstID, rs)
		}
		if f.hookSecretOf(firstID) != firstSecret {
			return fmt.Errorf("controller rotated %s (id not preserved)", firstID)
		}
		return nil
	}
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: hooks(`{ url = "https://hooks.example.net/a", events = ["purge.completed"] }`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("pcdn_config_section.webhooks", "secrets.%", "1"),
					captureFirst,
					resource.TestCheckResourceAttrWith("pcdn_config_section.webhooks", "result", func(v string) error {
						if strings.Contains(v, "whsec_") || strings.Contains(v, "new_secrets") {
							return fmt.Errorf("secret leaked into result: %s", v)
						}
						return nil
					}),
				),
			},
			{
				// editing the hook keeps its id (matched by url) and therefore its secret
				Config: hooks(`{ url = "https://hooks.example.net/a", events = ["purge.completed", "ssl.issued"] }`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("pcdn_config_section.webhooks", "secrets.%", "1"),
					sameFirst,
				),
			},
			{
				// a second hook adds a second secret
				Config: hooks(`{ url = "https://hooks.example.net/a", events = ["purge.completed", "ssl.issued"] },
				               { url = "https://hooks.example.net/b", events = ["quota.warning"] }`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("pcdn_config_section.webhooks", "secrets.%", "2"),
					sameFirst,
				),
			},
			{
				// removing the first hook drops its secret
				Config: hooks(`{ url = "https://hooks.example.net/b", events = ["quota.warning"] }`),
				Check: func(s *terraform.State) error {
					rs := s.RootModule().Resources["pcdn_config_section.webhooks"].Primary.Attributes
					if rs["secrets.%"] != "1" || rs["secrets."+firstID] != "" {
						return fmt.Errorf("secrets after removal: %v", rs)
					}
					return nil
				},
			},
		},
	})
}

// TestAccConcurrentWritesAreSerialised applies several sections and records at Terraform's default
// parallelism (10) and checks that the controller never saw two writes at once.
func TestAccConcurrentWritesAreSerialised(t *testing.T) {
	requireTerraform(t)
	f := newFakeController(t)
	hcl := providerConfig(f)
	for _, s := range []string{"cache", "waf", "ddos", "ssl", "headers", "hotlink"} {
		hcl += fmt.Sprintf("resource \"pcdn_config_section\" %q {\n  section = %q\n  config = \"{}\"\n}\n", s, s)
	}
	for i := 1; i <= 6; i++ {
		hcl += fmt.Sprintf("resource \"pcdn_record\" \"r%d\" {\n  name = \"h%d\"\n  type = \"A\"\n  content = \"185.1.2.%d\"\n}\n", i, i, i)
	}
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		Steps: []resource.TestStep{{
			Config: hcl,
			Check: func(*terraform.State) error {
				if m := f.maxWrites.Load(); m != 1 {
					return fmt.Errorf("controller saw %d writes in flight at once, want 1", m)
				}
				if f.count("PUT /capi/v1/config/cache")+f.recordCount() < 7 {
					return fmt.Errorf("writes missing")
				}
				return nil
			},
		}},
	})
}

func TestAccConfigSection_errors(t *testing.T) {
	requireTerraform(t)
	f := newFakeController(t)
	cases := []struct {
		name, hcl string
		want      *regexp.Regexp
	}{
		{"unknown section", `section = "nope"
  config = "{}"`, regexp.MustCompile(`value must be one of`)},
		{"config not an object", `section = "cache"
  config = jsonencode([1, 2])`, regexp.MustCompile(`config must be a JSON object`)},
		{"config not JSON", `section = "cache"
  config = "{enabled"`, regexp.MustCompile(`Invalid JSON`)},
		{"controller validation list", `section = "cache"
  config = jsonencode({ edge_ttl = 5, colour = "red" })`,
			regexp.MustCompile(`(?s)HTTP 422.*(colour: Extra inputs are not permitted.*edge_ttl: Input should be|edge_ttl: Input should be.*colour: Extra inputs)`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resource.UnitTest(t, resource.TestCase{
				ProtoV6ProviderFactories: testProviderFactories(),
				Steps: []resource.TestStep{{
					Config:      providerConfig(f) + "resource \"pcdn_config_section\" \"s\" {\n  " + tc.hcl + "\n}\n",
					ExpectError: tc.want,
				}},
			})
		})
	}
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		Steps: []resource.TestStep{{
			Config:        providerConfig(f) + "resource \"pcdn_config_section\" \"s\" {\n  section = \"cache\"\n  config = \"{}\"\n}\n",
			ResourceName:  "pcdn_config_section.s",
			ImportState:   true,
			ImportStateId: "colours",
			ExpectError:   regexp.MustCompile(`by its section name`),
		}},
	})
}

func TestJSONHelpers(t *testing.T) {
	eq := []struct {
		a, b string
		want bool
	}{
		{`{"a":1,"b":[1,2]}`, "{ \"b\" : [1, 2.0],\n \"a\": 1 }", true},
		{`{"a":1}`, `{"a":1,"b":null}`, false},
		{`{"a":[1,2]}`, `{"a":[2,1]}`, false},
		{`{"a":"x"}`, `{"a":"X"}`, false},
		{`not json`, `not json`, true},
		{`not json`, `{}`, false},
	}
	for _, c := range eq {
		if got := jsonEqual(c.a, c.b); got != c.want {
			t.Errorf("jsonEqual(%s, %s) = %v", c.a, c.b, got)
		}
	}
	if _, err := decodeJSON(`{} {}`); err == nil {
		t.Error("trailing data accepted")
	}

	v, _ := decodeJSON(`{"new_secrets":{"wh_1":"whsec_x"},"items":[{"id":"wh_1","secret":"s","url":"u"}],"secret_key":"k","secret_key_set":true}`)
	if got := canonicalJSON(redactSection(v)); got != `{"items":[{"id":"wh_1","secret":"","url":"u"}],"secret_key":"","secret_key_set":true}` {
		t.Errorf("redact: %s", got)
	}

	body, _ := decodeJSON(`{"items":[],"new_secrets":{"wh_1":"whsec_a","wh_2":""}}`)
	if s := newSecrets(body); len(s) != 1 || s["wh_1"] != "whsec_a" {
		t.Errorf("newSecrets: %v", s)
	}

	prior, _ := decodeJSON(`{"items":[{"id":"wh_a","url":"https://a"},{"id":"wh_b","url":"https://b"},{"id":"wh_c","url":"https://dup"},{"id":"wh_d","url":"https://dup"}]}`)
	cfg, _ := decodeJSONExact(`{"items":[{"url":"https://a","n":1.50},{"id":"wh_b","url":"https://b"},{"url":"https://dup"},{"url":"https://new"},{"id":"","url":"https://b"}]}`)
	if !injectWebhookIDs(cfg, prior) {
		t.Fatal("expected injection")
	}
	// a -> wh_a; b keeps explicit id; dup is ambiguous; new has no match; the 2nd https://b item
	// cannot claim wh_b (already used)
	if got := canonicalJSON(cfg); got != `{"items":[{"id":"wh_a","n":1.50,"url":"https://a"},{"id":"wh_b","url":"https://b"},{"url":"https://dup"},{"url":"https://new"},{"id":"","url":"https://b"}]}` {
		t.Errorf("inject: %s", got)
	}
	if injectWebhookIDs(cfg, nil) {
		t.Error("injection without a prior section")
	}

	// drift: only the changed keys enter config; unchanged ones keep the configured spelling
	current, _ := decodeJSON(`{"edge_ttl":999,"dev_mode":true,"level":"standard","secret_key":"","country":["CN"]}`)
	got := driftedConfig(`{"edge_ttl":600,"secret_key":"s3cr3t","country":["cn"]}`,
		`{"edge_ttl":600,"dev_mode":false,"level":"standard","secret_key":"","country":["CN"]}`, current)
	if got != `{"country":["cn"],"dev_mode":true,"edge_ttl":999,"secret_key":"s3cr3t"}` {
		t.Errorf("driftedConfig: %s", got)
	}
	if got := driftedConfig(`{"a":1}`, `not json`, current); !jsonEqual(got, canonicalJSON(current)) {
		t.Errorf("driftedConfig fallback: %s", got)
	}
}
