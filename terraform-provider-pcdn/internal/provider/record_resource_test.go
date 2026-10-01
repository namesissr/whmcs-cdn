package provider

import (
	"fmt"
	"regexp"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func recordID(s *terraform.State, name string) (int64, error) {
	rs, ok := s.RootModule().Resources[name]
	if !ok {
		return 0, fmt.Errorf("%s not in state", name)
	}
	return strconv.ParseInt(rs.Primary.ID, 10, 64)
}

// checkFakeRecord asserts a field of the record the controller stored for a resource.
func checkFakeRecord(f *fakeController, name, field string, want any) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		id, err := recordID(s, name)
		if err != nil {
			return err
		}
		rec := f.record(id)
		if rec == nil {
			return fmt.Errorf("record %d not on the controller", id)
		}
		if fmt.Sprint(rec[field]) != fmt.Sprint(want) {
			return fmt.Errorf("controller record %d %s = %v, want %v", id, field, rec[field], want)
		}
		return nil
	}
}

func TestAccRecord_lifecycle(t *testing.T) {
	requireTerraform(t)
	f := newFakeController(t)
	var firstID int64
	captureID := func(s *terraform.State) error {
		id, err := recordID(s, "pcdn_record.www")
		firstID = id
		return err
	}
	sameID := func(s *terraform.State) error {
		id, err := recordID(s, "pcdn_record.www")
		if err == nil && id != firstID {
			return fmt.Errorf("record was replaced (id %d -> %d); expected an in-place PATCH", firstID, id)
		}
		return err
	}
	cfg := func(body string) string {
		return providerConfig(f) + "resource \"pcdn_record\" \"www\" {\n" + body + "\n}\n"
	}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		CheckDestroy: func(*terraform.State) error {
			if n := f.recordCount(); n != 0 {
				return fmt.Errorf("%d records left on the controller", n)
			}
			return nil
		},
		Steps: []resource.TestStep{
			{
				// the controller lower-cases the name: the configured spelling stays in state and
				// the automatic post-apply plan proves there is no perpetual diff
				Config: cfg(`
  name    = "WWW"
  type    = "A"
  content = "185.1.2.3"
  proxied = true`),
				Check: resource.ComposeAggregateTestCheckFunc(
					captureID,
					resource.TestCheckResourceAttr("pcdn_record.www", "name", "WWW"),
					resource.TestCheckResourceAttr("pcdn_record.www", "ttl", "300"),
					resource.TestCheckResourceAttr("pcdn_record.www", "proxied", "true"),
					resource.TestCheckNoResourceAttr("pcdn_record.www", "priority"),
					resource.TestCheckResourceAttr("pcdn_record.www", "health_check", "false"),
					checkFakeRecord(f, "pcdn_record.www", "name", "www"),
					checkFakeRecord(f, "pcdn_record.www", "proxied", true),
				),
			},
			{
				Config: cfg(`
  name        = "WWW"
  type        = "A"
  content     = "185.1.2.4"
  ttl         = 600
  proxied     = true
  origin_port = 8080`),
				Check: resource.ComposeAggregateTestCheckFunc(
					sameID,
					resource.TestCheckResourceAttr("pcdn_record.www", "content", "185.1.2.4"),
					resource.TestCheckResourceAttr("pcdn_record.www", "origin_port", "8080"),
					checkFakeRecord(f, "pcdn_record.www", "ttl", 600),
					checkFakeRecord(f, "pcdn_record.www", "origin_port", 8080),
				),
			},
			{
				// the API can change the type in place (PATCH sends the full record)
				Config: cfg(`
  name    = "WWW"
  type    = "AAAA"
  content = "2001:DB8:0:0::1"`),
				Check: resource.ComposeAggregateTestCheckFunc(
					sameID,
					resource.TestCheckResourceAttr("pcdn_record.www", "content", "2001:DB8:0:0::1"),
					resource.TestCheckNoResourceAttr("pcdn_record.www", "origin_port"),
					checkFakeRecord(f, "pcdn_record.www", "content", "2001:db8::1"),
					checkFakeRecord(f, "pcdn_record.www", "type", "AAAA"),
				),
			},
			{
				ResourceName:      "pcdn_record.www",
				ImportState:       true,
				ImportStateVerify: true,
				// import reads the controller's canonical spelling
				ImportStateVerifyIgnore: []string{"name", "content"},
			},
			{
				// a spelling the controller normalises the same way plans nothing
				Config: cfg(`
  name    = "www."
  type    = "AAAA"
  content = "2001:db8::1"`),
				PlanOnly: true,
			},
			{
				// drift: the record is edited in the panel -> the plan corrects it
				PreConfig: func() { f.setRecordField(firstID, "content", "2001:db8::99") },
				Config: cfg(`
  name    = "WWW"
  type    = "AAAA"
  content = "2001:DB8:0:0::1"`),
				Check: resource.ComposeAggregateTestCheckFunc(
					sameID,
					checkFakeRecord(f, "pcdn_record.www", "content", "2001:db8::1"),
				),
			},
			{
				// deleted outside Terraform -> removed from state on refresh and recreated
				PreConfig: func() { f.deleteRecord(firstID) },
				Config: cfg(`
  name    = "WWW"
  type    = "AAAA"
  content = "2001:DB8:0:0::1"`),
				Check: func(s *terraform.State) error {
					id, err := recordID(s, "pcdn_record.www")
					if err == nil && id == firstID {
						return fmt.Errorf("record was not recreated")
					}
					return err
				},
			},
		},
	})
}

func TestAccRecord_normalisationAndPriority(t *testing.T) {
	requireTerraform(t)
	f := newFakeController(t)
	var mxID int64
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		Steps: []resource.TestStep{
			{
				// full name under the site domain + trailing dots + upper case: all stored relative and
				// lower-cased by the controller, MX priority defaults to 10, no diff afterwards
				Config: providerConfig(f) + `
resource "pcdn_record" "mx" {
  name    = "Mail.example.com."
  type    = "MX"
  content = "MX1.Example.NET."
}
resource "pcdn_record" "apex_txt" {
  type    = "TXT"
  content = "\"v=spf1 -all\""
}
resource "pcdn_record" "srv" {
  name     = "_sip._tcp"
  type     = "SRV"
  content  = "05 5060 SIP.example.net."
  priority = 20
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("pcdn_record.mx", "priority", "10"),
					resource.TestCheckResourceAttr("pcdn_record.mx", "name", "Mail.example.com."),
					checkFakeRecord(f, "pcdn_record.mx", "name", "mail"),
					checkFakeRecord(f, "pcdn_record.mx", "content", "mx1.example.net"),
					resource.TestCheckResourceAttr("pcdn_record.apex_txt", "name", "@"),
					checkFakeRecord(f, "pcdn_record.apex_txt", "content", "v=spf1 -all"),
					resource.TestCheckResourceAttr("pcdn_record.srv", "priority", "20"),
					checkFakeRecord(f, "pcdn_record.srv", "content", "5 5060 sip.example.net"),
				),
			},
			{
				// MX -> TXT in place: the planned priority becomes null (no stale 10)
				Config: providerConfig(f) + `
resource "pcdn_record" "mx" {
  name    = "Mail.example.com."
  type    = "TXT"
  content = "hello"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckNoResourceAttr("pcdn_record.mx", "priority"),
					checkFakeRecord(f, "pcdn_record.mx", "priority", nil),
				),
			},
			{
				// TXT -> MX in place: priority planned as 10 again
				Config: providerConfig(f) + `
resource "pcdn_record" "mx" {
  name    = "mail"
  type    = "MX"
  content = "mx1.example.net"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("pcdn_record.mx", "priority", "10"),
					func(s *terraform.State) error {
						id, err := recordID(s, "pcdn_record.mx")
						mxID = id
						return err
					},
				),
			},
			{
				// drift: the default priority is edited to 30 in the panel -> corrected back to 10
				PreConfig: func() { f.setRecordField(mxID, "priority", int64(30)) },
				Config: providerConfig(f) + `
resource "pcdn_record" "mx" {
  name    = "mail"
  type    = "MX"
  content = "mx1.example.net"
}
`,
				Check: checkFakeRecord(f, "pcdn_record.mx", "priority", 10),
			},
		},
	})
}

func TestAccRecord_importThenNoDiff(t *testing.T) {
	requireTerraform(t)
	f := newFakeController(t)
	id := f.addRecord(map[string]any{"name": "www", "type": "CNAME", "content": "example.com", "proxied": true})
	cfg := providerConfig(f) + `
resource "pcdn_record" "www" {
  name    = "WWW"
  type    = "CNAME"
  content = "Example.COM."
  proxied = true
}
`
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config:             cfg,
				ResourceName:       "pcdn_record.www",
				ImportState:        true,
				ImportStateId:      strconv.FormatInt(id, 10),
				ImportStatePersist: true,
			},
			{
				// the imported canonical spelling satisfies the configured one: no PATCH planned
				Config:   cfg,
				PlanOnly: true,
			},
		},
	})
	if n := f.count(fmt.Sprintf("PATCH /capi/v1/records/%d", id)); n != 0 {
		t.Errorf("%d PATCH calls after import", n)
	}
}

// SPEC §16.7: weighted / failover records and the controller probe. Every PATCH must carry weight,
// health_protocol and health_path (PATCH replaces the whole record), the defaulted health_path must not
// cause a perpetual diff, and the computed `health` object is read back without ever planning a change.
func TestAccRecord_weightedHealth(t *testing.T) {
	requireTerraform(t)
	f := newFakeController(t)
	var aID int64
	captureA := func(s *terraform.State) (err error) {
		aID, err = recordID(s, "pcdn_record.a")
		return err
	}
	cfg := func(body string) string {
		return providerConfig(f) + `resource "pcdn_record" "a" {
  name    = "app"
  type    = "A"
  content = "185.1.2.3"
` + body + "\n}\n" + `resource "pcdn_record" "b" {
  name         = "app"
  type         = "A"
  content      = "185.1.2.4"
  weight       = 0
  health_check = true
}
resource "pcdn_record" "c" {
  name         = "alt"
  type         = "CNAME"
  content      = "origin1.example.net"
  weight       = 50
  health_check = true
}
`
	}
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		Steps: []resource.TestStep{
			{
				// health_path is not configured: the controller stores "/" for an https probe and the
				// plan predicts it (the post-apply empty-plan check proves there is no diff)
				Config: cfg(`  weight          = 70
  health_check    = true
  health_protocol = "https"
  health_port     = 443`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("pcdn_record.a", "weight", "70"),
					resource.TestCheckResourceAttr("pcdn_record.a", "health_protocol", "https"),
					resource.TestCheckResourceAttr("pcdn_record.a", "health_path", "/"),
					resource.TestCheckResourceAttr("pcdn_record.a", "health.ok", "true"),
					resource.TestCheckResourceAttr("pcdn_record.a", "health.ms", "12"),
					resource.TestCheckResourceAttr("pcdn_record.a", "health.advertised", "true"),
					resource.TestCheckResourceAttr("pcdn_record.b", "weight", "0"),
					resource.TestCheckNoResourceAttr("pcdn_record.b", "health_protocol"),
					resource.TestCheckNoResourceAttr("pcdn_record.b", "health_path"),
					resource.TestCheckResourceAttr("pcdn_record.c", "health_check", "true"),
					checkFakeRecord(f, "pcdn_record.a", "weight", 70),
					checkFakeRecord(f, "pcdn_record.a", "health_path", "/"),
					checkFakeRecord(f, "pcdn_record.c", "weight", 50),
				),
			},
			{
				// an unrelated change (ttl) must send weight/protocol/path back, not null them
				Config: cfg(`  weight          = 70
  ttl             = 600
  health_check    = true
  health_protocol = "https"
  health_port     = 443`),
				Check: resource.ComposeAggregateTestCheckFunc(
					captureA,
					checkFakeRecord(f, "pcdn_record.a", "ttl", 600),
					checkFakeRecord(f, "pcdn_record.a", "weight", 70),
					checkFakeRecord(f, "pcdn_record.a", "health_protocol", "https"),
					checkFakeRecord(f, "pcdn_record.a", "health_path", "/"),
					checkFakeRecord(f, "pcdn_record.a", "health_port", 443),
				),
			},
			{
				// the probe result changes on the controller: refresh updates `health`, plans nothing
				PreConfig: func() {
					f.setRecordField(aID, "health", map[string]any{"ok": false, "ms": nil, "fail": int64(3),
						"at": "2026-10-01T10:05:00Z", "error": "timeout", "advertised": false})
				},
				RefreshState: true,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("pcdn_record.a", "health.ok", "false"),
					resource.TestCheckResourceAttr("pcdn_record.a", "health.fail", "3"),
					resource.TestCheckResourceAttr("pcdn_record.a", "health.error", "timeout"),
					resource.TestCheckResourceAttr("pcdn_record.a", "health.advertised", "false"),
				),
			},
			{
				Config: cfg(`  weight          = 70
  ttl             = 600
  health_check    = true
  health_protocol = "https"
  health_port     = 443`),
				PlanOnly: true,
			},
			{
				// explicit path, then switching to tcp clears the path; dropping weight unweights it
				Config: cfg(`  weight          = 30
  health_check    = true
  health_protocol = "http"
  health_path     = "/healthz"`),
				Check: resource.ComposeAggregateTestCheckFunc(
					checkFakeRecord(f, "pcdn_record.a", "weight", 30),
					checkFakeRecord(f, "pcdn_record.a", "health_path", "/healthz"),
					resource.TestCheckResourceAttr("pcdn_record.a", "health_path", "/healthz"),
				),
			},
			{
				Config: cfg(`  health_check    = true
  health_protocol = "tcp"`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckNoResourceAttr("pcdn_record.a", "weight"),
					resource.TestCheckNoResourceAttr("pcdn_record.a", "health_path"),
					checkFakeRecord(f, "pcdn_record.a", "weight", nil),
					checkFakeRecord(f, "pcdn_record.a", "health_path", nil),
					checkFakeRecord(f, "pcdn_record.a", "health_protocol", "tcp"),
				),
			},
			{
				// health_check off: the computed health object becomes null
				Config: cfg(""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckNoResourceAttr("pcdn_record.a", "health.ok"),
					resource.TestCheckNoResourceAttr("pcdn_record.a", "health_protocol"),
					checkFakeRecord(f, "pcdn_record.a", "health_check", false),
				),
			},
			{
				ResourceName:      "pcdn_record.c",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccRecord_validation(t *testing.T) {
	requireTerraform(t)
	f := newFakeController(t)
	cases := []struct {
		name, body string
		want       string
	}{
		{"proxied TXT", `type = "TXT"
  content = "x"
  proxied = true`, `proxied is not supported for this record type`},
		{"pool without proxied", `type = "A"
  content = "185.1.2.3"
  pool = "main"`, `pool requires proxied = true`},
		{"origin_port with pool", `type = "A"
  content = "185.1.2.3"
  proxied = true
  pool = "main"
  origin_port = 8080`, `origin_port conflicts with pool`},
		{"priority on A", `type = "A"
  content = "185.1.2.3"
  priority = 5`, `priority is only used by MX and SRV records`},
		{"health_check on proxied", `type = "A"
  content = "185.1.2.3"
  proxied = true
  health_check = true`, `health_check is for DNS-only records`},
		{"health_port without health_check", `type = "A"
  content = "185.1.2.3"
  health_port = 8080`, `health_port requires health_check = true`},
		{"weight on proxied", `type = "A"
  content = "185.1.2.3"
  proxied = true
  weight = 10`, `weight is for DNS-only records`},
		{"weight on TXT", `type = "TXT"
  content = "x"
  weight = 10`, `weight is not supported for this record type`},
		{"weight out of range", `type = "A"
  content = "185.1.2.3"
  weight = 101`, `weight`},
		{"health_check on lone CNAME", `name = "app"
  type = "CNAME"
  content = "origin.example.net"
  health_check = true`, `health_check on a CNAME needs weight`},
		{"health_check on TXT", `type = "TXT"
  content = "x"
  health_check = true`, `health_check needs an A, AAAA or CNAME record`},
		{"health_protocol without health_check", `type = "A"
  content = "185.1.2.3"
  health_protocol = "http"`, `health_protocol requires health_check = true`},
		{"health_protocol invalid", `type = "A"
  content = "185.1.2.3"
  health_check = true
  health_protocol = "icmp"`, `value must be one of`},
		{"health_path with tcp", `type = "A"
  content = "185.1.2.3"
  health_check = true
  health_protocol = "tcp"
  health_path = "/up"`, `health_path requires health_protocol http or https`},
		{"health_path bad pattern", `type = "A"
  content = "185.1.2.3"
  health_check = true
  health_protocol = "http"
  health_path = "up now"`, `must start with /`},
		{"lower-case type", `type = "a"
  content = "185.1.2.3"`, `value must be one of`},
		{"ttl too low", `type = "A"
  content = "185.1.2.3"
  ttl = 30`, `ttl`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resource.UnitTest(t, resource.TestCase{
				ProtoV6ProviderFactories: testProviderFactories(),
				Steps: []resource.TestStep{{
					Config:      providerConfig(f) + "resource \"pcdn_record\" \"r\" {\n  " + tc.body + "\n}\n",
					ExpectError: regexp.MustCompile(regexp.QuoteMeta(tc.want)),
				}},
			})
		})
	}
	if n := f.count("POST /capi/v1/records"); n != 0 {
		t.Errorf("invalid configs reached the API (%d POSTs)", n)
	}
}

func TestAccRecord_controllerErrors(t *testing.T) {
	requireTerraform(t)
	f := newFakeController(t)
	// Persian `detail` string from the controller is surfaced verbatim
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		Steps: []resource.TestStep{{
			Config: providerConfig(f) + `
resource "pcdn_record" "r" {
  type    = "A"
  content = "10.0.0.1"
}
`,
			ExpectError: regexp.MustCompile(`(?s)HTTP 422.*آدرس IP باید عمومی باشد`),
		}},
	})
	// a key without the dns scope -> 403 with the controller message and a hint
	f.setScopes("purge")
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		Steps: []resource.TestStep{{
			Config: providerConfig(f) + `
resource "pcdn_record" "r" {
  type    = "A"
  content = "185.1.2.3"
}
`,
			ExpectError: regexp.MustCompile(`(?s)HTTP 403.*«dns».*lacks the scope`),
		}},
	})
}

func TestAccRecord_rateLimitAndDNSWarning(t *testing.T) {
	requireTerraform(t)
	f := newFakeController(t)
	// two 429s on the (non-idempotent) POST are retried; a 503 on the list is retried too
	f.injectStatus("POST /capi/v1/records", 429, 429)
	f.dnsError = "pdns unreachable"
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: providerConfig(f) + `
resource "pcdn_record" "r" {
  name    = "api"
  type    = "A"
  content = "185.1.2.3"
}
`,
				Check: func(*terraform.State) error {
					if n := f.count("POST /capi/v1/records"); n != 3 {
						return fmt.Errorf("POST /records called %d times, want 3 (2x429 + success)", n)
					}
					if n := f.recordCount(); n != 1 {
						return fmt.Errorf("%d records created, want exactly 1", n)
					}
					f.injectStatus("GET /capi/v1/records", 503)
					return nil
				},
			},
			{
				RefreshState: true,
				Check: func(*terraform.State) error {
					// the refresh succeeded, so the injected 503 was retried
					if n := f.pending("GET /capi/v1/records"); n != 0 {
						return fmt.Errorf("injected 503 not consumed (%d left)", n)
					}
					return nil
				},
			},
		},
	})
}

func TestAccRecord_postNotRetriedOn5xx(t *testing.T) {
	requireTerraform(t)
	f := newFakeController(t)
	f.injectStatus("POST /capi/v1/records", 502)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		Steps: []resource.TestStep{{
			Config: providerConfig(f) + `
resource "pcdn_record" "r" {
  type    = "A"
  content = "185.1.2.3"
}
`,
			ExpectError: regexp.MustCompile(`HTTP 502`),
		}},
	})
	if n := f.count("POST /capi/v1/records"); n != 1 {
		t.Errorf("POST retried after 502: %d calls", n)
	}
}

func TestAccRecord_importInvalidID(t *testing.T) {
	requireTerraform(t)
	f := newFakeController(t)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		Steps: []resource.TestStep{{
			Config: providerConfig(f) + `
resource "pcdn_record" "r" {
  type    = "A"
  content = "185.1.2.3"
}
`,
			ResourceName:  "pcdn_record.r",
			ImportState:   true,
			ImportStateId: "www",
			ExpectError:   regexp.MustCompile(`numeric controller id`),
		}},
	})
}

func TestNameAndContentEquivalence(t *testing.T) {
	names := []struct {
		cfg, server string
		want        bool
	}{
		{"WWW", "www", true}, {"www.", "www", true}, {"", "@", true}, {" @ ", "@", true},
		{"blog", "www", false}, {"www.example.com", "www", false}, // domain suffix: private state handles it
	}
	for _, c := range names {
		if got := nameEquivalent(c.cfg, c.server); got != c.want {
			t.Errorf("nameEquivalent(%q, %q) = %v, want %v", c.cfg, c.server, got, c.want)
		}
	}
	contents := []struct {
		rtype, cfg, server string
		want               bool
	}{
		{"A", "185.1.2.3", "185.1.2.3", true},
		{"AAAA", "2001:DB8:0::1", "2001:db8::1", true},
		{"AAAA", "2001:db8::2", "2001:db8::1", false},
		{"CNAME", "Origin.Example.NET.", "origin.example.net", true},
		{"MX", "mx.example.net", "mx2.example.net", false},
		{"SRV", "05 0080 Target.example.", "5 80 target.example", true},
		{"TXT", `"hello"`, "hello", true},
		{"TXT", "Hello", "hello", false}, // TXT is case-sensitive
		{"CAA", `0 issue "letsencrypt.org"`, `0 issue "letsencrypt.org"`, true},
	}
	for _, c := range contents {
		if got := contentEquivalent(c.rtype, c.cfg, c.server); got != c.want {
			t.Errorf("contentEquivalent(%s, %q, %q) = %v, want %v", c.rtype, c.cfg, c.server, got, c.want)
		}
	}
}
