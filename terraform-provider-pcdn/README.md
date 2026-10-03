# terraform-provider-pcdn

Terraform provider for the Pasargad CDN **customer API** (`/capi/v1`, SPEC §10.1 / §14.3.5 / §14.3.6).
It manages one site with a per-service customer API key (`pcdn_` + 40 hex): DNS records, configuration
sections and cache purges. Persian user guide: [`docs/TERRAFORM.md`](../docs/TERRAFORM.md).

| Kind | Name | API | Key scope |
|------|------|-----|-----------|
| resource | `pcdn_record` | `GET/POST /records`, `PATCH/DELETE /records/{id}` | `dns` |
| resource | `pcdn_config_section` | `GET/PUT /config/{section}` | `dns` |
| resource | `pcdn_purge` | `POST /purge` | `purge` |
| data source | `pcdn_site` | `GET /site` | any |

Built with [terraform-plugin-framework](https://github.com/hashicorp/terraform-plugin-framework)
(protocol 6, Terraform ≥ 1.0). Registry address: `registry.terraform.io/namesissr/pcdn` — the provider
is **not** published on the public registry; install a local build (below).

## Build and install

```sh
cd terraform-provider-pcdn
go build -ldflags "-X main.version=0.1.0" -o terraform-provider-pcdn .
```

**Filesystem mirror** (for real use; `terraform init` works offline):

```sh
d=~/.terraform.d/plugins/registry.terraform.io/namesissr/pcdn/0.1.0/linux_amd64
mkdir -p "$d" && cp terraform-provider-pcdn "$d/terraform-provider-pcdn_v0.1.0"
```

`~/.terraform.d/plugins` is an implied mirror; any other directory needs a `filesystem_mirror` block in
the CLI config (`~/.terraformrc`) — see `docs/TERRAFORM.md`. Then `required_providers { pcdn = { source =
"namesissr/pcdn", version = "~> 0.1" } }` and `terraform init`.

**Development override** (skips `terraform init` for this provider), in `~/.terraformrc`:

```hcl
provider_installation {
  dev_overrides {
    "namesissr/pcdn" = "/path/to/terraform-provider-pcdn"   # the directory holding the binary
  }
  direct {}
}
```

`go run . -debug` starts the provider for a debugger and prints the `TF_REATTACH_PROVIDERS` value.

## Provider configuration

```hcl
provider "pcdn" {
  endpoint        = "https://cdn-api.example.com" # or PCDN_ENDPOINT; a trailing /capi/v1 is accepted
  api_key         = var.pcdn_api_key              # or PCDN_API_KEY (sensitive)
  timeout_seconds = 30                            # per HTTP request, 1-600
  max_retries     = 8                             # 0-20
}
```

`endpoint` must be `https://`, except `http://localhost`, `127.0.0.1` or `[::1]` (tests). Redirects are
never followed. The key is sent only as `Authorization: Bearer`, never logged and never echoed in errors.
Every request carries `User-Agent: terraform-provider-pcdn/<version>`.

## Resources

### `pcdn_record`

Arguments mirror the controller's `RecordIn`: `type` (A, AAAA, CNAME, ALIAS, TXT, MX, NS, SRV, CAA;
required), `content` (required), `name` (default `@`), `ttl` (60-86400, default 300), `priority`
(MX/SRV; default 10 there, null otherwise), `proxied` (A/AAAA/CNAME, default false), `pool`,
`origin_port`, `health_check` (DNS-only A/AAAA), `health_port`. Computed `id`; import with
`terraform import pcdn_record.x <id>`.

* Updates use `PATCH` with the full record, in place — including a change of `type` (the API supports
  it, so `type` does not force replacement).
* Combinations the controller would silently rewrite (proxied TXT, pool without proxied, priority on
  an A record, …) are rejected at plan time, so there is never an "inconsistent result after apply".
* The controller normalises names and contents (lower case, trailing dot, `www.example.com` → `www`,
  IPv6 compression, TXT quotes). The configured spelling stays in state: after each apply/refresh the
  controller's canonical form is kept in private state, and a refresh only reports drift when the
  stored record changed; a plan modifier also ignores spelling-only differences (e.g. after import).
* A record deleted outside Terraform is removed from state and re-created; `DELETE` → 404 counts as done.
* A non-fatal `dns_error` from the controller (zone saved, PowerDNS sync pending) is a warning.

### `pcdn_config_section`

`section` (forces replacement; one of cache, ssl, waf, ddos, firewall, ratelimit, pagerules, pools,
headers, hotlink, image, errorpages, tunnel, transform, redirects, bots, logs, webhooks) and `config`
(a JSON object, usually `jsonencode({...})`). Computed `result` (the stored section as JSON, no
secrets) and sensitive `secrets` (webhooks only). Import by section name.

* Create/update = `PUT` of the whole section (omitted keys get the controller's defaults), followed by a
  `GET` that becomes `result`.
* **Diff on normalised JSON.** A resource-level plan modifier treats `config` as unchanged when it is
  the same JSON value as in state (key order, whitespace and `1` vs `1.0` ignored). The comparison is
  strict, not "subset", so removing a key is a real change (the key returns to its default).
* **Defaults and drift.** `config` keeps the configured text; drift detection compares the
  controller's current section with `result` from the last apply (GET vs GET, so server-added defaults
  never cause a diff). When they differ — the section was changed in the panel or via the API — the
  changed top-level keys are written into `config` in state and the plan shows exactly those keys.
* **Write-only fields.** `logs.secret_key` is returned as `""` (+ `secret_key_set`). Because drift is
  detected against `result`, the configured secret never causes a diff and is never copied into
  `result`; it is sent on every PUT of that section. A secret changed in the panel cannot be detected.
* **Webhook secrets.** The controller returns each signing secret once (`new_secrets` of the PUT
  reply); it is stored in the sensitive `secrets` map (by webhook id) and dropped when the webhook goes
  away. Items without an `id` are matched to the stored webhook with the same `url` (when exactly one
  matches) so editing a webhook keeps its id and secret instead of creating a new one.
* **Delete is a no-op** with a warning: sections cannot be deleted. Apply `config = jsonencode({})`
  first to reset a section to its defaults.
* The `X-Pcdn-Warnings` header of a PUT becomes warning diagnostics.
* Import stores the full stored section as `config`, so a partial configuration shows a one-time update.

### `pcdn_purge`

`urls` (full URLs), `prefixes` (`/path/` or `https://host/path/`, ≤ 20, ≤ 200 chars), `everything`,
`triggers` (map) — all force replacement, so any change queues a new purge. Computed `id` (random),
`queued` (`"3"` or `"all"`), `purged_at`. Read and delete never call the API. At least one URL/prefix or
`everything = true` is required (an empty request would purge everything on the controller);
`everything` cannot be combined with lists; at most 100 URLs + prefixes.

### `pcdn_site` (data source)

`domain`, `status`, `suspended`, `plan_json` (plan + features, `jsondecode` it), `nameservers`,
`cname_target`, `ssl_status`.

## Errors, retries and rate limits

* Controller errors keep their `detail`: a string, or FastAPI's list rendered as `loc: msg` lines,
  plus a one-line hint for 401/403/404/422/429/5xx.
* `429` is retried for every request (the controller's limiter rejects before doing anything);
  `5xx` and network errors only for idempotent requests (GET, PUT, DELETE, the full-record PATCH) —
  never a record `POST` or a purge. Exponential backoff with jitter (1 s … 30 s), `Retry-After` honoured,
  up to `max_retries`.
* **Writes are serialised per provider instance.** The controller stores all sections of a site in one
  JSON document that each section PUT reads, modifies and writes back, so two concurrent PUTs of
  different sections can lose one update; config writes are also limited per key (`CAPI_CONFIG_RATE`,
  default 6/min). Reads stay parallel.

## Development

```sh
gofmt -l . && go vet ./... && go test ./... && go build ./...
```

Tests run fully offline:

* `internal/client`: httptest-based tests of error mapping, retry rules, Retry-After, write
  serialisation, endpoint validation.
* `internal/provider`: real `terraform plan/apply/import/refresh/destroy` cycles
  (`terraform-plugin-testing`, `resource.UnitTest`) with the provider served in-process against an
  httptest **fake controller** that mimics the controller's normalisation, defaults, write-only secrets,
  webhook ids/secrets, purge rules, scopes and error shapes. They need a Terraform CLI
  (`TF_ACC_TERRAFORM_PATH`, or `terraform` on `PATH`) and are skipped without one, unless
  `PCDN_REQUIRE_TERRAFORM=1` (CI) turns that into a failure.

Layout:

```
main.go                       providerserver (protocol 6, -debug)
internal/client/              HTTP client: auth, errors, retries, write lock
internal/provider/            provider, resources, data source, JSON helpers, tests + fake controller
examples/                     provider, resources/<name>/resource.tf (+ import.sh), data-sources/<name>/
```
