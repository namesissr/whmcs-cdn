// Package provider implements the `pcdn` Terraform provider for the Pasargad CDN customer API
// (SPEC §10.1, §14.3.5, §14.3.6).
package provider

import (
	"context"
	"os"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/namesissr/whmcs-cdn/terraform-provider-pcdn/internal/client"
)

const (
	envEndpoint = "PCDN_ENDPOINT"
	envAPIKey   = "PCDN_API_KEY"
)

var _ provider.Provider = (*pcdnProvider)(nil)

// pcdnProvider is the provider implementation.
type pcdnProvider struct {
	version string
	// testBackoff shortens retry delays in tests (zero = client defaults).
	testBackoff time.Duration
}

type providerModel struct {
	Endpoint       types.String `tfsdk:"endpoint"`
	APIKey         types.String `tfsdk:"api_key"`
	TimeoutSeconds types.Int64  `tfsdk:"timeout_seconds"`
	MaxRetries     types.Int64  `tfsdk:"max_retries"`
}

// New returns a provider factory for the given version (set at build time with -ldflags).
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &pcdnProvider{version: version}
	}
}

func (p *pcdnProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "pcdn"
	resp.Version = p.version
}

func (p *pcdnProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages one Pasargad CDN site through the customer API (`/capi/v1`) with a per-service customer API key. " +
			"The key is bound to exactly one site, so resources never take a domain.",
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				Optional: true,
				Description: "Controller base URL, e.g. `https://cdn-api.example.com` (a trailing `/capi/v1` is accepted). " +
					"Must be https; plain http is only accepted for localhost / 127.0.0.1 / [::1]. Defaults to the `PCDN_ENDPOINT` environment variable.",
			},
			"api_key": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				Description: "Customer API key (`pcdn_` + 40 hex), created in the WHMCS client area. Its scopes decide what the provider may do: " +
					"`dns` for `pcdn_record` / `pcdn_config_section`, `purge` for `pcdn_purge`. Defaults to the `PCDN_API_KEY` environment variable.",
			},
			"timeout_seconds": schema.Int64Attribute{
				Optional:    true,
				Description: "Timeout of a single HTTP request in seconds (1-600, default 30).",
				Validators:  []validator.Int64{int64validator.Between(1, 600)},
			},
			"max_retries": schema.Int64Attribute{
				Optional: true,
				Description: "How many times a request is retried after HTTP 429 (any request) or 5xx / network errors (idempotent requests only), " +
					"with exponential backoff that honours Retry-After (0-20, default 8).",
				Validators: []validator.Int64{int64validator.Between(0, 20)},
			},
		},
	}
}

func (p *pcdnProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if cfg.Endpoint.IsUnknown() {
		resp.Diagnostics.AddAttributeError(path.Root("endpoint"), "Unknown pcdn endpoint",
			"The provider cannot be configured with an endpoint that is only known after apply. Use a static value or the PCDN_ENDPOINT environment variable.")
	}
	if cfg.APIKey.IsUnknown() {
		resp.Diagnostics.AddAttributeError(path.Root("api_key"), "Unknown pcdn API key",
			"The provider cannot be configured with an API key that is only known after apply. Use a static value or the PCDN_API_KEY environment variable.")
	}
	if resp.Diagnostics.HasError() {
		return
	}

	endpoint := os.Getenv(envEndpoint)
	if !cfg.Endpoint.IsNull() {
		endpoint = cfg.Endpoint.ValueString()
	}
	apiKey := os.Getenv(envAPIKey)
	if !cfg.APIKey.IsNull() {
		apiKey = cfg.APIKey.ValueString()
	}
	if endpoint == "" {
		resp.Diagnostics.AddAttributeError(path.Root("endpoint"), "Missing pcdn endpoint",
			"Set `endpoint` in the provider block or the PCDN_ENDPOINT environment variable to the controller URL, e.g. https://cdn-api.example.com.")
	}
	if apiKey == "" {
		resp.Diagnostics.AddAttributeError(path.Root("api_key"), "Missing pcdn API key",
			"Set `api_key` in the provider block or the PCDN_API_KEY environment variable to a customer API key (pcdn_...).")
	}
	if resp.Diagnostics.HasError() {
		return
	}

	ccfg := client.Config{
		Endpoint:   endpoint,
		APIKey:     apiKey,
		UserAgent:  "terraform-provider-pcdn/" + p.version,
		MaxRetries: -1,
		MinBackoff: p.testBackoff,
		MaxBackoff: p.testBackoff * 4,
	}
	if !cfg.TimeoutSeconds.IsNull() && !cfg.TimeoutSeconds.IsUnknown() {
		ccfg.Timeout = time.Duration(cfg.TimeoutSeconds.ValueInt64()) * time.Second
	}
	if !cfg.MaxRetries.IsNull() && !cfg.MaxRetries.IsUnknown() {
		ccfg.MaxRetries = int(cfg.MaxRetries.ValueInt64())
	}
	c, err := client.New(ccfg)
	if err != nil {
		// client.New never includes the key in its errors
		attr := path.Root("endpoint")
		if _, eerr := client.NormalizeEndpoint(endpoint); eerr == nil {
			attr = path.Root("api_key")
		}
		resp.Diagnostics.AddAttributeError(attr, "Invalid pcdn provider configuration", err.Error())
		return
	}
	resp.ResourceData = c
	resp.DataSourceData = c
}

func (p *pcdnProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewRecordResource,
		NewConfigSectionResource,
		NewPurgeResource,
	}
}

func (p *pcdnProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewSiteDataSource,
	}
}
