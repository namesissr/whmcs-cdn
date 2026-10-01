package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/namesissr/whmcs-cdn/terraform-provider-pcdn/internal/client"
)

var (
	_ datasource.DataSource              = (*siteDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*siteDataSource)(nil)
)

type siteDataSource struct {
	client *client.Client
}

// NewSiteDataSource returns the pcdn_site data source.
func NewSiteDataSource() datasource.DataSource { return &siteDataSource{} }

type siteModel struct {
	ID          types.String `tfsdk:"id"`
	Domain      types.String `tfsdk:"domain"`
	Status      types.String `tfsdk:"status"`
	Suspended   types.Bool   `tfsdk:"suspended"`
	PlanJSON    types.String `tfsdk:"plan_json"`
	Nameservers types.List   `tfsdk:"nameservers"`
	CNAMETarget types.String `tfsdk:"cname_target"`
	SSLStatus   types.String `tfsdk:"ssl_status"`
}

func (d *siteDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_site"
}

func (d *siteDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The site the API key belongs to (`GET /capi/v1/site`; any key scope).",
		Attributes: map[string]schema.Attribute{
			"id":        schema.StringAttribute{Computed: true, Description: "The site domain."},
			"domain":    schema.StringAttribute{Computed: true, Description: "The site domain, e.g. `example.com`."},
			"status":    schema.StringAttribute{Computed: true, Description: "Effective site status as reported by the controller."},
			"suspended": schema.BoolAttribute{Computed: true, Description: "Whether the site is suspended."},
			"plan_json": schema.StringAttribute{
				Computed:    true,
				Description: "The site's plan and features as JSON (`jsondecode(...)`), e.g. `bandwidth_limit_gb`, `max_records`, `features.waf`.",
			},
			"nameservers": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Nameservers the domain must delegate to.",
			},
			"cname_target": schema.StringAttribute{Computed: true, Description: "CNAME target for setups that do not delegate the zone (null when not offered)."},
			"ssl_status":   schema.StringAttribute{Computed: true, Description: "Certificate status, e.g. `pending`, `active`, `error` (null when unknown)."},
		},
	}
}

func (d *siteDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = clientFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *siteDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	if !requireClient(d.client, &resp.Diagnostics) {
		return
	}
	site, err := d.client.GetSite(ctx)
	if err != nil {
		addAPIError(&resp.Diagnostics, "Could not read the site", err)
		return
	}
	m := siteModel{
		ID:          types.StringValue(site.Domain),
		Domain:      types.StringValue(site.Domain),
		Status:      types.StringValue(site.Status),
		Suspended:   types.BoolValue(site.Suspended),
		PlanJSON:    types.StringNull(),
		CNAMETarget: stringValue(site.CNAMETarget),
		SSLStatus:   stringValue(site.SSLStatus),
	}
	if len(site.Plan) > 0 && string(site.Plan) != "null" {
		if v, err := decodeJSON(string(site.Plan)); err == nil {
			m.PlanJSON = types.StringValue(canonicalJSON(v))
		} else {
			m.PlanJSON = types.StringValue(string(site.Plan))
		}
	}
	ns := site.Nameservers
	if ns == nil {
		ns = []string{}
	}
	list, diags := types.ListValueFrom(ctx, types.StringType, ns)
	resp.Diagnostics.Append(diags...)
	m.Nameservers = list
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}
