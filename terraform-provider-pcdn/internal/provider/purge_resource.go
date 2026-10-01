package provider

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"regexp"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/namesissr/whmcs-cdn/terraform-provider-pcdn/internal/client"
)

// Limits of controller/app/routes_admin.py purge_site (SPEC §9.2).
const (
	maxPurgeItems    = 100
	maxPurgePrefixes = 20
	maxPrefixLen     = 200
)

var (
	purgeURLRE    = regexp.MustCompile(`^https?://\S`)
	purgePrefixRE = regexp.MustCompile(`^(/|https?://\S)`)
)

var (
	_ resource.Resource                   = (*purgeResource)(nil)
	_ resource.ResourceWithConfigure      = (*purgeResource)(nil)
	_ resource.ResourceWithValidateConfig = (*purgeResource)(nil)
)

type purgeResource struct {
	client *client.Client
}

// NewPurgeResource returns the pcdn_purge resource.
func NewPurgeResource() resource.Resource { return &purgeResource{} }

type purgeModel struct {
	ID         types.String `tfsdk:"id"`
	URLs       types.List   `tfsdk:"urls"`
	Prefixes   types.List   `tfsdk:"prefixes"`
	Everything types.Bool   `tfsdk:"everything"`
	Triggers   types.Map    `tfsdk:"triggers"`
	Queued     types.String `tfsdk:"queued"`
	PurgedAt   types.String `tfsdk:"purged_at"`
}

func (r *purgeResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_purge"
}

func (r *purgeResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Queues one cache purge for the API key's site (`POST /capi/v1/purge`, key scope `purge`) when it is created. " +
			"Every argument forces a new resource, so any change — typically to `triggers` — queues a new purge. " +
			"Reading and destroying it never call the API (a purge cannot be undone).",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "Random id of this purge (the controller does not return one).",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"urls": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Full URLs to purge exactly, e.g. `https://example.com/app.css` (http:// or https://).",
				Validators: []validator.List{
					listvalidator.SizeAtMost(maxPurgeItems),
					listvalidator.ValueStringsAre(stringvalidator.RegexMatches(purgeURLRE, "must be a full URL starting with http:// or https://")),
				},
				PlanModifiers: []planmodifier.List{listplanmodifier.RequiresReplace()},
			},
			"prefixes": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Path prefixes to purge: a path (`/blog/`) or a full URL prefix (`https://example.com/img/`). Up to 20, each at most 200 characters.",
				Validators: []validator.List{
					listvalidator.SizeAtMost(maxPurgePrefixes),
					listvalidator.ValueStringsAre(
						stringvalidator.LengthAtMost(maxPrefixLen),
						stringvalidator.RegexMatches(purgePrefixRE, "must start with / or http:// or https://"),
					),
				},
				PlanModifiers: []planmodifier.List{listplanmodifier.RequiresReplace()},
			},
			"everything": schema.BoolAttribute{
				Optional:      true,
				Computed:      true,
				Default:       booldefault.StaticBool(false),
				Description:   "Purge the whole site cache. Cannot be combined with urls or prefixes.",
				PlanModifiers: []planmodifier.Bool{boolplanmodifier.RequiresReplace()},
			},
			"triggers": schema.MapAttribute{
				Optional:      true,
				ElementType:   types.StringType,
				Description:   "Arbitrary values; changing any of them queues a new purge (e.g. a release version or a file hash).",
				PlanModifiers: []planmodifier.Map{mapplanmodifier.RequiresReplace()},
			},
			"queued": schema.StringAttribute{
				Computed:      true,
				Description:   "What the controller queued: the number of URLs + prefixes, or `all`.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"purged_at": schema.StringAttribute{
				Computed:      true,
				Description:   "When the purge was queued (RFC 3339, UTC).",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
		},
	}
}

func (r *purgeResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFrom(req.ProviderData, &resp.Diagnostics)
}

// ValidateConfig enforces the controller's PurgeIn rules up front. An empty request is rejected
// on purpose: the controller would treat it as "purge everything".
func (r *purgeResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var m purgeModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if m.URLs.IsUnknown() || m.Prefixes.IsUnknown() || m.Everything.IsUnknown() {
		return
	}
	nURLs, nPrefixes := len(m.URLs.Elements()), len(m.Prefixes.Elements())
	everything := m.Everything.ValueBool()
	switch {
	case everything && nURLs+nPrefixes > 0:
		resp.Diagnostics.AddAttributeError(path.Root("everything"), "everything conflicts with urls and prefixes",
			"everything = true purges the whole site cache; leave urls and prefixes empty, or set everything = false.")
	case !everything && nURLs+nPrefixes == 0:
		resp.Diagnostics.AddError("Nothing to purge",
			"Set urls and/or prefixes, or everything = true to purge the whole site cache. "+
				"(An empty purge request would make the controller purge everything, so it must be explicit.)")
	case nURLs+nPrefixes > maxPurgeItems:
		resp.Diagnostics.AddError("Too many purge items",
			"The controller accepts at most 100 URLs + prefixes in one purge; split them over several pcdn_purge resources.")
	}
}

func (r *purgeResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if !requireClient(r.client, &resp.Diagnostics) {
		return
	}
	var plan purgeModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	in := client.PurgeInput{Everything: plan.Everything.ValueBool()}
	if !plan.URLs.IsNull() {
		resp.Diagnostics.Append(plan.URLs.ElementsAs(ctx, &in.URLs, false)...)
	}
	if !plan.Prefixes.IsNull() {
		resp.Diagnostics.Append(plan.Prefixes.ElementsAs(ctx, &in.Prefixes, false)...)
	}
	if resp.Diagnostics.HasError() {
		return
	}
	res, err := r.client.Purge(ctx, in)
	if err != nil {
		addAPIError(&resp.Diagnostics, "Could not purge the cache", err)
		return
	}
	plan.ID = types.StringValue(randomID())
	plan.Queued = types.StringValue(res.QueuedString())
	plan.PurgedAt = types.StringValue(time.Now().UTC().Format(time.RFC3339))
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Read is a no-op: a purge is a one-shot action with nothing to refresh.
func (r *purgeResource) Read(context.Context, resource.ReadRequest, *resource.ReadResponse) {}

// Update is never reached for a real change (every argument forces replacement); it only carries
// the computed values over.
func (r *purgeResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state purgeModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.ID, plan.Queued, plan.PurgedAt = state.ID, state.Queued, state.PurgedAt
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Delete is a no-op: a purge cannot be undone; the resource just leaves state.
func (r *purgeResource) Delete(context.Context, resource.DeleteRequest, *resource.DeleteResponse) {}

func randomID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return time.Now().UTC().Format("20060102T150405.000000000Z")
	}
	return hex.EncodeToString(b)
}
