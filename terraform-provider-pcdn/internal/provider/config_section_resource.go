package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/namesissr/whmcs-cdn/terraform-provider-pcdn/internal/client"
)

// sectionNames are the keys of controller/app/sections.py SECTIONS plus the SPEC §14.3.2 / §14.3.3
// sections `logs` and `webhooks`.
var sectionNames = []string{
	"cache", "ssl", "waf", "ddos", "firewall", "ratelimit", "pagerules", "pools", "headers", "hotlink",
	"image", "errorpages", "tunnel", "transform", "redirects", "bots", "logs", "webhooks",
}

var (
	_ resource.Resource                = (*configSectionResource)(nil)
	_ resource.ResourceWithConfigure   = (*configSectionResource)(nil)
	_ resource.ResourceWithImportState = (*configSectionResource)(nil)
	_ resource.ResourceWithModifyPlan  = (*configSectionResource)(nil)
)

type configSectionResource struct {
	client *client.Client
}

// NewConfigSectionResource returns the pcdn_config_section resource.
func NewConfigSectionResource() resource.Resource { return &configSectionResource{} }

type configSectionModel struct {
	ID      types.String `tfsdk:"id"`
	Section types.String `tfsdk:"section"`
	Config  types.String `tfsdk:"config"`
	Result  types.String `tfsdk:"result"`
	Secrets types.Map    `tfsdk:"secrets"`
}

func (r *configSectionResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_config_section"
}

func (r *configSectionResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "One configuration section of the API key's site (`/capi/v1/config/{section}`, key scope `dns`). " +
			"The whole section is replaced with PUT on create and update (keys left out of `config` get the controller's defaults). " +
			"Sections cannot be deleted: destroying this resource only removes it from state.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "The section name.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"section": schema.StringAttribute{
				Required:      true,
				Description:   "Section name: " + strings.Join(sectionNames, ", ") + ". Changing it forces a new resource.",
				Validators:    []validator.String{stringvalidator.OneOf(sectionNames...)},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"config": schema.StringAttribute{
				Required: true,
				Description: "The section body as a JSON object, usually `jsonencode({...})`. Compared semantically: key order, whitespace " +
					"and number formatting never cause a diff. Write-only values (`logs.secret_key`) are sent but never read back.",
				Validators: []validator.String{jsonObjectValidator{}},
			},
			"result": schema.StringAttribute{
				Computed: true,
				Description: "The section as stored by the controller (normalised, with every default filled in), as JSON. " +
					"Secrets are never included. Use `jsondecode(...)` to read assigned ids such as webhook ids.",
			},
			"secrets": schema.MapAttribute{
				Computed:    true,
				Sensitive:   true,
				ElementType: types.StringType,
				Description: "Webhook signing secrets by webhook id, captured from the controller's `new_secrets` the only time it returns them " +
					"(when a webhook is created). Null for other sections. Secrets of webhooks that no longer exist are dropped.",
			},
		},
	}
}

func (r *configSectionResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFrom(req.ProviderData, &resp.Diagnostics)
}

// ModifyPlan implements the semantic diff on `config`: when the configured JSON equals the JSON in
// state (ignoring key order / whitespace / number formatting), the prior state is planned so no
// update is shown. This is a strict equality (not a subset match) so removing a key from `config`
// is still a change — PUT replaces the whole section and the removed key returns to its default.
func (r *configSectionResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		if !req.State.Raw.IsNull() {
			var state configSectionModel
			resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
			resp.Diagnostics.AddWarning("Config section will only be removed from state",
				deleteWarning(state.Section.ValueString()))
		}
		return
	}
	var plan configSectionModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	changed := false
	// only webhooks ever return secrets: plan a known null instead of "(known after apply)"
	if !plan.Section.IsUnknown() && plan.Section.ValueString() != "webhooks" && !plan.Secrets.IsNull() {
		plan.Secrets = types.MapNull(types.StringType)
		changed = true
	}
	if !req.State.Raw.IsNull() {
		var state configSectionModel
		resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
		if resp.Diagnostics.HasError() {
			return
		}
		if !plan.Config.IsUnknown() && !plan.Section.IsUnknown() && plan.Section.ValueString() == state.Section.ValueString() &&
			!state.Config.IsNull() && jsonEqual(plan.Config.ValueString(), state.Config.ValueString()) {
			plan.Config = state.Config
			plan.Result = state.Result
			plan.Secrets = state.Secrets
			plan.ID = state.ID
			changed = true
		}
	}
	if changed {
		resp.Diagnostics.Append(resp.Plan.Set(ctx, plan)...)
	}
}

func deleteWarning(section string) string {
	return fmt.Sprintf("Configuration sections cannot be deleted on the controller. Section %q keeps its current settings; "+
		"it is only removed from Terraform state. To restore the defaults, apply `config = jsonencode({})` before removing the resource.", section)
}

func (r *configSectionResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if !requireClient(r.client, &resp.Diagnostics) {
		return
	}
	var plan configSectionModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.write(ctx, &plan, types.StringNull(), types.MapNull(types.StringType), &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *configSectionResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	if !requireClient(r.client, &resp.Diagnostics) {
		return
	}
	var plan, state configSectionModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.write(ctx, &plan, state.Result, state.Secrets, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// write PUTs the configured section, then re-reads it with GET so `result` has exactly the shape a
// later refresh sees (drift detection compares GET with GET). `config` keeps the configured text.
func (r *configSectionResource) write(ctx context.Context, m *configSectionModel, priorResult types.String,
	priorSecrets types.Map, diags *diag.Diagnostics) {
	section := m.Section.ValueString()
	body := json.RawMessage(m.Config.ValueString())

	var prior any
	if !priorResult.IsNull() && !priorResult.IsUnknown() {
		prior, _ = decodeJSON(priorResult.ValueString())
	}
	if section == "webhooks" && prior != nil {
		if cfg, err := decodeJSONExact(m.Config.ValueString()); err == nil && injectWebhookIDs(cfg, prior) {
			if b, err := json.Marshal(cfg); err == nil {
				body = b
			}
		}
	}

	w, err := r.client.PutSection(ctx, section, body)
	if err != nil {
		addAPIError(diags, fmt.Sprintf("Could not write config section %q", section), err)
		return
	}
	for _, msg := range w.Warnings {
		diags.AddWarning(fmt.Sprintf("Controller warning for section %q", section), msg)
	}
	putBody, _ := decodeJSON(string(w.Body))
	fresh := newSecrets(putBody)

	stored := putBody
	if raw, gerr := r.client.GetSection(ctx, section); gerr == nil {
		if v, derr := decodeJSON(string(raw)); derr == nil {
			stored = v
		}
	} else {
		diags.AddWarning(fmt.Sprintf("Could not re-read config section %q", section),
			"The section was saved, but reading it back failed; `result` holds the PUT reply instead. "+gerr.Error())
	}
	stored = redactSection(stored)

	m.ID = types.StringValue(section)
	m.Result = types.StringValue(canonicalJSON(stored))
	m.Secrets = mergeSecrets(section, priorSecrets, fresh, stored, diags)
}

// mergeSecrets combines the secrets already in state with the ones just returned, keeping only ids
// that still exist in the stored webhooks section. Null when there is nothing to keep.
func mergeSecrets(section string, prior types.Map, fresh map[string]string, stored any,
	diags *diag.Diagnostics) types.Map {
	if section != "webhooks" {
		return types.MapNull(types.StringType)
	}
	all := map[string]string{}
	if !prior.IsNull() && !prior.IsUnknown() {
		for k, v := range prior.Elements() {
			if s, ok := v.(types.String); ok && !s.IsNull() && !s.IsUnknown() {
				all[k] = s.ValueString()
			}
		}
	}
	for k, v := range fresh {
		all[k] = v
	}
	live := webhookIDs(stored)
	elems := map[string]attr.Value{}
	for k, v := range all {
		if live[k] {
			elems[k] = types.StringValue(v)
		}
	}
	if len(elems) == 0 {
		return types.MapNull(types.StringType)
	}
	out, d := types.MapValue(types.StringType, elems)
	diags.Append(d...)
	return out
}

// Read compares the controller's section with `result` from the last apply/refresh. When they are
// equal nothing changed outside Terraform and `config` keeps the configured text — even though the
// controller fills in defaults and blanks write-only values like `logs.secret_key`. When they differ
// (a change in the panel or the API), the changed top-level keys are written into `config` (see
// driftedConfig) so the next plan shows exactly that drift and re-applies the configuration.
func (r *configSectionResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if !requireClient(r.client, &resp.Diagnostics) {
		return
	}
	var state configSectionModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	section := state.Section.ValueString()
	raw, err := r.client.GetSection(ctx, section)
	if err != nil {
		if client.IsNotFound(err) {
			resp.Diagnostics.AddError(fmt.Sprintf("Config section %q is not supported by this controller", section),
				"The controller answered 404 for this section; it may be older than this provider version. "+err.Error())
			return
		}
		addAPIError(&resp.Diagnostics, fmt.Sprintf("Could not read config section %q", section), err)
		return
	}
	v, err := decodeJSON(string(raw))
	if err != nil {
		resp.Diagnostics.AddError("Unexpected response from the controller", err.Error())
		return
	}
	current := canonicalJSON(redactSection(v))

	switch {
	case state.Config.IsNull() || state.Config.IsUnknown() || state.Result.IsNull() || state.Result.IsUnknown():
		state.Config = types.StringValue(current) // import: the stored section is all there is
	case !jsonEqual(current, state.Result.ValueString()):
		state.Config = types.StringValue(driftedConfig(state.Config.ValueString(), state.Result.ValueString(), v))
	}
	state.ID = types.StringValue(section)
	state.Result = types.StringValue(current)
	state.Secrets = mergeSecrets(section, state.Secrets, nil, v, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *configSectionResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state configSectionModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	resp.Diagnostics.AddWarning("Config section removed from state only", deleteWarning(state.Section.ValueString()))
}

func (r *configSectionResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	name := strings.TrimSpace(req.ID)
	known := false
	for _, s := range sectionNames {
		known = known || s == name
	}
	if !known {
		resp.Diagnostics.AddError("Invalid import id",
			fmt.Sprintf("Import a pcdn_config_section by its section name (%s), e.g. `terraform import pcdn_config_section.cache cache`.",
				strings.Join(sectionNames, ", ")))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), name)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("section"), name)...)
}

// jsonObjectValidator requires a string holding one JSON object.
type jsonObjectValidator struct{}

func (jsonObjectValidator) Description(context.Context) string { return "must be a JSON object" }

func (v jsonObjectValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (jsonObjectValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	v, err := decodeJSON(req.ConfigValue.ValueString())
	if err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid JSON", "config must be valid JSON (use jsonencode): "+err.Error())
		return
	}
	if _, ok := v.(map[string]any); !ok {
		resp.Diagnostics.AddAttributeError(req.Path, "config must be a JSON object",
			`The section body is a JSON object, e.g. jsonencode({ enabled = true }).`)
	}
}
