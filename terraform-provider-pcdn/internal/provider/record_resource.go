package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/namesissr/whmcs-cdn/terraform-provider-pcdn/internal/client"
)

var (
	_ resource.Resource                   = (*recordResource)(nil)
	_ resource.ResourceWithConfigure      = (*recordResource)(nil)
	_ resource.ResourceWithImportState    = (*recordResource)(nil)
	_ resource.ResourceWithValidateConfig = (*recordResource)(nil)
)

// recordTypes mirrors controller/app/validation.py RECORD_TYPES.
var recordTypes = []string{"A", "AAAA", "CNAME", "ALIAS", "TXT", "MX", "NS", "SRV", "CAA"}

// PROXYABLE in validation.py; the controller silently clears `proxied` for other types.
var proxyableTypes = map[string]bool{"A": true, "AAAA": true, "CNAME": true}

// The controller keeps `priority` only for these types (default 10) and clears it otherwise.
var priorityTypes = map[string]bool{"MX": true, "SRV": true}

// weightTypes may carry a weight (SPEC §16.7: non-proxied A/AAAA/CNAME only; the controller rejects others).
var weightTypes = map[string]bool{"A": true, "AAAA": true, "CNAME": true}

// healthPathRE mirrors RecordIn.health_path's pattern (max_length 512).
var healthPathRE = regexp.MustCompile(`^/[^\s"'<>\\]*$`)

// healthAttrTypes is the shape of the computed `health` object (the controller's last probe).
var healthAttrTypes = map[string]attr.Type{
	"ok": types.BoolType, "ms": types.Int64Type, "fail": types.Int64Type, "checked_at": types.StringType,
	"error": types.StringType, "advertised": types.BoolType,
}

// poolNameRE mirrors RecordIn.pool's pattern.
var poolNameRE = regexp.MustCompile(`^[a-z0-9_-]{1,32}$`)

// privCanonical is the private-state key holding the controller's canonical name/content as of the
// last apply or refresh (see the Read comment).
const privCanonical = "canonical"

type canonicalRecord struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

type recordResource struct {
	client *client.Client
}

// NewRecordResource returns the pcdn_record resource.
func NewRecordResource() resource.Resource { return &recordResource{} }

type recordModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Type        types.String `tfsdk:"type"`
	Content     types.String `tfsdk:"content"`
	TTL         types.Int64  `tfsdk:"ttl"`
	Priority    types.Int64  `tfsdk:"priority"`
	Proxied     types.Bool   `tfsdk:"proxied"`
	Pool        types.String `tfsdk:"pool"`
	OriginPort  types.Int64  `tfsdk:"origin_port"`
	HealthCheck types.Bool   `tfsdk:"health_check"`
	HealthPort  types.Int64  `tfsdk:"health_port"`
	// SPEC §16.7
	Weight         types.Int64  `tfsdk:"weight"`
	HealthProtocol types.String `tfsdk:"health_protocol"`
	HealthPath     types.String `tfsdk:"health_path"`
	Health         types.Object `tfsdk:"health"`
}

func (r *recordResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_record"
}

func (r *recordResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A DNS record of the API key's site (`/capi/v1/records`, key scope `dns`). Updates are applied in place with PATCH " +
			"(the full record is sent), including type changes. The controller normalises names and contents (lower case, trailing dot, " +
			"canonical IPs, the site domain suffix); the configured spelling is kept in state as long as the stored record is unchanged.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "Numeric record id assigned by the controller. Also the import id.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString("@"),
				Description: "Record name relative to the site domain: `@` for the apex (default), `www`, `blog.eu`. " +
					"A full name under the site domain (`www.example.com`) is accepted and stored relative.",
				Validators:    []validator.String{stringvalidator.LengthAtMost(253)},
				PlanModifiers: []planmodifier.String{equivalentSpelling{}},
			},
			"type": schema.StringAttribute{
				Required:    true,
				Description: "Record type: " + strings.Join(recordTypes, ", ") + " (upper case).",
				Validators:  []validator.String{stringvalidator.OneOf(recordTypes...)},
			},
			"content": schema.StringAttribute{
				Required: true,
				Description: "Record value: a public IPv4/IPv6 address (A/AAAA), a host name (CNAME/ALIAS/NS/MX), " +
					"`weight port target` (SRV), `0 issue \"letsencrypt.org\"` (CAA) or text (TXT).",
				Validators:    []validator.String{stringvalidator.LengthBetween(1, 2048)},
				PlanModifiers: []planmodifier.String{equivalentSpelling{content: true}},
			},
			"ttl": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(300),
				Description: "TTL in seconds, 60-86400 (default 300).",
				Validators:  []validator.Int64{int64validator.Between(60, 86400)},
			},
			"priority": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				Description: "Priority for MX and SRV records (0-65535). When omitted the controller uses 10 for MX/SRV; " +
					"it is always null for other types.",
				Validators:    []validator.Int64{int64validator.Between(0, 65535)},
				PlanModifiers: []planmodifier.Int64{priorityPlanModifier{}},
			},
			"proxied": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Serve this host through the CDN edges (A, AAAA and CNAME only). Default false (DNS only).",
			},
			"pool": schema.StringAttribute{
				Optional:    true,
				Description: "Load-balancer pool name (section `pools`) for a proxied A/AAAA/CNAME record; `content` stays the DNS fallback.",
				Validators:  []validator.String{stringvalidator.RegexMatches(poolNameRE, "must match [a-z0-9_-]{1,32}")},
			},
			"origin_port": schema.Int64Attribute{
				Optional:    true,
				Description: "Origin port for a proxied record without a pool (1-65535; default 80/443 by origin protocol).",
				Validators:  []validator.Int64{int64validator.Between(1, 65535)},
			},
			"health_check": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				Description: "DNS failover for non-proxied A/AAAA records (and weighted CNAME sets): the controller probes the record " +
					"(`health_protocol`, `health_port`, `health_path`) and withdraws unhealthy members from the answer, never all of them.",
			},
			"health_port": schema.Int64Attribute{
				Optional:    true,
				Description: "Port probed when `health_check` is true (default 80, or 443 for `https`).",
				Validators:  []validator.Int64{int64validator.Between(1, 65535)},
			},
			"weight": schema.Int64Attribute{
				Optional: true,
				Description: "Weight 0-100 of this record in a weighted / failover set of non-proxied A, AAAA or CNAME records with the " +
					"same name (SPEC §16.7); 0 = backup, answered only when every weighted member is down. Null = not weighted.",
				Validators: []validator.Int64{int64validator.Between(0, 100)},
			},
			"health_protocol": schema.StringAttribute{
				Optional: true,
				Description: "Probe used by the controller when `health_check` is true: `tcp`, `http` or `https` " +
					"(null = TCP; on an unweighted A/AAAA set null keeps the PowerDNS port check).",
				Validators: []validator.String{stringvalidator.OneOf("tcp", "http", "https")},
			},
			"health_path": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Path requested by an `http`/`https` probe, e.g. `/healthz` (default `/`). Null for other probes.",
				Validators: []validator.String{
					stringvalidator.LengthAtMost(512),
					stringvalidator.RegexMatches(healthPathRE, "must start with / and contain no spaces, quotes, < > or backslashes"),
				},
				PlanModifiers: []planmodifier.String{healthPathPlanModifier{}},
			},
			"health": schema.SingleNestedAttribute{
				Computed: true,
				Description: "The controller's last probe of this record (null without `health_check`). Refreshed on every read; " +
					"informational only, never causes a diff. Kept as last read across an apply that does not toggle `health_check`.",
				PlanModifiers: []planmodifier.Object{healthPlanModifier{}},
				Attributes: map[string]schema.Attribute{
					"ok":         schema.BoolAttribute{Computed: true, Description: "Whether the last probe succeeded (null before the first probe)."},
					"ms":         schema.Int64Attribute{Computed: true, Description: "Duration of the last probe in milliseconds."},
					"fail":       schema.Int64Attribute{Computed: true, Description: "Consecutive failed probes."},
					"checked_at": schema.StringAttribute{Computed: true, Description: "Time of the last probe (UTC, ISO 8601)."},
					"error":      schema.StringAttribute{Computed: true, Description: "Error of the last failed probe."},
					"advertised": schema.BoolAttribute{Computed: true, Description: "Whether the record is currently in the DNS answer."},
				},
			},
		},
	}
}

func (r *recordResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFrom(req.ProviderData, &resp.Diagnostics)
}

// ValidateConfig rejects combinations the controller would silently rewrite (which would otherwise
// surface as "inconsistent result after apply" errors).
func (r *recordResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var m recordModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	typeKnown := !m.Type.IsNull() && !m.Type.IsUnknown()
	rtype := m.Type.ValueString()
	proxiedKnown := !m.Proxied.IsUnknown()
	proxied := m.Proxied.ValueBool() // null = default false

	if typeKnown && proxiedKnown && proxied && !proxyableTypes[rtype] {
		resp.Diagnostics.AddAttributeError(path.Root("proxied"), "proxied is not supported for this record type",
			fmt.Sprintf("Only A, AAAA and CNAME records can be proxied through the CDN; %s records are DNS only.", rtype))
	}
	if !m.Pool.IsNull() && !m.Pool.IsUnknown() && proxiedKnown && !proxied {
		resp.Diagnostics.AddAttributeError(path.Root("pool"), "pool requires proxied = true",
			"A load-balancer pool only applies to proxied records; the controller ignores it otherwise.")
	}
	if !m.OriginPort.IsNull() && !m.OriginPort.IsUnknown() {
		if proxiedKnown && !proxied {
			resp.Diagnostics.AddAttributeError(path.Root("origin_port"), "origin_port requires proxied = true",
				"The origin port only applies to proxied records; the controller ignores it otherwise.")
		}
		if !m.Pool.IsNull() && !m.Pool.IsUnknown() {
			resp.Diagnostics.AddAttributeError(path.Root("origin_port"), "origin_port conflicts with pool",
				"A record that uses a pool takes its ports from the pool's origins.")
		}
	}
	healthKnown := !m.HealthCheck.IsUnknown()
	health := m.HealthCheck.ValueBool()
	weightSet := !m.Weight.IsNull() && !m.Weight.IsUnknown()
	if weightSet {
		if typeKnown && !weightTypes[rtype] {
			resp.Diagnostics.AddAttributeError(path.Root("weight"), "weight is not supported for this record type",
				fmt.Sprintf("Only non-proxied A, AAAA and CNAME records can be weighted; remove weight from this %s record.", rtype))
		}
		if proxiedKnown && proxied {
			resp.Diagnostics.AddAttributeError(path.Root("weight"), "weight is for DNS-only records",
				"Weighted / failover sets are answered by DNS; set proxied = false or remove weight (proxied hosts use a pool).")
		}
	}
	if healthKnown && health {
		if typeKnown && !weightTypes[rtype] {
			resp.Diagnostics.AddAttributeError(path.Root("health_check"), "health_check needs an A, AAAA or CNAME record",
				"DNS health checks are only supported for A and AAAA records and weighted CNAME sets.")
		}
		if typeKnown && rtype == "CNAME" && m.Weight.IsNull() {
			resp.Diagnostics.AddAttributeError(path.Root("health_check"), "health_check on a CNAME needs weight",
				"A lone CNAME has nothing to fail over to, so the controller turns the check off; set weight to make it part of a weighted set.")
		}
		if proxiedKnown && proxied {
			resp.Diagnostics.AddAttributeError(path.Root("health_check"), "health_check is for DNS-only records",
				"Proxied records are health-checked by the edges (use a pool); health_check only applies when proxied = false.")
		}
	}
	if !m.HealthPort.IsNull() && !m.HealthPort.IsUnknown() && healthKnown && !health {
		resp.Diagnostics.AddAttributeError(path.Root("health_port"), "health_port requires health_check = true",
			"The controller ignores health_port unless health_check is enabled.")
	}
	protoSet := !m.HealthProtocol.IsNull() && !m.HealthProtocol.IsUnknown()
	if protoSet && healthKnown && !health {
		resp.Diagnostics.AddAttributeError(path.Root("health_protocol"), "health_protocol requires health_check = true",
			"The controller ignores health_protocol unless health_check is enabled.")
	}
	if !m.HealthPath.IsNull() && !m.HealthPath.IsUnknown() && !m.HealthProtocol.IsUnknown() {
		if p := m.HealthProtocol.ValueString(); p != "http" && p != "https" {
			resp.Diagnostics.AddAttributeError(path.Root("health_path"), "health_path requires health_protocol http or https",
				"Only HTTP(S) probes request a path; the controller ignores it for TCP probes.")
		}
	}
	if !m.Priority.IsNull() && !m.Priority.IsUnknown() && typeKnown && !priorityTypes[rtype] {
		resp.Diagnostics.AddAttributeError(path.Root("priority"), "priority is only used by MX and SRV records",
			fmt.Sprintf("Remove priority from this %s record.", rtype))
	}
}

func (m recordModel) input() client.RecordInput {
	return client.RecordInput{
		Name:        m.Name.ValueString(),
		Type:        m.Type.ValueString(),
		Content:     m.Content.ValueString(),
		TTL:         m.TTL.ValueInt64(),
		Priority:    int64Ptr(m.Priority),
		Proxied:     m.Proxied.ValueBool(),
		Pool:        stringPtr(m.Pool),
		OriginPort:  int64Ptr(m.OriginPort),
		HealthCheck: m.HealthCheck.ValueBool(),
		HealthPort:  int64Ptr(m.HealthPort),
		// always sent: PATCH replaces the full record, so omitting them would reset them to null
		Weight:         int64Ptr(m.Weight),
		HealthProtocol: stringPtr(m.HealthProtocol),
		HealthPath:     stringPtr(m.HealthPath),
	}
}

// healthObject converts the controller's probe result into the computed `health` attribute.
func healthObject(h *client.RecordHealth) types.Object {
	if h == nil {
		return types.ObjectNull(healthAttrTypes)
	}
	boolV := func(b *bool) types.Bool {
		if b == nil {
			return types.BoolNull()
		}
		return types.BoolValue(*b)
	}
	obj, _ := types.ObjectValue(healthAttrTypes, map[string]attr.Value{
		"ok": boolV(h.OK), "ms": int64Value(h.MS), "fail": int64Value(h.Fail), "checked_at": stringValue(h.At),
		"error": stringValue(h.Error), "advertised": boolV(h.Advertised),
	})
	return obj
}

// fromServer copies the controller's record into the model. name/content are only overwritten
// when keepName/keepContent are false (see Read).
func (m *recordModel) fromServer(rec *client.Record, keepName, keepContent bool) {
	m.ID = types.StringValue(strconv.FormatInt(rec.ID, 10))
	if !keepName {
		m.Name = types.StringValue(rec.Name)
	}
	m.Type = types.StringValue(rec.Type)
	if !keepContent {
		m.Content = types.StringValue(rec.Content)
	}
	m.TTL = types.Int64Value(rec.TTL)
	m.Priority = int64Value(rec.Priority)
	m.Proxied = types.BoolValue(rec.Proxied)
	m.Pool = stringValue(rec.Pool)
	m.OriginPort = int64Value(rec.OriginPort)
	m.HealthCheck = types.BoolValue(rec.HealthCheck)
	m.HealthPort = int64Value(rec.HealthPort)
	m.Weight = int64Value(rec.Weight)
	m.HealthProtocol = stringValue(rec.HealthProtocol)
	m.HealthPath = stringValue(rec.HealthPath)
	m.Health = healthObject(rec.Health)
}

type privateSetter interface {
	SetKey(ctx context.Context, key string, value []byte) diag.Diagnostics
}

func setCanonical(ctx context.Context, p privateSetter, rec *client.Record) diag.Diagnostics {
	b, _ := json.Marshal(canonicalRecord{Name: rec.Name, Content: rec.Content})
	return p.SetKey(ctx, privCanonical, b)
}

func (r *recordResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if !requireClient(r.client, &resp.Diagnostics) {
		return
	}
	var plan recordModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	res, err := r.client.CreateRecord(ctx, plan.input())
	if err != nil {
		addAPIError(&resp.Diagnostics, "Could not create DNS record", err)
		return
	}
	dnsWarning(&resp.Diagnostics, res.DNSError)
	planned := plan.Health
	// The controller stored the normalised form of exactly what was sent, so the configured
	// name/content are kept (no "inconsistent result" for "WWW" vs "www"); the canonical form goes
	// to private state for drift detection.
	plan.fromServer(&res.Record, true, true)
	keepPlannedHealth(&plan, planned)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	resp.Diagnostics.Append(setCanonical(ctx, resp.Private, &res.Record)...)
}

// keepPlannedHealth keeps a known planned `health` (see healthPlanModifier): the applied state must
// match the plan, and the next refresh brings the controller's current probe result anyway.
func keepPlannedHealth(m *recordModel, planned types.Object) {
	if !planned.IsUnknown() {
		m.Health = planned
	}
}

// Read refreshes the record from GET /records (there is no single-record GET). A record that is gone
// is removed from state. name/content keep the configured spelling when the controller's value is
// unchanged since the last apply (private state) or is a known normalisation of it; any other
// difference is real drift and is written to state so the next plan corrects it.
func (r *recordResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if !requireClient(r.client, &resp.Diagnostics) {
		return
	}
	var state recordModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id, err := parseRecordID(state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("id"), "Invalid record id", err.Error())
		return
	}
	rec, err := r.client.GetRecord(ctx, id)
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		addAPIError(&resp.Diagnostics, "Could not read DNS record", err)
		return
	}
	var canon *canonicalRecord
	if raw, d := req.Private.GetKey(ctx, privCanonical); !d.HasError() && len(raw) > 0 {
		var c canonicalRecord
		if json.Unmarshal(raw, &c) == nil {
			canon = &c
		}
	}
	keepName := !state.Name.IsNull() && !state.Name.IsUnknown() &&
		((canon != nil && canon.Name == rec.Name) || nameEquivalent(state.Name.ValueString(), rec.Name))
	keepContent := !state.Content.IsNull() && !state.Content.IsUnknown() &&
		((canon != nil && canon.Content == rec.Content) || contentEquivalent(rec.Type, state.Content.ValueString(), rec.Content))
	state.fromServer(rec, keepName, keepContent)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
	resp.Diagnostics.Append(setCanonical(ctx, resp.Private, rec)...)
}

func (r *recordResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	if !requireClient(r.client, &resp.Diagnostics) {
		return
	}
	var plan, state recordModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id, err := parseRecordID(state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("id"), "Invalid record id", err.Error())
		return
	}
	res, err := r.client.UpdateRecord(ctx, id, plan.input())
	if err != nil {
		if client.IsNotFound(err) {
			resp.Diagnostics.AddError("DNS record no longer exists",
				fmt.Sprintf("Record %d was deleted outside Terraform. Run `terraform plan` again: the refresh removes it from state and plans to recreate it.", id))
			return
		}
		addAPIError(&resp.Diagnostics, "Could not update DNS record", err)
		return
	}
	dnsWarning(&resp.Diagnostics, res.DNSError)
	planned := plan.Health
	plan.fromServer(&res.Record, true, true)
	keepPlannedHealth(&plan, planned)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	resp.Diagnostics.Append(setCanonical(ctx, resp.Private, &res.Record)...)
}

func (r *recordResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if !requireClient(r.client, &resp.Diagnostics) {
		return
	}
	var state recordModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id, err := parseRecordID(state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("id"), "Invalid record id", err.Error())
		return
	}
	dnsErr, err := r.client.DeleteRecord(ctx, id)
	if client.IsNotFound(err) {
		return // already gone
	}
	if err != nil {
		addAPIError(&resp.Diagnostics, "Could not delete DNS record", err)
		return
	}
	dnsWarning(&resp.Diagnostics, dnsErr)
}

func (r *recordResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if _, err := parseRecordID(req.ID); err != nil {
		resp.Diagnostics.AddError("Invalid import id",
			"Import a pcdn_record by its numeric controller id (see GET /capi/v1/records), e.g. `terraform import pcdn_record.www 123`.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), strings.TrimSpace(req.ID))...)
}

func parseRecordID(s string) (int64, error) {
	id, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("%q is not a positive integer record id", s)
	}
	return id, nil
}

// normName mirrors validation.normalize_name for everything that does not need the site domain
// (case, surrounding space, trailing dot, ""/"@").
func normName(s string) string {
	n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	if n == "" {
		n = "@"
	}
	return n
}

func nameEquivalent(a, b string) bool { return a == b || normName(a) == normName(b) }

// normContent mirrors validation.validate_record's content normalisation per type.
func normContent(rtype, s string) string {
	c := strings.TrimSpace(s)
	switch rtype {
	case "A", "AAAA":
		if a, err := netip.ParseAddr(c); err == nil {
			return a.String()
		}
	case "CNAME", "NS", "ALIAS", "MX":
		return strings.TrimSuffix(strings.ToLower(c), ".")
	case "SRV":
		f := strings.Fields(c)
		if len(f) == 3 {
			w, err1 := strconv.Atoi(f[0])
			p, err2 := strconv.Atoi(f[1])
			if err1 == nil && err2 == nil {
				return fmt.Sprintf("%d %d %s", w, p, strings.TrimSuffix(strings.ToLower(f[2]), "."))
			}
		}
	case "TXT":
		return strings.Trim(c, `"`)
	}
	return c
}

func contentEquivalent(rtype, a, b string) bool {
	return a == b || normContent(rtype, a) == normContent(rtype, b)
}

// equivalentSpelling keeps the prior state value of `name` / `content` in the plan when the
// configured value only differs by a spelling the controller normalises away (case, trailing dot,
// IPv6 zero compression, TXT quotes...). Without it an imported record (state holds the canonical
// form) or a case-only config edit would plan a PATCH that changes nothing.
type equivalentSpelling struct{ content bool }

func (m equivalentSpelling) Description(context.Context) string {
	return "Ignores differences the controller normalises away (case, trailing dot, address spelling)."
}

func (m equivalentSpelling) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m equivalentSpelling) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if req.StateValue.IsNull() || req.StateValue.IsUnknown() || req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() ||
		req.PlanValue.IsUnknown() || req.PlanValue.Equal(req.StateValue) {
		return
	}
	planned, prior := req.PlanValue.ValueString(), req.StateValue.ValueString()
	if !m.content {
		if nameEquivalent(planned, prior) {
			resp.PlanValue = req.StateValue
		}
		return
	}
	var planType, stateType types.String
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("type"), &planType)...)
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("type"), &stateType)...)
	if resp.Diagnostics.HasError() || planType.IsUnknown() || !planType.Equal(stateType) {
		return
	}
	if contentEquivalent(planType.ValueString(), planned, prior) {
		resp.PlanValue = req.StateValue
	}
}

// priorityPlanModifier predicts the controller's priority when it is not configured: 10 for MX/SRV,
// null for every other type, so the plan never shows "(known after apply)" for it and a type change
// cannot leave a stale value behind.
type priorityPlanModifier struct{}

func (priorityPlanModifier) Description(context.Context) string {
	return "Defaults to 10 for MX/SRV records and null for other types when not configured."
}

func (m priorityPlanModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (priorityPlanModifier) PlanModifyInt64(ctx context.Context, req planmodifier.Int64Request, resp *planmodifier.Int64Response) {
	if !req.ConfigValue.IsNull() || req.Plan.Raw.IsNull() {
		return
	}
	var rtype types.String
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("type"), &rtype)...)
	if resp.Diagnostics.HasError() {
		return
	}
	switch {
	case rtype.IsUnknown():
		resp.PlanValue = types.Int64Unknown()
	case priorityTypes[rtype.ValueString()]:
		resp.PlanValue = types.Int64Value(10)
	default:
		resp.PlanValue = types.Int64Null()
	}
}

// healthPathPlanModifier predicts the controller's health_path when it is not configured: "/" for an
// http/https probe, null otherwise, so the plan matches the stored record.
type healthPathPlanModifier struct{}

func (healthPathPlanModifier) Description(context.Context) string {
	return "Defaults to / for http/https probes and null otherwise when not configured."
}

func (m healthPathPlanModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (healthPathPlanModifier) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if !req.ConfigValue.IsNull() || req.Plan.Raw.IsNull() {
		return
	}
	var proto types.String
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("health_protocol"), &proto)...)
	if resp.Diagnostics.HasError() {
		return
	}
	switch {
	case proto.IsUnknown():
		resp.PlanValue = types.StringUnknown()
	case proto.ValueString() == "http" || proto.ValueString() == "https":
		resp.PlanValue = types.StringValue("/")
	default:
		resp.PlanValue = types.StringNull()
	}
}

// healthPlanModifier keeps the computed `health` object from state unless health_check is toggled.
// Without it every update (and every plan where only a spelling the controller normalises differs)
// would show `health = (known after apply)`. The value is informational and refreshed on each read.
type healthPlanModifier struct{}

func (healthPlanModifier) Description(context.Context) string {
	return "Keeps the last read probe result unless health_check changes."
}

func (m healthPlanModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (healthPlanModifier) PlanModifyObject(ctx context.Context, req planmodifier.ObjectRequest, resp *planmodifier.ObjectResponse) {
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() || !req.PlanValue.IsUnknown() {
		return
	}
	var cfgHC, stateHC types.Bool
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("health_check"), &cfgHC)...)
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("health_check"), &stateHC)...)
	if resp.Diagnostics.HasError() || cfgHC.IsUnknown() || cfgHC.ValueBool() != stateHC.ValueBool() {
		return
	}
	resp.PlanValue = req.StateValue
}
