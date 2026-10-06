package provider

import (
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/namesissr/whmcs-cdn/terraform-provider-pcdn/internal/client"
)

// clientFrom extracts the API client handed over by Provider.Configure. It returns nil without a
// diagnostic when the provider is not configured yet (validation-only RPCs).
func clientFrom(data any, diags *diag.Diagnostics) *client.Client {
	if data == nil {
		return nil
	}
	c, ok := data.(*client.Client)
	if !ok {
		diags.AddError("Unexpected provider data",
			fmt.Sprintf("Expected *client.Client, got %T. This is a bug in the provider.", data))
		return nil
	}
	return c
}

// requireClient adds an error when the client is missing (an unconfigured provider).
func requireClient(c *client.Client, diags *diag.Diagnostics) bool {
	if c == nil {
		diags.AddError("Provider not configured",
			"The pcdn provider has not been configured: set endpoint and api_key (or PCDN_ENDPOINT / PCDN_API_KEY).")
		return false
	}
	return true
}

// addAPIError turns a client error into a readable diagnostic that keeps the controller's own
// `detail` messages (often Persian) and adds a short English hint for the status code.
func addAPIError(diags *diag.Diagnostics, summary string, err error) {
	var apiErr *client.APIError
	if errors.As(err, &apiErr) {
		var b strings.Builder
		fmt.Fprintf(&b, "%s %s returned HTTP %d.\n", apiErr.Method, apiErr.Path, apiErr.StatusCode)
		if len(apiErr.Messages) > 1 {
			b.WriteString("The controller reported:\n")
			for _, m := range apiErr.Messages {
				b.WriteString("  - " + m + "\n")
			}
		} else if apiErr.Detail != "" {
			b.WriteString("The controller reported: " + apiErr.Detail + "\n")
		}
		if h := apiErr.Hint(); h != "" {
			b.WriteString("\n" + h)
		}
		diags.AddError(summary, strings.TrimRight(b.String(), "\n"))
		return
	}
	diags.AddError(summary, err.Error())
}

// dnsWarning reports the controller's non-fatal `dns_error` (the change is saved but PowerDNS could
// not be updated right now; the controller re-syncs automatically).
func dnsWarning(diags *diag.Diagnostics, dnsErr *string) {
	if dnsErr != nil && *dnsErr != "" {
		diags.AddWarning("DNS sync is pending",
			"The record change was saved, but the controller could not push the zone to the DNS servers yet ("+*dnsErr+
				"). The controller retries automatically; no action is needed unless this persists.")
	}
}

func stringPtr(v types.String) *string {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	s := v.ValueString()
	return &s
}

func int64Ptr(v types.Int64) *int64 {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	n := v.ValueInt64()
	return &n
}

func stringValue(p *string) types.String {
	if p == nil {
		return types.StringNull()
	}
	return types.StringValue(*p)
}

func int64Value(p *int64) types.Int64 {
	if p == nil {
		return types.Int64Null()
	}
	return types.Int64Value(*p)
}
