package latte

import "math"

// Typed entitlements: the answers a seller signed into this licence about
// what their customer bought.
//
// An entitlement answers one of exactly two questions about the software you
// shipped: *may this customer do X* (a boolean, read with Can) and *how many
// Y do they get* (an integer, read with Limit). The values are set on a
// policy and overridden per licence in the LicenseLatte dashboard, resolved
// server-side, and signed into the activation token as the `ent` claim — so
// Can and Limit answer fully offline, with no network call and no second
// source of truth.
//
// They are deliberately not the same thing as License.Metadata (the `pmd`
// claim): metadata is arbitrary display data, filtered per field, and
// untyped. Entitlements are booleans and integers, unfiltered, and exist
// precisely to be read on the customer's machine. The two never merge, and a
// key may appear in both meaning different things.
//
// # Absence denies, and that has a rollout consequence
//
// A key that is not in the claim answers false / missing. There is no
// "unknown means allow": the token is a bearer artefact sitting in a file on
// the machine of the person it constrains, so if absence granted, stripping
// the claim would unlock everything, and replaying a token minted before the
// seller adopted entitlements would do the same with no tampering at all.
//
// The cost of that default lands on you, not on the server. Shipping
//
//	if !lic.Can("export_pdf") { hide() }
//
// before your installed base has renewed disables PDF export for every
// customer whose cached token predates the claim. Use HasEntitlements to
// bridge one release:
//
//	if lic.HasEntitlements() {
//	    enabled = lic.Can("export_pdf")
//	} else {
//	    enabled = legacyBehaviour()
//	}
//
// Drop the fallback once the base has renewed — one grace window, which the
// dashboard shows per policy.
//
// # Tamper resistance
//
// Entitlements are a distribution mechanism for a signed answer, not a
// tamper-proofing one. A determined user can patch this check out of your
// binary exactly as they could any other. If real revenue depends on a
// feature, re-validate it server-side.

// Unlimited is the sentinel an integer entitlement carries to mean "no
// ceiling". Limit returns it as-is; compare against this constant rather
// than testing for a negative number.
//
//	if n, ok := lic.Limit("max_projects"); ok && n != latte.Unlimited && used >= n {
//	    return errTooManyProjects
//	}
const Unlimited int64 = -1

// decodeEntitlements narrows a raw `ent` claim to the two types the format
// admits — bool and int64 — dropping everything else.
//
// Dropping rather than failing is the contract, not laxity: rejecting a token
// because a seller managed to get a string into one value would take a
// working product offline for a data-entry mistake, on a machine that cannot
// be reached to fix it. Refusing bad values is the server's job at write
// time, where there is a human and an error message.
//
// encoding/json hands every number back as a float64, so an integer arrives
// here as one and is recognised by being whole rather than by its Go type. A
// fractional number is dropped for the same reason a string is: the format
// has no float, and a value that survived here but nowhere else would be
// worse than one that survived nowhere.
//
// A nil return means the claim was absent; a non-nil empty map means it was
// present and empty. HasEntitlements reads exactly that distinction.
func decodeEntitlements(claims map[string]any) map[string]any {
	raw, ok := claims["ent"].(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]any, len(raw))
	for key, v := range raw {
		switch value := v.(type) {
		case bool:
			out[key] = value
		case float64:
			if !math.IsInf(value, 0) && !math.IsNaN(value) && value == math.Trunc(value) {
				out[key] = int64(value)
			}
		case int64:
			out[key] = value
		}
	}
	return out
}
