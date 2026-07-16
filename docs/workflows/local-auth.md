# Local auth

## Purpose

Operator runbook for the **Local auth** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `local-auth-contract.yaml`
- Serves contract route `/api/auth/local/roles`.
- Validator slice `local-auth`
- Contract `local-auth-contract.yaml` has catalog-publication status `active`.
  This is not an active production authenticator lifecycle state;
  `configuredForProduction` and live-authentication flags remain `false`.

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

This static catalog has no provider-execution lifecycle. Its publication moves
through authoring, validation, review, publication, deprecation, and retirement.
A future authenticator configuration separately follows the boundary's
`configured -> validated -> active -> draining -> removed` lifecycle, with
quarantine as a fail-closed exit. Publishing this catalog cannot activate that
provider state or authorize a login.

## Required inputs and approvals

The static contract declares profile and production-eligibility metadata rather
than request inputs. Any future change that enables a real authenticator must
use the governed provider-registry schema, exact configuration version,
profile/applicability decision, step-up where required, reviewer, activation
receipt, and rollback/retirement evidence. A time-bounded migration overlay is
not a fourth deployment profile and cannot make this catalog an authority
source.

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- Also serves `/api/auth/local/me`.
- Also serves `/api/auth/local/decision`.
- It is not production authentication.
- `configuredForProduction` is always `false` for the current local-mock slice.
- Production authentication uses the versioned authenticator registry. Entra ID
  is one generic OIDC configuration; conforming non-Entra OIDC providers and
  approved OIDC brokers use the same boundary.
- Target local production authentication is purpose-bound WebAuthn/passkeys;
  ordinary and dormant break-glass credentials are separate profiles, and
  password-only fallback is prohibited.

## Evidence

Evidence artifacts for this workflow are captured by the evidence pipeline and retained per the evidence export and retention contract.
