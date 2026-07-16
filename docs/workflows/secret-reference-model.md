# Secret reference catalog

## Purpose

Operator runbook for the **Secret reference catalog** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

Secret references let platform code and manifests point to runtime-resolved material without committing any secret value. A reference records who owns the material, which component consumes it, the rotation policy, and the readiness state — never the value itself.

## Provider direction

Secret references use the platform's capability registry; there is no universal runtime provider and no error-triggered provider fallback. Each reference selects one admitted provider id and immutable configuration version. HashiCorp Vault, OpenBao, cloud secret managers, deployment materializers such as CSI or External Secrets Operator, and approved enterprise adapters can participate only for capabilities their exact adapter version has proven.

Resolution, dynamic issuance, lease control, key custody, certificate issuance,
version publication, and workload materialization are separate capabilities.
The catalog names them as `resolve-read`, `issue-dynamic-credential`,
`control-lease`, `custody-key`, `issue-certificate`, `publish-version`, and
`materialize-reload`. Read support never grants publication; materialization
never claims source lease, wrapping, or write semantics. A CSI/ESO/VSO
projection is a new custody boundary. Provider administration uses a versioned
adapter interface rather than a committed provider CLI or raw provider path.

The schema separates the governed `SecretReferenceRecord`, runtime `SecretRef`,
value-free `SecretLeaseMetadata`, non-serializable `SecretMaterial`, immutable
provider capability descriptor, separate provider lifecycle record, value-free
publication receipt, and materialization receipt. A deployment id and
trust-domain id, plus an applicable tenant id in multi-tenant mode, are required
runtime namespaces, but real identifiers and concrete provider paths remain
deployment data and never enter this seed file.

Adapters and workers fail closed when a reference is missing, pending approval,
blocked, quarantined, retired, unresolved, or beyond its policy freshness. The
reference-readiness, provider-lifecycle, and lease-lifecycle state machines are
distinct. `rotation-due` does not by itself revoke a valid lease: policy decides
whether it blocks new work, while explicit expiry/revocation controls existing
authority. Lease metadata is lifecycle-conditional: `requested` carries no
fabricated lease id, resolved version, or issue/expiry time, while issued and
active-family states must carry the exact version and timing fields; terminal
states additionally carry their terminal time.

## Contract

- Contract definition `secret-reference-catalog.yaml`
- Serves contract route `/api/catalog/secret-references`.
- Validator slice `secret-reference`
- Contract `secret-reference-catalog.yaml` is marked draft (version 2)

The API projection publishes the catalog's seven `referenceKinds` entries under
the canonical `secretReferenceKinds` response field. These are classifications
only: `adapter-credential`, `worker-credential`, `database-credential`,
`object-storage-credential`, `pki-material`, `recovery-material`, and
`signing-material`. The projection never includes secret material, provider
locators, credentials, deployment identifiers, or provider responses.

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

The static catalog moves through authoring, validation, review, publication,
deprecation, and retirement; it does not resolve material. A governed reference
record separately moves through its declared readiness states. Provider
configuration, leases, publication, and materialization each use their own
versioned lifecycle and evidence. No catalog publication or readiness label can
skip provider admission, authorization, or runtime lease checks.

## Required inputs and approvals

The catalog now declares the required governance/runtime schema fields,
capability interfaces, provider descriptor and lifecycle fields, publication
and materialization receipts, version selectors, and state models. Runtime
instances additionally require an exact provider/configuration version,
deployment/trust-domain and applicable tenant namespace, purpose, consumer/
workload, policy decision, and value-free conformance evidence.

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

## Requirements

No additional validator-pinned wording applies to this runbook beyond the contract facts above.

## Evidence

Evidence artifacts for this workflow are captured by the evidence pipeline and retained per the evidence export and retention contract.
