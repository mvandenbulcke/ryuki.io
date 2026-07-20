# Execution trust profile (protocol v7)

Protocol v7 makes a successful live plan an execution-authority snapshot, not
only a plan digest. The planning agent signs the complete non-secret
`ExecutionTrustProfile`; the control plane validates its closed schema and
reviewed-live allowlist, then copies its canonical digest and the exact planning
agent enrollment into the CP-signed live grant.

The profile binds:

- the platform, reviewed offering, embedded provider-lock source/version,
  exact IaC digest, and a stable non-secret provider authority reference plus
  immutable version for the vSphere destination/account credential set;
- the backend **type**, a stable non-secret, kind-scoped backend credential-
  authority reference plus immutable revision, control-plane state key, and
  privacy-safe SHA-256 commitment to the isolation-validated backend semantics;
- the approved executable canonical path, probed version, optional configured
  content digest, and executable-provenance policy;
- explicit provider and backend credential-authority modes (ambient CLI,
  metadata, in-cluster, default-chain, and file-discovery modes are not in the
  allowlist); and
- both the runner descendant-containment policy and Terraform state-key
  isolation policy.

Raw backend HCL/values, credential values, provider-returned data, hostnames,
account names, tenant identifiers, and secrets never enter the profile. The
backend commitment replaces secret scalars with typed markers and sanitizes URL
credentials. The provider authority id is an opaque provisioning-record
reference; its version must rotate whenever the selected server, account, or
credential set changes. The backend authority id follows
`backend-credential-authority/<backend-kind>/<opaque-id>`; its revision must
rotate whenever the backend principal, destination, or credential set changes.

The current agent environment seam does not cryptographically or atomically
co-resolve that reference with the free-form provider credential values.
Profile derivation packages both into one in-memory resolution result, but it
performs separate environment reads and runner execution resolves credentials
again. It reads `RYUKI_LIVE_PROVIDER_AUTHORITY_ID` and
`RYUKI_LIVE_PROVIDER_AUTHORITY_VERSION` separately from the declared
`RYUKI_LIVE_CRED_*` variables and validates only their public shape and
presence. Exact correspondence therefore remains a trusted-access deployment
responsibility. Provider-connected activation requires a typed secret-manager
connector that returns one versioned credential-and-authority bundle and
deployment readback that proves the binding.

The backend reference currently has the same limitation. The agent reads
`RYUKI_LIVE_BACKEND_CREDENTIAL_AUTHORITY_ID` and
`RYUKI_LIVE_BACKEND_CREDENTIAL_AUTHORITY_REVISION` as separate non-secret
environment values. It validates their public shape and backend-kind scope but
does not atomically co-resolve them with backend secret material. A production
adapter must return one typed, versioned backend credential-and-authority
bundle; this document does not treat the environment compatibility seam as
proof of that binding.

Approval carries the exact reviewed plan job UUID, attempt UUID, and signed
`raw_plan_digest`. The redacted evidence pack has an independent
`evidence_digest`; it verifies the safe review projection but is never
substituted as mutation authority.
The control plane locks that selected row and re-verifies its stored attempt,
lease generation, result UUID, signed-envelope identity, immutable enrollment,
agent id, public-key fingerprint, profile, spec, and raw-plan digest before minting. The
grant signs that exact plan job and attempt as well as the canonical profile
digest, so a later same-digest row cannot substitute for the one reviewed. The
LiveApply/LiveDestroy job is preassigned to that enrollment. Leasing, the agent
pre-contact gate, the agent mutation-boundary gate, and control-plane result
ingestion all compare the same authority. A changed plan row or attempt,
enrollment, key, backend authority, provider destination/account authority
version, executable identity, provider lock, IaC, credential mode, containment
policy, or state key requires a new plan and approval.

Only the whole-request human approval flow is enabled. Human per-step approval
is fail-closed in this release: the portal omits the action and the step route
returns `409 Conflict` after authorization checks without minting a job. Exact-
plan step-grant comparison remains internal protocol groundwork, while system-
owned step-scoped `LiveDestroy` authority is reserved for compensation.

The signed domains are `ryuki-v5/signed-envelope` and
`ryuki-v7/verified-live-context`; protocol v1 through v6 grants/results are
rejected rather than interpreted without the exact request-version authority.

Production external execution currently remains fail-closed: the runner has no
production constructor for the required sealed per-command descendant-
containment capability. Therefore no production LivePlan can mint an execution
profile until a real attach-before-exec, kill-all, wait-empty platform adapter
is implemented. Pure/stub tests may exercise the protocol and comparison logic.
