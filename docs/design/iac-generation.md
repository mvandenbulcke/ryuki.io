# IaC generation & integrity

Status: **design + slices 1 & 2 implemented**. Author: platform.

## Problem

When a request is dispatched to an agent today, the Infrastructure-as-Code it
runs is resolved by a hard-coded `match` over ~6 offering slugs
(`ryuki_runner::iac::resolve` / `resolve_ansible`), and two integrity/generation
gaps remain:

1. **No request→tfvars binding.** The dispatch sets `JobSpec.vars` to a raw copy
   of `request.metadata` (`contracts.rs`). The embedded Terraform modules declare
   variables like `vm_name`, `num_cpus`, `memory_mb` — but nothing maps the
   request's logical inputs (`name`, `cpu`, `memory_gb`, …) onto them, so a
   selected deployment's parameters do not reach the module unless the caller
   happens to use the exact Terraform variable names.
2. **`iac_digest` is a stub.** `JobSpec.iac_digest` is always `"0".repeat(64)`
   with no producer and no verification. The runner notes this directly
   (`lib.rs`: *"this does not yet verify the resolved bundle against
   `JobSpec.iac_digest`"*). An agent therefore runs whatever IaC it resolves
   locally, with no proof it matches what the control plane approved.

## Non-goals / constraints

- **The engine stays pure.** IaC generation must be deterministic and I/O-free
  where it lives in `ryuki-engine`; the digest helper and the binding live in
  `ryuki-runner` (which owns the embedded IaC content and is not validator-pure).
- **No raw-HCL templating.** Generating `.tf` text by string substitution is
  injection-prone (a value containing `"` or `}` breaks the HCL). We only ever
  generate the **JSON** tfvars (`ryuki.auto.tfvars.json`) — JSON values cannot
  break the surrounding HCL/YAML structure — and keep the module bodies as fixed,
  parameterized templates that read `var.*`.
- **Live apply is operator-owned.** Running a real `terraform apply` against
  infrastructure needs a deployed agent (`RYUKI_AGENT_ALLOW_LIVE=true`), real
  provider credentials and a durable state backend; that is not CI-verifiable and
  is out of scope here.

## Architecture

### Integrity: a runner-kind-agnostic bundle digest

`iac_digest` is the SHA-256 of the offering's **complete** embedded IaC bundle —
the union of its Terraform files and its Ansible files, in a canonical order.
Both sides compute it from the same `ryuki-runner` crate:

- **Producer (control plane).** At dispatch, `contracts.rs` sets
  `JobSpec.iac_digest = iac::offering_iac_digest(slug)`.
- **Verifier (agent/runner).** Before running, `run_offline_dry_run` recomputes
  `iac::offering_iac_digest(offering)` and, if the spec carries a real approved
  digest, **refuses** when they differ.

Because the digest spans both runners, the agent verifies it regardless of which
runner it actually invokes. In one workspace build the digests match by
construction; a control plane and an agent built from divergent commits (or a
tampered bundle) produce different digests → the agent refuses. This closes the
documented S5 stub.

The digest is deliberately over the **template** (the module files), not the
request-derived tfvars: the tfvars are bound to the request via `JobSpec`
(`request_id`, `vars`) and signed in the result envelope separately.

### Generation: a pure, declarative tfvars binding (Slice 2)

`iac::render_vars(offering_id, …)` (pure) will map a request's logical inputs
onto the Terraform variable names the module declares, e.g. for the
server-deployment offerings:

| Logical input        | tfvar       | Transform        |
| -------------------- | ----------- | ---------------- |
| name                 | `vm_name`   | as-is            |
| cpu                  | `num_cpus`  | as-is            |
| memory_gb            | `memory_mb` | × 1024           |
| site / environment / id | same / `request_id` | as-is |
| `metadata["network"]`, … | `network`, … | allow-listed passthrough |

Offerings **without** a declared binding fall back to the existing
`request.metadata` passthrough, so current behavior is preserved. The bindings
are data; adding an offering's binding does not require new control-flow.

**Data-model note (why this is Slice 2, not Slice 1).** The engine `Request`
type (`models.rs`) carries only `id`, `site`, `environment`, `metadata`, … — it
does **not** carry `cpu` / `memory_gb` / `name` as typed fields. Those live in
the `requests` table columns and the create-request body. So a correct
`cpu → num_cpus`, `memory_gb → memory_mb × 1024` binding needs those values
threaded from the DB row (or the create payload) into the renderer — a small but
deliberate data-flow change. Slice 1 ships the integrity bridge cleanly without
touching that path; Slice 2 adds the binding.

## Slice plan

- **Slice 1 (this change).** `bundle_digest` + `offering_iac_digest` + the
  producer/verifier wiring (the integrity bridge). The control plane sets the
  real `iac_digest` at dispatch; the runner recomputes it and **refuses** a
  mismatch. Fully unit-tested.
- **Slice 2 (done).** `render_vars` with the server-deployment binding +
  metadata-passthrough fallback (the generation step), threading `cpu`/
  `memory_gb`/`name` from the request row; wired into dispatch so a selected
  server deployment's inputs reach the module's `vm_name`/`num_cpus`/`memory_mb`
  variables as JSON tfvars.
- **Slice 3 (done — binding registry).** The per-offering wiring is now a single
  declarative `OFFERINGS` registry (`OfferingIac { id, terraform, ansible,
  binding }`); `resolve`, `resolve_ansible`, `render_vars` and
  `offering_iac_digest` all derive from it, so an offering's IaC and var-binding
  can never drift apart (a consistency test enforces every entry has a runner).
  Adding a wired offering is one registry entry plus the embedded template
  consts. The *templates themselves* stay embedded at compile time to preserve
  the offline/self-contained guarantee — making the templates fully
  catalog-YAML-driven would need a runtime content-addressed template store and
  is a separate future change.
- **Slice 4 (operator-owned).** A real apply against live infrastructure, proven
  end-to-end with provider credentials and a durable state backend.

## What this does NOT claim

Slice 1 binds the approved IaC by content digest and makes the agent refuse a
mismatch — it does not by itself change which offerings are deployable, generate
tfvars (Slice 2), or perform a live apply (operator-owned). Only offerings with a
wired module are deployable; the ~110-entry catalog is not.
