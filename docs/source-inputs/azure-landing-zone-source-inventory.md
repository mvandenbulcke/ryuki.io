# Azure landing-zone source inventory

This inventory records the **categories of Azure landing-zone source material** that the
`/api/workflows/azure-landing-zone/validation-contract` validation reasons about. It is
deliberately filename-free: each row exposes a stable *source reference* token rather than a raw
document filename, version date, or file path. The validation is static-seed and dry-run only — no
Azure, ARM, Bicep, Terraform, or Microsoft Graph calls are made, and no landing-zone resources are
created or changed. Source references map to redacted, summarized design facts; the underlying
documents themselves are never committed to this repository.

Each reference is a logical handle used by the contract's `requiredInputs`,
`validationSurfaces`, and `planSections`. When a landing-zone validation request is summarized, the
operator confirms that the corresponding source category has been reviewed; the reference token is
what appears in the evidence summary, never a filename.

| Category | Source reference | Status |
| --- | --- | --- |
| Policy baseline guardrails | source-ref-alz-policy-baseline | reviewed |
| Management group taxonomy | source-ref-alz-management-taxonomy | reviewed |
| Policy detail and assignments | source-ref-alz-policy-detail | reviewed |
| Resource naming standards | source-ref-alz-resource-naming | reviewed |
| Tagging standards | source-ref-alz-tagging | reviewed |
| Connectivity and network topology | source-ref-alz-connectivity | reviewed |
| Identity and access model | source-ref-alz-identity | reviewed |
| Security baseline and controls | source-ref-alz-security | reviewed |
| Platform DevOps and pipelines | source-ref-alz-devops | reviewed |
| Architecture decision records, final set | source-ref-alz-adr-final-set | reviewed |
| Architecture decision records, update set | source-ref-alz-adr-update-set | reviewed |
| Resource organization model | source-ref-alz-resource-organization | reviewed |
| Review comments and findings | source-ref-alz-comments-workbook | reviewed |
| Architecture proposal, narrative summary | source-ref-alz-architecture-proposal-summary | reviewed |
| Architecture proposal, topology diagram | source-ref-alz-architecture-proposal-diagram | reviewed |
| Naming and tagging template | source-ref-alz-naming-tagging-template | reviewed |

## Prohibitions

- No raw source filenames, version-dated filenames, or office-document extensions are recorded here
  — only stable source-reference tokens.
- No live Azure, Resource Manager, Bicep, Terraform, or Microsoft Graph calls.
- No landing-zone resource creation, mutation, or deletion.
- Source material is referenced by token only; redaction and summarization happen before any
  reference is surfaced in evidence.
