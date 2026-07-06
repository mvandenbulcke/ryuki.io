//! Hand-maintained OpenAPI 3.1 document for three route groups:
//!
//!   1. AGENT-PROTOCOL endpoints — the machine-readable surface external
//!      agents integrate against (`sources/ryuki-api/src/agents.rs::agent_routes()`),
//!      cross-checked against [`crate::agents::AGENT_ROUTE_PATHS`].
//!   2. PUBLIC endpoints — the no-auth surface (health/readiness probes +
//!      pre-login bootstrap reads), cross-checked against
//!      [`crate::PUBLIC_ROUTE_PATHS`].
//!   3. OPS-READ endpoints — a bounded, read-only operational surface (events/
//!      alerts feed, scheduler introspection) gated behind a session +
//!      permission tier, cross-checked against
//!      [`crate::contracts::OPS_READ_ROUTE_PATHS`].
//!
//! This is a PURE data builder — no IO, no DB, no axum state — so it is
//! trivially unit-testable and cannot drift from reality silently: the test
//! module below asserts `paths` equals the exact union of all three
//! source-of-truth constants.
//!
//! Deliberately hand-transcribed (NOT generated via utoipa/schemars): no new
//! dependency, no annotations on existing handlers/types. Keep this in sync
//! by hand whenever `agents.rs`, `main.rs`, `contracts.rs`, or
//! `ryuki-protocol/src/types.rs` change shape.

use serde_json::{json, Value};

/// Build the full OpenAPI 3.1 document describing the agent-protocol wire
/// surface. Pure function — safe to call from tests and from the handler.
pub fn openapi_document() -> Value {
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Ryuki Agent Protocol API",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "Machine-readable contract for three route groups. (1) The \
                CP↔agent wire protocol (registration, job polling/lease, ack, result \
                submission, heartbeat): all endpoints except `cp-public-key` require an \
                agent bearer token (`Authorization: Bearer rya_...`), and every request \
                MAY carry the `x-ryuki-protocol-version` header (absent => legacy version \
                1). (2) PUBLIC endpoints (no auth) — infra probes plus the pre-login portal \
                bootstrap reads. (3) A bounded READ-ONLY operational surface (events/alerts \
                feed, scheduler introspection) that requires an operator session and a \
                permission tier, documented for operational tooling, not external agents."
        },
        "servers": [
            { "url": "/", "description": "Same-origin control plane" }
        ],
        "components": {
            "securitySchemes": {
                "agentBearer": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "rya_<hex>",
                    "description": "Agent-issued bearer token returned once by \
                        POST /api/agents/register. Sent as `Authorization: Bearer rya_...`."
                },
                "apiSessionHeader": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-Ryuki-Session-Id",
                    "description": "Operator session identifier for the ops-read surface. \
                        `Authorization: Bearer <session-uuid>` and the `ryuki_session` cookie \
                        are alternate carriers of the same session; any one of the three is \
                        sufficient."
                }
            },
            "parameters": {
                "ProtocolVersionHeader": {
                    "name": "x-ryuki-protocol-version",
                    "in": "header",
                    "required": false,
                    "description": "Sender's CP↔agent wire-schema version (decimal u32). \
                        Absent => resolved to the legacy value (1). Rejected (400) if it \
                        appears more than once, is not a positive integer, or is outside \
                        the control plane's supported set.",
                    "schema": { "type": "integer", "format": "int64", "minimum": 1 }
                }
            },
            "schemas": {
                "JobMode": {
                    "type": "string",
                    "description": "Execution mode. The agent MUST NOT elevate the mode on its own.",
                    "enum": ["offline_dry_run", "live_plan", "live_apply"]
                },
                "JobStatus": {
                    "type": "string",
                    "description": "CP-side lifecycle status of a job (agent-dispatchable subset).",
                    "enum": [
                        "pending",
                        "leased",
                        "running",
                        "succeeded",
                        "failed",
                        "expired",
                        "reconcile_required",
                        "live_refused"
                    ]
                },
                "JobResultStatus": {
                    "type": "string",
                    "description": "Terminal execution outcomes an agent may report. Narrower \
                        than JobStatus; the CP rejects any value outside this set (in \
                        particular `verified` is CP-internal and is rejected if submitted \
                        by an agent).",
                    "enum": [
                        "check_ok",
                        "planned",
                        "applied",
                        "verified",
                        "failed",
                        "live_refused"
                    ]
                },
                "ToolCapability": {
                    "type": "object",
                    "description": "Version info for a single tool (Terraform or Ansible).",
                    "required": ["version"],
                    "properties": {
                        "version": { "type": "string", "example": "1.9.5" },
                        "provider_versions": {
                            "type": "object",
                            "description": "Terraform provider name → version. Empty/absent for Ansible.",
                            "additionalProperties": { "type": "string" }
                        }
                    }
                },
                "Capabilities": {
                    "type": "object",
                    "description": "Full capability set self-declared by an agent at registration. \
                        NOT trusted for authz decisions — reconciled against a trusted \
                        inventory by an admin.",
                    "properties": {
                        "terraform": { "$ref": "#/components/schemas/ToolCapability" },
                        "ansible": { "$ref": "#/components/schemas/ToolCapability" }
                    }
                },
                "JobSpec": {
                    "type": "object",
                    "description": "References IaC artefacts by stable identifier + digest, never \
                        by inline content. Credentials are never included.",
                    "required": ["request_id", "offering_id", "iac_ref", "iac_digest", "mode"],
                    "properties": {
                        "request_id": { "type": "string", "format": "uuid" },
                        "offering_id": { "type": "string", "format": "uuid" },
                        "iac_ref": { "type": "string" },
                        "iac_digest": { "type": "string", "description": "SHA-256 hex digest of the IaC template." },
                        "vars": {
                            "type": "object",
                            "description": "Non-secret variable overrides.",
                            "additionalProperties": { "type": "string" }
                        },
                        "mode": { "$ref": "#/components/schemas/JobMode" }
                    }
                },
                "JobLease": {
                    "type": "object",
                    "description": "Fencing lease issued when an agent polls and wins a job row.",
                    "required": ["attempt_id", "lease_generation", "fencing_token", "deadline", "cp_nonce"],
                    "properties": {
                        "attempt_id": { "type": "string", "format": "uuid" },
                        "lease_generation": { "type": "integer", "format": "int64", "minimum": 0 },
                        "fencing_token": { "type": "string" },
                        "deadline": { "type": "string", "format": "date-time" },
                        "cp_nonce": { "type": "string", "description": "Per-lease one-time nonce; copied verbatim into SignedEnvelope.cp_nonce." }
                    }
                },
                "VerifiedLiveContext": {
                    "type": "object",
                    "description": "CP-signed approval grant for a LiveApply job.",
                    "required": ["request_id", "approved_plan_digest", "approver", "expiry", "signature"],
                    "properties": {
                        "request_id": { "type": "string", "format": "uuid" },
                        "approved_plan_digest": { "type": "string" },
                        "approver": { "type": "string" },
                        "expiry": { "type": "string", "format": "date-time" },
                        "step_job_id": {
                            "type": "string",
                            "format": "uuid",
                            "description": "Present only for a step-scoped grant (#42 slice A): binds this grant to ONE specific dispatched step job id, preventing replay across steps or across a re-dispatch of the same step. Absent (not null) for a legacy/whole-request grant — the pre-existing single-job trust model, unchanged."
                        },
                        "signature": { "type": "string", "description": "Base64-encoded Ed25519 signature." }
                    }
                },
                "Job": {
                    "type": "object",
                    "description": "A dispatchable unit of work, as returned by GET /api/agents/{agent_id}/jobs.",
                    "required": ["id", "platform", "spec", "status"],
                    "properties": {
                        "id": { "type": "string", "format": "uuid" },
                        "platform": { "type": "string" },
                        "spec": { "$ref": "#/components/schemas/JobSpec" },
                        "status": { "$ref": "#/components/schemas/JobStatus" },
                        "lease": {
                            "oneOf": [
                                { "$ref": "#/components/schemas/JobLease" },
                                { "type": "null" }
                            ],
                            "description": "Present when the job has been leased."
                        },
                        "live_context": {
                            "oneOf": [
                                { "$ref": "#/components/schemas/VerifiedLiveContext" },
                                { "type": "null" }
                            ],
                            "description": "CP-signed approval grant; required for live_apply, absent otherwise."
                        }
                    }
                },
                "SignedEnvelope": {
                    "type": "object",
                    "description": "Binds the full execution context for a posted result; \
                        tamper-evident via an Ed25519 signature over the fixed-order signable fields.",
                    "required": [
                        "agent_id", "platform", "job_id", "attempt_id", "lease_generation",
                        "request_id", "result_id", "mode", "status", "job_spec_digest",
                        "evidence_digest", "redaction_policy_version", "timestamp", "key_id",
                        "cp_nonce", "signature"
                    ],
                    "properties": {
                        "agent_id": { "type": "string" },
                        "platform": { "type": "string" },
                        "job_id": { "type": "string", "format": "uuid" },
                        "attempt_id": { "type": "string", "format": "uuid" },
                        "lease_generation": { "type": "integer", "format": "int64", "minimum": 0 },
                        "request_id": { "type": "string", "format": "uuid" },
                        "result_id": { "type": "string", "format": "uuid", "description": "Must equal JobResult.result_id." },
                        "mode": { "$ref": "#/components/schemas/JobMode" },
                        "status": { "$ref": "#/components/schemas/JobResultStatus" },
                        "job_spec_digest": { "type": "string", "description": "SHA-256 hex digest of the canonical JobSpec bytes." },
                        "approved_plan_digest": {
                            "oneOf": [{ "type": "string" }, { "type": "null" }],
                            "description": "SHA-256 hex digest of the approved plan; null for non-live_apply modes."
                        },
                        "evidence_digest": { "type": "string", "description": "SHA-256 hex digest of the (post-redaction) evidence pack." },
                        "redaction_policy_version": { "type": "string", "example": "ryuki-redaction-v1" },
                        "timestamp": { "type": "string", "format": "date-time" },
                        "key_id": { "type": "string" },
                        "cp_nonce": { "type": "string", "description": "Copied verbatim from JobLease.cp_nonce." },
                        "signature": { "type": "string", "description": "Base64-encoded Ed25519 signature." }
                    }
                },
                "JobResult": {
                    "type": "object",
                    "description": "Posted by the agent as part of ResultBody. The triple \
                        (job_id, attempt_id, result_id) is the idempotency key.",
                    "required": ["job_id", "attempt_id", "result_id", "status", "evidence_digest", "signed_envelope"],
                    "properties": {
                        "job_id": { "type": "string", "format": "uuid" },
                        "attempt_id": { "type": "string", "format": "uuid" },
                        "result_id": { "type": "string", "format": "uuid" },
                        "status": { "$ref": "#/components/schemas/JobResultStatus" },
                        "evidence_digest": { "type": "string", "description": "SHA-256 hex digest of the (redacted) evidence pack." },
                        "signed_envelope": { "$ref": "#/components/schemas/SignedEnvelope" }
                    }
                },
                "RegisterBody": {
                    "type": "object",
                    "required": ["agent_id", "platform", "capabilities", "public_key"],
                    "properties": {
                        "agent_id": { "type": "string", "description": "Stable agent identifier, e.g. \"defra-vcenter-01\"." },
                        "platform": { "type": "string", "description": "Platform / site this agent serves, e.g. \"defra\"." },
                        "capabilities": { "$ref": "#/components/schemas/Capabilities" },
                        "public_key": { "type": "string", "description": "Base64-encoded Ed25519 verifying (public) key." }
                    }
                },
                "RegisterResponse": {
                    "type": "object",
                    "description": "Returned once on successful registration. The token is never stored or returned again.",
                    "required": ["agent_id", "token"],
                    "properties": {
                        "agent_id": { "type": "string" },
                        "token": { "type": "string", "example": "rya_<hex>" }
                    }
                },
                "AckBody": {
                    "type": "object",
                    "required": ["attempt_id", "fencing_token"],
                    "properties": {
                        "attempt_id": { "type": "string", "format": "uuid" },
                        "fencing_token": { "type": "string" }
                    }
                },
                "AckResponse": {
                    "type": "object",
                    "required": ["job_id", "status"],
                    "properties": {
                        "job_id": { "type": "string", "format": "uuid" },
                        "status": { "type": "string", "example": "Running" }
                    }
                },
                "ResultBody": {
                    "type": "object",
                    "description": "The outer JobResult fields are untrusted; only the embedded \
                        SignedEnvelope is authoritative — the CP equality-checks every outer \
                        field against it before persisting anything.",
                    "required": ["job_result"],
                    "properties": {
                        "job_result": { "$ref": "#/components/schemas/JobResult" },
                        "evidence": {
                            "type": "array",
                            "items": { "type": "integer", "minimum": 0, "maximum": 255 },
                            "default": [],
                            "description": "Raw evidence bytes, serialized as a JSON array of u8 (the \
                                wire shape of the server's `Vec<u8>` field — NOT base64). Its SHA-256 is \
                                evidence_digest. May be empty for modes producing no evidence, but the \
                                digest must still match."
                        },
                        "evidence_json": {
                            "description": "Optional structured evidence parsed from the evidence bytes \
                                (ANY JSON value — the field is a serde_json::Value; an untyped schema, per \
                                OpenAPI 3.1, permits any type including null). Never trusted for authz."
                        }
                    }
                },
                "HeartbeatBody": {
                    "type": "object",
                    "properties": {
                        "running_job_id": {
                            "oneOf": [{ "type": "string", "format": "uuid" }, { "type": "null" }],
                            "description": "Currently running job id, if any."
                        }
                    }
                },
                "HeartbeatResponse": {
                    "type": "object",
                    "required": ["agent_id", "last_seen_at"],
                    "properties": {
                        "agent_id": { "type": "string" },
                        "last_seen_at": { "type": "string", "format": "date-time" }
                    }
                },
                "CpPublicKeyResponse": {
                    "type": "object",
                    "required": ["public_key", "protocol_version"],
                    "properties": {
                        "public_key": { "type": "string", "description": "Base64-encoded Ed25519 CP public key." },
                        "protocol_version": { "type": "integer", "format": "int64", "minimum": 1 }
                    }
                },
                "ErrorBody": {
                    "type": "object",
                    "required": ["error"],
                    "properties": {
                        "error": { "type": "string" }
                    }
                },
                "ProblemDetails": {
                    "type": "object",
                    "description": "RFC 9457-shaped error body returned by the public infra \
                        probes (`/health`, `/ready`) on failure.",
                    "required": ["error", "message"],
                    "properties": {
                        "error": { "type": "string", "example": "DATABASE_UNAVAILABLE" },
                        "message": { "type": "string" },
                        "detail": {
                            "oneOf": [{ "type": "string" }, { "type": "null" }]
                        }
                    }
                },
                "HealthResponse": {
                    "type": "object",
                    "description": "Liveness probe result. `status` is `degraded` (still 200) \
                        when the database is disconnected or hard config validation fails.",
                    "required": ["status", "database", "config", "auth_mode", "rate_limit_enabled"],
                    "properties": {
                        "status": { "type": "string", "enum": ["healthy", "degraded"] },
                        "database": {
                            "type": "object",
                            "required": ["connected", "provider"],
                            "properties": {
                                "connected": { "type": "boolean" },
                                "provider": { "type": "string" }
                            }
                        },
                        "config": {
                            "type": "object",
                            "required": ["valid", "errors", "warnings"],
                            "properties": {
                                "valid": { "type": "boolean" },
                                "errors": { "type": "array", "items": { "type": "string" } },
                                "warnings": { "type": "array", "items": { "type": "string" } }
                            }
                        },
                        "auth_mode": { "type": "string" },
                        "rate_limit_enabled": { "type": "boolean" }
                    }
                },
                "ReadyResponse": {
                    "type": "object",
                    "description": "Readiness probe result. Returned only on success (200); \
                        failure returns a 503 ProblemDetails instead (DRAINING, \
                        READINESS_CHECK_FAILED, CONFIG_INVALID, DATABASE_UNAVAILABLE, and \
                        related database-unusable/migration codes).",
                    "required": ["status"],
                    "properties": {
                        "status": { "type": "string", "example": "ready" }
                    },
                    "additionalProperties": true
                },
                "AuthStatusResponse": {
                    "type": "object",
                    "required": ["tenant_configured", "client_configured", "enabled", "instance"],
                    "properties": {
                        "tenant_configured": { "type": "boolean" },
                        "client_configured": { "type": "boolean" },
                        "enabled": { "type": "boolean" },
                        "instance": { "type": "string" }
                    }
                },
                "AuthSession": {
                    "type": "object",
                    "description": "The resolved session for the caller. `site_scope` / \
                        `environment_scope` are omitted entirely when empty (unscoped \
                        principal), not sent as empty arrays.",
                    "required": ["user_id", "display_name", "roles", "token_valid", "provider_mode"],
                    "properties": {
                        "user_id": { "type": "string" },
                        "display_name": { "type": "string" },
                        "roles": { "type": "array", "items": { "type": "string" } },
                        "token_valid": { "type": "boolean" },
                        "provider_mode": { "type": "string" },
                        "site_scope": { "type": "array", "items": { "type": "string" } },
                        "environment_scope": { "type": "array", "items": { "type": "string" } }
                    }
                },
                "RbacRole": {
                    "type": "object",
                    "required": ["name", "description", "permissions"],
                    "properties": {
                        "name": { "type": "string" },
                        "description": { "type": "string" },
                        "permissions": { "type": "array", "items": { "type": "string" } }
                    }
                },
                "PlatformSummaryResponse": {
                    "type": "object",
                    "required": [
                        "productName", "lifecycleStages", "components", "guardrails",
                        "browserIsolation", "localAuthorization"
                    ],
                    "properties": {
                        "productName": { "type": "string" },
                        "lifecycleStages": {
                            "type": "array",
                            "description": "Ordered lifecycle stage descriptors.",
                            "items": { "type": "object" }
                        },
                        "components": {
                            "type": "array",
                            "description": "Platform component descriptors.",
                            "items": { "type": "object" }
                        },
                        "guardrails": {
                            "type": "array",
                            "description": "Guardrail descriptors.",
                            "items": { "type": "object" }
                        },
                        "browserIsolation": { "type": "boolean" },
                        "localAuthorization": {
                            "type": "object",
                            "required": [
                                "authenticationMode", "configuredForProduction",
                                "entraGroupsConfigured", "roleHeader", "requiredProductionProvider"
                            ],
                            "properties": {
                                "authenticationMode": { "type": "string" },
                                "configuredForProduction": { "type": "boolean" },
                                "entraGroupsConfigured": { "type": "boolean" },
                                "roleHeader": { "type": "string" },
                                "requiredProductionProvider": { "type": "string" }
                            }
                        }
                    }
                },
                "ScheduleView": {
                    "type": "object",
                    "required": ["id", "name", "job_kind", "interval_secs", "enabled", "next_run_at"],
                    "properties": {
                        "id": { "type": "string" },
                        "name": { "type": "string" },
                        "job_kind": { "type": "string" },
                        "interval_secs": { "type": "integer", "format": "int64" },
                        "enabled": { "type": "boolean" },
                        "next_run_at": { "type": "string", "format": "date-time" },
                        "last_run_at": {
                            "oneOf": [{ "type": "string", "format": "date-time" }, { "type": "null" }]
                        }
                    }
                },
                "SchedulerSchedulesResponse": {
                    "type": "object",
                    "required": ["schedules", "durable"],
                    "properties": {
                        "schedules": { "type": "array", "items": { "$ref": "#/components/schemas/ScheduleView" } },
                        "durable": { "type": "boolean", "description": "False when no database is configured (empty list)." }
                    }
                },
                "ExecutionView": {
                    "type": "object",
                    "required": ["id", "schedule_id", "job_kind", "status", "started_at"],
                    "properties": {
                        "id": { "type": "string" },
                        "schedule_id": { "type": "string" },
                        "job_kind": { "type": "string" },
                        "status": { "type": "string" },
                        "detail": {
                            "oneOf": [{ "type": "string" }, { "type": "null" }]
                        },
                        "started_at": { "type": "string", "format": "date-time" },
                        "finished_at": {
                            "oneOf": [{ "type": "string", "format": "date-time" }, { "type": "null" }]
                        }
                    }
                },
                "SchedulerExecutionsResponse": {
                    "type": "object",
                    "required": ["executions", "durable"],
                    "properties": {
                        "executions": { "type": "array", "items": { "$ref": "#/components/schemas/ExecutionView" } },
                        "durable": { "type": "boolean", "description": "False when no database is configured (empty list)." }
                    }
                },
                "EventItem": {
                    "type": "object",
                    "required": ["id", "event_type", "aggregate_type", "aggregate_id", "actor", "payload", "occurred_at"],
                    "properties": {
                        "id": { "type": "integer", "format": "int64" },
                        "event_type": { "type": "string" },
                        "aggregate_type": { "type": "string" },
                        "aggregate_id": { "type": "string" },
                        "site": {
                            "oneOf": [{ "type": "string" }, { "type": "null" }]
                        },
                        "environment": {
                            "oneOf": [{ "type": "string" }, { "type": "null" }]
                        },
                        "actor": { "type": "string" },
                        "payload": {
                            "description": "The event's structured payload — an arbitrary JSON value \
                                (the column is a serde_json::Value); conventionally a JSON object but \
                                NOT type-constrained, so an untyped schema (per OpenAPI 3.1, any type)."
                        },
                        "occurred_at": { "type": "string", "format": "date-time" }
                    }
                },
                "EventsResponse": {
                    "type": "object",
                    "required": ["events", "durable"],
                    "properties": {
                        "events": { "type": "array", "items": { "$ref": "#/components/schemas/EventItem" } },
                        "durable": { "type": "boolean", "description": "False when no database is configured (empty list)." }
                    }
                },
                "AlertItem": {
                    "type": "object",
                    "required": [
                        "id", "event_type", "aggregate_type", "aggregate_id", "actor",
                        "severity", "payload", "occurred_at", "acknowledged"
                    ],
                    "properties": {
                        "id": { "type": "integer", "format": "int64" },
                        "event_type": { "type": "string" },
                        "aggregate_type": { "type": "string" },
                        "aggregate_id": { "type": "string" },
                        "site": {
                            "oneOf": [{ "type": "string" }, { "type": "null" }]
                        },
                        "environment": {
                            "oneOf": [{ "type": "string" }, { "type": "null" }]
                        },
                        "actor": { "type": "string" },
                        "severity": { "type": "string", "example": "critical" },
                        "payload": {
                            "description": "The event's structured payload — an arbitrary JSON value \
                                (the column is a serde_json::Value); conventionally a JSON object but \
                                NOT type-constrained, so an untyped schema (per OpenAPI 3.1, any type)."
                        },
                        "occurred_at": { "type": "string", "format": "date-time" },
                        "acknowledged": { "type": "boolean" },
                        "acknowledged_by": {
                            "oneOf": [{ "type": "string" }, { "type": "null" }]
                        },
                        "acknowledged_at": {
                            "oneOf": [{ "type": "string", "format": "date-time" }, { "type": "null" }]
                        }
                    }
                },
                "AlertsResponse": {
                    "type": "object",
                    "required": ["alerts", "durable"],
                    "properties": {
                        "alerts": { "type": "array", "items": { "$ref": "#/components/schemas/AlertItem" } },
                        "durable": { "type": "boolean", "description": "False when no database is configured (empty list)." }
                    }
                }
            }
        },
        "paths": {
            "/api/agents/register": {
                "post": {
                    "summary": "Enroll a new agent (pending admin approval)",
                    "description": "Generates a bearer token, stores its SHA-256 hash, and returns \
                        the plaintext token ONCE. The agent remains in `pending` status until an \
                        admin approves it.",
                    "operationId": "registerAgent",
                    "tags": ["agents"],
                    "parameters": [{ "$ref": "#/components/parameters/ProtocolVersionHeader" }],
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": { "schema": { "$ref": "#/components/schemas/RegisterBody" } }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "Agent registered (pending approval).",
                            "content": {
                                "application/json": { "schema": { "$ref": "#/components/schemas/RegisterResponse" } }
                            }
                        },
                        "400": {
                            "description": "Empty agent_id/platform/public_key, malformed/weak Ed25519 public key, or an invalid/unsupported x-ryuki-protocol-version header.",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorBody" } } }
                        },
                        "409": {
                            "description": "agent_id already registered.",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorBody" } } }
                        },
                        "503": {
                            "description": "Database unavailable.",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorBody" } } }
                        }
                    }
                }
            },
            "/api/agents/cp-public-key": {
                "get": {
                    "summary": "Fetch the control plane's Ed25519 public key",
                    "description": "Unauthenticated — a public key is not a secret. Agents use \
                        this to pin the CP public key for verifying VerifiedLiveContext grants, and \
                        to read the CP's advertised protocol_version.",
                    "operationId": "cpPublicKey",
                    "tags": ["agents"],
                    "security": [],
                    "parameters": [{ "$ref": "#/components/parameters/ProtocolVersionHeader" }],
                    "responses": {
                        "200": {
                            "description": "CP public key + advertised protocol version.",
                            "content": {
                                "application/json": { "schema": { "$ref": "#/components/schemas/CpPublicKeyResponse" } }
                            }
                        },
                        "503": {
                            "description": "CP signing key not initialised (degraded startup).",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorBody" } } }
                        }
                    }
                }
            },
            "/api/agents/{agent_id}/jobs": {
                "get": {
                    "summary": "Poll for and atomically lease the next pending job",
                    "description": "Authenticated (bearer token + approved). Atomically leases the \
                        next Pending job for this agent's platform via SELECT ... FOR UPDATE SKIP \
                        LOCKED, and returns the full Job with its JobLease (including cp_nonce + \
                        fencing_token). Returns 204 when no Pending job is available.",
                    "operationId": "pollJob",
                    "tags": ["agents"],
                    "security": [{ "agentBearer": [] }],
                    "parameters": [
                        { "$ref": "#/components/parameters/ProtocolVersionHeader" },
                        {
                            "name": "agent_id",
                            "in": "path",
                            "required": true,
                            "schema": { "type": "string" }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "A job was leased.",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Job" } } }
                        },
                        "204": { "description": "No Pending job available for this agent's platform." },
                        "401": {
                            "description": "Missing/malformed bearer token.",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorBody" } } }
                        },
                        "403": {
                            "description": "Token does not match any approved agent, or does not match the path agent_id.",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorBody" } } }
                        },
                        "503": {
                            "description": "Database unavailable.",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorBody" } } }
                        }
                    }
                }
            },
            "/api/agents/{agent_id}/jobs/{job_id}/ack": {
                "post": {
                    "summary": "Acknowledge a leased job (Leased -> Running)",
                    "description": "The caller must supply the fencing_token and attempt_id that \
                        match the current lease. A mismatch, expired lease, or wrong status returns 409.",
                    "operationId": "ackJob",
                    "tags": ["agents"],
                    "security": [{ "agentBearer": [] }],
                    "parameters": [
                        { "$ref": "#/components/parameters/ProtocolVersionHeader" },
                        { "name": "agent_id", "in": "path", "required": true, "schema": { "type": "string" } },
                        { "name": "job_id", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } }
                    ],
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": { "schema": { "$ref": "#/components/schemas/AckBody" } }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "Job transitioned to Running.",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/AckResponse" } } }
                        },
                        "403": {
                            "description": "Token does not match agent_id, or job is not assigned to this agent.",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorBody" } } }
                        },
                        "404": {
                            "description": "Job not found.",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorBody" } } }
                        },
                        "409": {
                            "description": "Status/attempt_id/fencing_token mismatch or expired lease.",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorBody" } } }
                        }
                    }
                }
            },
            "/api/agents/{agent_id}/jobs/{job_id}/result": {
                "post": {
                    "summary": "Submit a signed terminal job result",
                    "description": "Verifies and records the signed JobResult from an agent. The \
                        full verifier runs fail-closed: every check that fails returns 4xx and \
                        mutates nothing. A repeat POST with the same (job_id, attempt_id, \
                        result_id) returns an idempotent 200.",
                    "operationId": "postJobResult",
                    "tags": ["agents"],
                    "security": [{ "agentBearer": [] }],
                    "parameters": [
                        { "$ref": "#/components/parameters/ProtocolVersionHeader" },
                        { "name": "agent_id", "in": "path", "required": true, "schema": { "type": "string" } },
                        { "name": "job_id", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } }
                    ],
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": { "schema": { "$ref": "#/components/schemas/ResultBody" } }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "Result recorded (or idempotently re-returned for a repeat submission).",
                            "content": { "application/json": { "schema": { "type": "object" } } }
                        },
                        "400": {
                            "description": "Malformed body, digest mismatch, or an invalid/unsupported x-ryuki-protocol-version header.",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorBody" } } }
                        },
                        "401": {
                            "description": "Missing/malformed bearer token.",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorBody" } } }
                        },
                        "403": {
                            "description": "Token does not match path agent_id, or job is not assigned to this agent.",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorBody" } } }
                        },
                        "409": {
                            "description": "Stale attempt/lease_generation, or a result conflicting with an already-recorded terminal outcome.",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorBody" } } }
                        }
                    }
                }
            },
            "/api/agents/{agent_id}/heartbeat": {
                "post": {
                    "summary": "Report agent liveness",
                    "description": "Updates last_seen_at on the agent row. Optionally records the currently running job id.",
                    "operationId": "heartbeat",
                    "tags": ["agents"],
                    "security": [{ "agentBearer": [] }],
                    "parameters": [
                        { "$ref": "#/components/parameters/ProtocolVersionHeader" },
                        { "name": "agent_id", "in": "path", "required": true, "schema": { "type": "string" } }
                    ],
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": { "schema": { "$ref": "#/components/schemas/HeartbeatBody" } }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "Heartbeat recorded.",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/HeartbeatResponse" } } }
                        },
                        "401": {
                            "description": "Missing/malformed bearer token.",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorBody" } } }
                        },
                        "403": {
                            "description": "Token does not match agent_id.",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorBody" } } }
                        },
                        "503": {
                            "description": "Database unavailable.",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorBody" } } }
                        }
                    }
                }
            },
            "/health": {
                "get": {
                    "summary": "Liveness probe",
                    "description": "Unauthenticated. Always 200 unless `?simulate=error` is \
                        passed, which forces a 503 ProblemDetails for testing the error \
                        contract. `status` is `degraded` (still 200) when the database is \
                        disconnected or hard config validation fails.",
                    "operationId": "health",
                    "tags": ["public"],
                    "security": [],
                    "parameters": [
                        {
                            "name": "simulate",
                            "in": "query",
                            "required": false,
                            "description": "Set to `error` to force a 503 ProblemDetails response.",
                            "schema": { "type": "string", "enum": ["error"] }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Health check result (healthy or degraded).",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/HealthResponse" } } }
                        },
                        "503": {
                            "description": "Simulated failure via `?simulate=error`.",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ProblemDetails" } } }
                        }
                    }
                }
            },
            "/ready": {
                "get": {
                    "summary": "Readiness probe",
                    "description": "Unauthenticated. Returns 200 only when the server is not \
                        draining, hard config validation passes, and the database is reachable \
                        with migrations applied. `?simulate=error` forces a 503 ProblemDetails \
                        for testing the error contract.",
                    "operationId": "ready",
                    "tags": ["public"],
                    "security": [],
                    "parameters": [
                        {
                            "name": "simulate",
                            "in": "query",
                            "required": false,
                            "description": "Set to `error` to force a 503 ProblemDetails response.",
                            "schema": { "type": "string", "enum": ["error"] }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Server is ready to accept traffic.",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ReadyResponse" } } }
                        },
                        "503": {
                            "description": "Not ready: draining, simulated failure, invalid \
                                config, or the database is unavailable/unusable/mid-migration.",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ProblemDetails" } } }
                        }
                    }
                }
            },
            "/api/auth/status": {
                "get": {
                    "summary": "Report whether Entra ID SSO is configured",
                    "description": "Unauthenticated pre-login read — the sign-in page's bootstrap.",
                    "operationId": "authStatus",
                    "tags": ["public"],
                    "security": [],
                    "responses": {
                        "200": {
                            "description": "Entra ID configuration presence.",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/AuthStatusResponse" } } }
                        }
                    }
                }
            },
            "/api/auth/session": {
                "get": {
                    "summary": "Read the caller's resolved session",
                    "description": "Unauthenticated route (exempt from the session-required \
                        gate) so the portal can probe its own auth state pre-login; an \
                        unauthenticated caller gets back an unverified/anonymous session shape, \
                        not a 401.",
                    "operationId": "authSession",
                    "tags": ["public"],
                    "security": [],
                    "responses": {
                        "200": {
                            "description": "The resolved (or unverified/anonymous) session.",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/AuthSession" } } }
                        }
                    }
                }
            },
            "/api/auth/roles": {
                "get": {
                    "summary": "List the platform's RBAC roles",
                    "description": "Unauthenticated — role/permission names are not secret; the \
                        sign-in page uses this to describe access levels before login.",
                    "operationId": "authRoles",
                    "tags": ["public"],
                    "security": [],
                    "responses": {
                        "200": {
                            "description": "All configured RBAC roles.",
                            "content": {
                                "application/json": {
                                    "schema": { "type": "array", "items": { "$ref": "#/components/schemas/RbacRole" } }
                                }
                            }
                        }
                    }
                }
            },
            "/api/platform/summary": {
                "get": {
                    "summary": "Read platform branding/mode metadata",
                    "description": "Unauthenticated pre-login read — the sign-in page's \
                        bootstrap for choosing sign-in copy (authenticationMode). Non-sensitive \
                        branding/mode metadata only: no request data, secrets, tenant ids, or \
                        network values.",
                    "operationId": "platformSummary",
                    "tags": ["public"],
                    "security": [],
                    "responses": {
                        "200": {
                            "description": "Platform summary.",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/PlatformSummaryResponse" } } }
                        }
                    }
                }
            },
            "/api/ops/scheduler/schedules": {
                "get": {
                    "summary": "List the durable scheduler's registered recurring jobs",
                    "description": "Requires an operator session and the `execute` permission \
                        tier. Read-only. Returns an empty list with `durable: false` when no \
                        database is configured.",
                    "operationId": "opsSchedulerSchedules",
                    "tags": ["ops-read"],
                    "security": [{ "apiSessionHeader": [] }],
                    "responses": {
                        "200": {
                            "description": "The registered schedules.",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SchedulerSchedulesResponse" } } }
                        },
                        "401": {
                            "description": "Missing/invalid session.",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorBody" } } }
                        },
                        "403": {
                            "description": "Session lacks the `execute` permission tier.",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorBody" } } }
                        }
                    }
                }
            },
            "/api/ops/scheduler/executions": {
                "get": {
                    "summary": "List recent durable-scheduler job runs",
                    "description": "Requires an operator session and the `execute` permission \
                        tier. Read-only. Returns an empty list with `durable: false` when no \
                        database is configured.",
                    "operationId": "opsSchedulerExecutions",
                    "tags": ["ops-read"],
                    "security": [{ "apiSessionHeader": [] }],
                    "responses": {
                        "200": {
                            "description": "Recent job executions.",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SchedulerExecutionsResponse" } } }
                        },
                        "401": {
                            "description": "Missing/invalid session.",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorBody" } } }
                        },
                        "403": {
                            "description": "Session lacks the `execute` permission tier.",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorBody" } } }
                        }
                    }
                }
            },
            "/api/events": {
                "get": {
                    "summary": "Read the operational domain-event feed",
                    "description": "Requires an operator session and the `request` (or higher, \
                        e.g. `audit`) permission tier. Newest first, site/environment-scoped: a \
                        scoped principal sees only its own scope's events plus platform-wide \
                        (NULL on both axes) events. Returns an empty list with `durable: false` \
                        when no database is configured.",
                    "operationId": "opsEvents",
                    "tags": ["ops-read"],
                    "security": [{ "apiSessionHeader": [] }],
                    "parameters": [
                        {
                            "name": "event_type",
                            "in": "query",
                            "required": false,
                            "description": "Filter to one dotted event type, e.g. `request.approve`.",
                            "schema": { "type": "string" }
                        },
                        {
                            "name": "aggregate_id",
                            "in": "query",
                            "required": false,
                            "description": "Filter to one aggregate's history (e.g. a request id).",
                            "schema": { "type": "string" }
                        },
                        {
                            "name": "limit",
                            "in": "query",
                            "required": false,
                            "description": "Page size. Default 50, clamped to 1..500.",
                            "schema": { "type": "integer", "minimum": 1, "maximum": 500, "default": 50 }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "The event feed page.",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/EventsResponse" } } }
                        },
                        "401": {
                            "description": "Missing/invalid session.",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorBody" } } }
                        },
                        "403": {
                            "description": "Session lacks the required permission tier.",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorBody" } } }
                        }
                    }
                }
            },
            "/api/events/alerts": {
                "get": {
                    "summary": "Read the alert-worthy slice of the domain-event feed",
                    "description": "Requires an operator session and the `request` (or higher, \
                        e.g. `audit`) permission tier. Same scoping as `/api/events`, filtered to \
                        events the alert classifier flags (request reaching a negative terminal \
                        state), annotated with severity and acknowledgement state. Returns an \
                        empty list with `durable: false` when no database is configured.",
                    "operationId": "opsEventsAlerts",
                    "tags": ["ops-read"],
                    "security": [{ "apiSessionHeader": [] }],
                    "parameters": [
                        {
                            "name": "aggregate_id",
                            "in": "query",
                            "required": false,
                            "description": "Filter to one aggregate's history (e.g. a request id).",
                            "schema": { "type": "string" }
                        },
                        {
                            "name": "limit",
                            "in": "query",
                            "required": false,
                            "description": "Page size. Default 50, clamped to 1..500.",
                            "schema": { "type": "integer", "minimum": 1, "maximum": 500, "default": 50 }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "The alert feed page.",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/AlertsResponse" } } }
                        },
                        "401": {
                            "description": "Missing/invalid session.",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorBody" } } }
                        },
                        "403": {
                            "description": "Session lacks the required permission tier.",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorBody" } } }
                        }
                    }
                }
            }
        }
    })
}

/// Thin handler wrapping [`openapi_document`] for `GET /api/agents/openapi.json`.
pub async fn openapi_json() -> axum::Json<Value> {
    axum::Json(openapi_document())
}

#[cfg(test)]
mod tests {
    use super::openapi_document;
    use serde_json::Value;
    use std::collections::BTreeSet;

    #[test]
    fn shape_is_a_well_formed_openapi_3_1_document() {
        let doc = openapi_document();
        let openapi_version = doc["openapi"]
            .as_str()
            .expect("openapi field must be a string");
        assert!(
            openapi_version.starts_with("3.1"),
            "expected an OpenAPI 3.1.x document, got {openapi_version}"
        );

        let info = &doc["info"];
        assert!(
            info["title"].as_str().is_some_and(|s| !s.is_empty()),
            "info.title must be a non-empty string"
        );
        assert!(
            info["version"].as_str().is_some_and(|s| !s.is_empty()),
            "info.version must be a non-empty string"
        );

        assert!(doc["paths"].is_object(), "paths must be an object");
        assert!(
            doc["components"]["schemas"].is_object(),
            "components.schemas must be present"
        );
        assert!(
            doc["components"]["securitySchemes"]["agentBearer"].is_object(),
            "components.securitySchemes.agentBearer must be present"
        );
        assert!(
            doc["components"]["securitySchemes"]["apiSessionHeader"].is_object(),
            "components.securitySchemes.apiSessionHeader must be present"
        );
    }

    /// Asserts every (METHOD, path) pair in `expected` is present in `doc.paths`
    /// with the right method. Shared helper for the three per-group coverage
    /// tests below.
    fn assert_all_documented(doc: &Value, expected: &[(&str, &str)]) {
        let paths = doc["paths"].as_object().expect("paths must be an object");
        for (method, path) in expected {
            let item = paths
                .get(*path)
                .unwrap_or_else(|| panic!("missing documented path: {path}"));
            let method_key = method.to_lowercase();
            assert!(
                item.get(&method_key).is_some(),
                "path {path} is missing the {method} operation"
            );
        }
    }

    #[test]
    fn all_six_agent_paths_are_documented_with_the_right_method() {
        let doc = openapi_document();
        assert_all_documented(&doc, crate::agents::AGENT_ROUTE_PATHS);
    }

    #[test]
    fn all_public_paths_are_documented_with_the_right_method() {
        let doc = openapi_document();
        assert_all_documented(&doc, crate::PUBLIC_ROUTE_PATHS);
    }

    #[test]
    fn all_ops_read_paths_are_documented_with_the_right_method() {
        let doc = openapi_document();
        assert_all_documented(&doc, crate::contracts::OPS_READ_ROUTE_PATHS);
    }

    /// DRIFT GUARD: the full set of (method, path) pairs documented here must
    /// equal the UNION of `crate::agents::AGENT_ROUTE_PATHS`,
    /// `crate::PUBLIC_ROUTE_PATHS`, and `crate::contracts::OPS_READ_ROUTE_PATHS`
    /// EXACTLY — no missing, no extra. Adding or removing a route in any of the
    /// three groups without updating this spec (or vice versa) fails this test.
    ///
    /// `GET /api/agents/openapi.json` (this document's own meta route) is
    /// intentionally NOT part of any of the three constants and NOT listed in
    /// `paths` — it describes the document, it is not part of the surface the
    /// document describes.
    #[test]
    fn documented_paths_match_the_union_of_all_route_path_constants_exactly() {
        let doc = openapi_document();
        let paths = doc["paths"].as_object().expect("paths must be an object");

        let documented: BTreeSet<(String, String)> = paths
            .iter()
            .flat_map(|(path, item)| {
                let obj = item.as_object().expect("path item must be an object");
                obj.keys()
                    .filter(|k| {
                        matches!(
                            k.as_str(),
                            "get" | "post" | "put" | "delete" | "patch" | "options" | "head"
                        )
                    })
                    .map(move |method| (method.to_uppercase(), path.clone()))
            })
            .collect();

        let source_of_truth: BTreeSet<(String, String)> = crate::agents::AGENT_ROUTE_PATHS
            .iter()
            .chain(crate::PUBLIC_ROUTE_PATHS.iter())
            .chain(crate::contracts::OPS_READ_ROUTE_PATHS.iter())
            .map(|(method, path)| (method.to_string(), path.to_string()))
            .collect();

        assert_eq!(
            documented, source_of_truth,
            "openapi.rs paths and the union of AGENT_ROUTE_PATHS + PUBLIC_ROUTE_PATHS + \
             OPS_READ_ROUTE_PATHS have drifted apart \
             (left = documented in openapi.rs, right = union of route-path constants)"
        );
    }
}
