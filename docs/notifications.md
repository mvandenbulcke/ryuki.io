# Notifications

Ryuki has in-app notifications with per-user read receipts. They are emitted by the server on lifecycle and operational events, listed in the portal bell, and readable over the API. There is no email or webhook delivery today: a dispatch outbox records what a future sender *would* do, and nothing more.

## What gets notified, and to whom

Notifications are created only by server-side domain logic; there is no API to emit one.

| Event | Recipient | Severity |
| --- | --- | --- |
| `request.plan` | Role: `DatacenterApprover` | Info |
| `request.approve` | Request owner | Success |
| `request.reject` | Request owner | Warning |
| `request.verify` | Request owner | Success |
| `request.cancel` | Request owner | Warning |
| `slo.breach` / `slo.recovered` | Role: `MonitoringOperator` | Critical / Success |
| `budget.breach` / `budget.recovered` | Role: `MonitoringOperator` | Warning / Success |
| `agent.offline` / `agent.online` | Role: `MonitoringOperator` | Warning / Success |

Lifecycle notifications are emitted after the transaction commits, detached from the request path: a notification failure can never fail the transition. Monitoring alerts (SLO, budget, agent liveness) are written atomically with their domain event by the background scan loops. A partial approval deliberately does not tell the owner "approved."

Notification bodies are synthesized from structured fields (request id, aggregate id); free-text never flows into a notification.

## Recipients and read state

A notification targets either one user or one role. Role notifications are a single row that every holder of the role sees; read state is a per-user receipt, so one operator marking an alert read does not clear it for the rest of the team.

Notifications are not site- or environment-scoped: they follow the recipient, not the resource's scope.

## API

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/api/notifications` | The caller's notifications, newest first (capped at 200). |
| GET | `/api/notifications/unread-count` | Badge count. |
| POST | `/api/notifications/{id}/read` | Mark one read. Non-recipients get a 404; existence is never leaked. |
| POST | `/api/notifications/read-all` | Mark all read. |
| GET | `/api/admin/notifications/dispatch-outbox` | Admin: dry-run dispatch telemetry (`?status=`, `?limit=`). Returns metadata only, never bodies. |

Reading requires an ordinary session (audit or request tier); marking read is self-service for the recipient. Without a database the read endpoints degrade to empty `no-db` responses and the write endpoints return 503.

## The portal bell

The bell lives in the portal header. The badge shows the unread count and the panel lists recent notifications; clicking an item marks it read and deep-links to the request when one is referenced. Counts refresh when the panel opens or after your own read actions; a background poll is a possible follow-up, so a notification arriving mid-session appears the next time you open the panel.

## Delivery channels

Every emitted notification also plans its hypothetical delivery in the dispatch outbox: Critical events plan email and webhook, Warnings plan webhook, Info and Success plan nothing. The outbox is telemetry for operators to inspect (`dry_run_logged` status); no send path exists yet, and outbox bookkeeping can never roll back a notification.

## Known limits

There is no retention or pruning job for notifications yet; the list endpoint caps at the newest 200 per recipient. If you need long-term archival of operational events, use the audit trail and domain events, which are the durable record.
