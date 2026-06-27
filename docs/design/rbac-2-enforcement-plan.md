# Swarm #2 — site/env RBAC enforcement: verified gap plan (2026-06-27)

## SHIPPED (progress)
- [x] **request lifecycle** — `b6b3e45` (chokepoint in apply_transition_audited + after-load guards on 13 handlers + create body guard; site+env)
- [x] **certificates** — `29d5309` (site-only; full CRUD; +AuthExtractor on 5)
- [x] **storage** volumes/arrays — `4f487d7` (site-only; by-id reads + load-then-guard writes)
- [x] **k8s namespaces** — `e696c29` (site-only; get + update_quota/suspend/resume/terminate pre-load)
- [x] **gmsa** — `c998ffc` (site-only; create/assign/remove/rotate/test/expiring; inventory pre-existing)
- [x] **request verify/protect no-DB** — `8346840` (in-memory dry-run branches; DB branches already guarded by b6b3e45)
- [x] **load balancer** — `3e19354` (site-only; all 10 handlers: provision/vs_get/update/delete/drain/disable/enable/member_add/remove/validate_vip; vs_get loads-then-guards-then-loads-pool; codex caught 2 cross-site defects)
- [x] **log forwarders** — `18f5486` (site-only; all 8: onboard/coverage/gaps/volume/retention/validate/verify/disable; disable was cross-site → new site-confined repo fn disable_for_hostname_in_sites; codex APPROVED first pass)
- [x] **immutability** — `0838806` (site-only; all 8 reads: check/retention_lock/air_gap by-id, verify_all/compliance_report site-query, noncompliant/retention_risk list-all, remediation by-id-over-list; codex APPROVED first pass)
- [x] **ad computers** — `3f8ab20` (site-only; all 6: prestage body-create, move/disable/enable/delete by-name writes (guard before status-409 leak), ad_get by-name read; codex APPROVED first pass; resolves the AD-write chip)
- [x] **patch waves** — `f81d7cc` (MULTI-SITE: new within_multi_scope/multi_scope_guard_or_404 containment helpers; all 8 wave handlers incl. patch_reboot the audit missed; +narrow_site_aggregate for compliance/pending_reboots dashboards; codex design-reviewed then caught 3 aggregate leaks, all fixed)
- [x] **legal holds** — `eeaddac` (site-only; all 7; per-handler oracle-safe not-found codes (400/404/409); +is_scoped helper; no-DB fallbacks fail closed 503 for scoped; codex caught a body-oracle + a 6-handler no-DB bypass class, all fixed)
- [x] **emergency changes** — `b9655e4` (site-only break-glass; all 6; ProblemDetails guards emergency_scope_guard/_preload_guard; per-action 404; guard before status-409; no-DB fail-closed 503; emergency_history pre-scoped; codex APPROVED first pass)
- [x] **managed secrets** — `3325fb8` (site-only; 7 handlers incl. rotation_history the audit missed; re-home guard on update; rotation_fail scopes via parent secret_id; no-DB fail-closed 503; codex caught a cross-site vault_path leak in due/expiring no-DB fallbacks, fixed)
- [x] **sql deployments** — `df32e33` (site-only; 6 of 8 handlers (validate is pure, inventory pre-scoped); plan body-guard + install/configure/verify/backup/monitoring by-id guard before state-409; standard status_404 so no oracle; codex APPROVED first pass)
- [x] **file shares** — `3ecfec9` (site-only; 5 of 8 (list/recert-due/stale-owners pre-scoped, contract static); by-id reads + recertify CAS + ACL open-access/report/revoke all load+guard the parent share before child ACL access; codex APPROVED first pass)

Resume with the next unchecked domain below (lb / logs / immutability / patch / secrets / emergency / decommission / …). Per-domain cadence: confirm the table has site (and/or environment), apply guards, add a scoped DB test, clippy + router-build, commit.

Authoritative work-list from the 203-agent verified audit (149 handlers already enforced). **190 confirmed-gap handlers** across 44 domain groups.

Guard patterns: by-id -> `scope_guard_or_404(&session,&row.site,&row.environment,&id)?` right after load (SITE-ONLY tables pass `""` for environment, which fails-closed for env-scoped principals); list/query -> `enforce_site_scope` / `retain_site_scoped`; write-from-body -> `enforce_scope_filters`. CAVEATS: some handlers take no session (need AuthExtractor added = makes an open read require auth); some read child tables (e.g. rotation_runs) needing the parent's site via join; confirm each table actually has a site column before guarding.

## requests  (15)
- [ ] **requests_create** [high] `sources/ryuki-api/src/contracts.rs:13742` — Insert a dual-axis body-scope guard immediately AFTER the check_permission gate (after line 13767, before the engine create_request call at 13769 and the INSERT at 13820). Source o
- [ ] **requests_approve_live_apply** [high] `sources/ryuki-api/src/contracts.rs:14168` — Add the by-id scope guard before the grant is minted, mirroring requests_get / requests_execution_job. 1) Add `environment: String` to the PlanJobRow struct (14206-14213). 2) Add `
- [ ] **requests_validate** [high] `sources/ryuki-api/src/contracts.rs:14439` — DB path: immediately after loading `current` (after contracts.rs:14458, before validate_request at 14461) insert `scope_guard_or_404(&session, &current.site, &current.environment, 
- [ ] **requests_approve** [high] `sources/ryuki-api/src/contracts.rs:15121` — In requests_approve, insert a scope guard immediately after the row is loaded in BOTH paths, before check_sod / approve_request / apply_transition_audited. DB path: after the `.ok_
- [ ] **requests_lock** [high] `sources/ryuki-api/src/contracts.rs:15234` — DB path: right after loading `current` (after contracts.rs:15251), add scope_guard_or_404(&session, &current.site, &current.environment, &request_id)? so an out-of-scope row 404s e
- [ ] **requests_execute** [high] `sources/ryuki-api/src/contracts.rs:15309` — DB path: after the row is loaded (insert after line 15352, before request_lifecycle::begin_execution at 15363) add scope_guard_or_404(&session, &current.site, &current.environment,
- [ ] **requests_verify** [high] `sources/ryuki-api/src/contracts.rs:15487` — 
- [ ] **requests_protect** [high] `sources/ryuki-api/src/contracts.rs:15618` — Add a scope guard immediately after loading the row, before the engine transition / before returning, in BOTH branches. DB branch (after line 15635, mirroring requests_get:14376): 
- [ ] **requests_publish** [high] `sources/ryuki-api/src/contracts.rs:15726` — In the DB branch, after loading `current` (line 15743) and before apply_transition_audited (15761), insert: scope_guard_or_404(&session, &current.site, &current.environment, &reque
- [ ] **requests_retire** [high] `sources/ryuki-api/src/contracts.rs:15835` — Add the canonical by-id guard immediately after the DB row loads (after line 15852, before retire_request at 15855): scope_guard_or_404(&session, &current.site, &current.environmen
- [ ] **requests_reject** [high] `sources/ryuki-api/src/contracts.rs:15951` — DB path: immediately after the `current` row loads (after 15975, before check_sod at 15979) insert `scope_guard_or_404(&session, &current.site, &current.environment, &request_id)?;
- [ ] **requests_rework** [high] `sources/ryuki-api/src/contracts.rs:16072` — Add a post-load by-id scope guard in BOTH paths, mirroring request_evidence_pack (:16814). DB path: immediately after building `let request = db_row_to_request(&current, &request_i
- [ ] **requests_batch_cancel** [high] `sources/ryuki-api/src/contracts.rs:16372` — Fix in the shared core cancel_one (contracts.rs:16276) so BOTH batch (16372) and single (16254) paths are covered in one place. DB branch: after loading `current` (line 16290) and 
- [ ] **requests_fail** [medium] `sources/ryuki-api/src/contracts.rs:16161` — After loading `current` (line 16189), add scope_guard_or_404(&session, &current.site, &current.environment, &request_id)? before the fail_request/apply_transition_audited write — (
- [ ] **requests_plan** [?] `sources/ryuki-api/src/contracts.rs:14991` — 

## certificates  (10)
- [ ] **certificates_request** [high] `sources/ryuki-api/src/contracts.rs:21857` — Add `guard_body_site_scope(&session, &body.site)?;` immediately after `let pool = get_db()...?;` (after contracts.rs:21861) and before building the CertificateRequest, mirroring th
- [ ] **certificates_get / certificates_approve / certificates_install / certificates_verify** [high] `sources/ryuki-api/src/contracts.rs:22077` — For each handler add `AuthExtractor(session): AuthExtractor` as the first param, then after loading the record and before returning, call `scope_guard_or_404(&session, &record.site
- [ ] **certificates_renew / certificates_revoke** [high] `sources/ryuki-api/src/contracts.rs:21952` — In certificates_renew (contracts.rs:21952), immediately after the `cert` load+404 (after line 21962, before the Revoked-status 409 check at 21965), add `guard_body_site_scope(&sess
- [ ] **certificates_inventory** [high] `sources/ryuki-api/src/contracts.rs:22067` — In sources/ryuki-api/src/contracts.rs:22067, change the signature to take `AuthExtractor(session): AuthExtractor` and an optional `?site` query param (mirror CertificateExpiringQue
- [ ] **certificates_get** [high] `sources/ryuki-api/src/contracts.rs:22077` — Extract the session and add a post-load scope guard, mirroring certificates_expiring on the same table. Change signature to `async fn certificates_get(AuthExtractor(session): AuthE
- [ ] **certificates_renew** [high] `sources/ryuki-api/src/contracts.rs:21952` — Add the by-id WRITE scope guard immediately after the row is loaded, before any state transition. In certificates_renew, right after line 21962 (`.ok_or_else(|| status_404(&id))?`)
- [ ] **certificates_revoke** [high] `sources/ryuki-api/src/contracts.rs:22003` — In certificates_revoke, after loading the row (contracts.rs:22012) and BEFORE the engine guard at :22017, add `scope_guard_or_404(&session, &cert.site, "", &id)?;`. The (site,env) 
- [ ] **certificates_approve** [medium] `sources/ryuki-api/src/contracts.rs:21919` — Add scope enforcement to the by-id read. (1) Change the signature to take the session: `async fn certificates_approve(AuthExtractor(session): AuthExtractor, Path(id): Path<String>)
- [ ] **certificates_install** [medium] `sources/ryuki-api/src/contracts.rs:21930` — Add `AuthExtractor(session): AuthExtractor` as the first param of certificates_install, then immediately after loading `record` (line 21937, before the return at 21938) enforce SIT
- [ ] **certificates_verify** [?] `sources/ryuki-api/src/contracts.rs:21941` — Add AuthExtractor(session): AuthExtractor to the certificates_verify signature, then after loading the record call scope_guard_or_404(&session, &record.site, "", &id)? BEFORE retur

## lb  (9)
- [x] **lb_provision** [high] `sources/ryuki-api/src/contracts.rs:30508` — Add `AuthExtractor(session): AuthExtractor` to the lb_provision signature, then before build_provision call `let (eff_site, _) = enforce_scope_filters(&session, norm(&b.site), None
- [x] **lb_vs_get** [high] `sources/ryuki-api/src/contracts.rs:30562` — Add `AuthExtractor(session): AuthExtractor` as the first parameter of lb_vs_get (contracts.rs:30562), matching the sibling lb_vs_update. After loading the row at L30566-30569, befo
- [x] **lb_vs_update** [high] `sources/ryuki-api/src/contracts.rs:30588` — The UPDATE mutates by id with no site predicate and the row carries `site`, so guard against the row's actual site. Cleanest minimal fix using the canonical helper: pre-load the VS
- [x] **lb_vs_delete** [high] `sources/ryuki-api/src/contracts.rs:30649` — Load the VS's site before the destructive write and gate on it. In lb_vs_delete (contracts.rs:30649), after obtaining `db` and before `delete_virtual_server`, fetch the row to lear
- [x] **lb_pool_member_add** [high] `sources/ryuki-api/src/contracts.rs:30680` — After loading `vs` at L30702, before opening the mutation tx / calling add_pool_member, add: scope_guard_or_404(&session, &vs.site, "", &id)?; — the (site) source is `vs.site` from
- [x] **lb_pool_member_remove** [high] `sources/ryuki-api/src/contracts.rs:30757` — Insert a by-id scope guard immediately after pool_id is resolved (after contracts.rs:30768) and BEFORE the tx begins at L30770:      scope_guard_or_404(&session, &vs.site, "", &id)
- [x] **lb_vs_drain** [high] `sources/ryuki-api/src/contracts.rs:30810` — update_vs_status returns the updated VS (carrying `site`) inside the still-open transaction. Insert a post-load by-id guard between the row load (L30823) and the audit/commit: `sco
- [x] **lb_vs_disable** [high] `sources/ryuki-api/src/contracts.rs:30840` — The updated row (with site) is only available after the UPDATE, so guard post-load and roll back if out of scope. After the .ok_or_else(|| status_404(&id))? at L30853 (before audit
- [x] **lb_vs_enable** [high] `sources/ryuki-api/src/contracts.rs:30870` — After the update_vs_status load at contracts.rs:30876-30883 and BEFORE tx.commit() at L30891, insert: scope_guard_or_404(&session, &vs.site, "", &id)?; (defined at contracts.rs:211

## immutability  (8)
- [x] **immutability_check** [high] `sources/ryuki-api/src/contracts.rs:9014` — Add `session: AuthSession` as a handler parameter and call scope_guard_or_404 after the row loads, using the row's site (environment is empty for this resource). Concretely at cont
- [x] **immutability_verify_all** [high] `sources/ryuki-api/src/contracts.rs:9053` — Add `Extension(session): Extension<AuthSession>` to the handler signature, then before the DB read replace the manual empty-site check with `let site = enforce_site_scope(&session,
- [x] **immutability_compliance_report** [high] `sources/ryuki-api/src/contracts.rs:9072` — Add the AuthSession to the handler and clamp the queried site to the principal's scope before the DB read. Change the signature to `async fn immutability_compliance_report(AuthExtr
- [x] **immutability_noncompliant** [high] `sources/ryuki-api/src/contracts.rs:9091` — Mirror the established twin datacenter_failing_checks_endpoint exactly. (a) Add the session extractor to the signature: `async fn immutability_noncompliant(AuthExtractor(session): 
- [x] **immutability_retention_risk** [high] `sources/ryuki-api/src/contracts.rs:9102` — Two-step (the handler currently has no auth extractor, so add it first). 1) Change the signature to accept the session: `async fn immutability_retention_risk(AuthExtractor(session)
- [x] **immutability_remediation** [high] `sources/ryuki-api/src/contracts.rs:9113` — 
- [x] **immutability_retention_lock** [medium] `sources/ryuki-api/src/contracts.rs:9027` — Add the by-id scope guard, identical to the canonical pattern. 1) Add an AuthSession extractor to the handler signature: `async fn immutability_retention_lock(AuthExtractor(session
- [x] **immutability_air_gap** [medium] `sources/ryuki-api/src/contracts.rs:9040` — Add `session: AuthSession` to the handler signature, then after loading the check call `scope_guard_or_404(&session, &check.site, "", &id)?` before returning (the row exposes `chec

## logs  (8)
- [x] **logs_onboard** [high] `sources/ryuki-api/src/contracts.rs:10535` — Add the canonical site-only write guard at the top of logs_onboard, before the engine/DB work. Insert `guard_body_site_scope(&session, &body.site)?;` immediately after `let pool = 
- [x] **logs_coverage** [high] `sources/ryuki-api/src/contracts.rs:10645` — Add `session: AuthSession` to the logs_coverage signature, then before the DB read resolve the effective site via enforce_site_scope: `let site = enforce_site_scope(&session, Some(
- [x] **logs_gaps** [high] `sources/ryuki-api/src/contracts.rs:10662` — Add scope enforcement mirroring the canonical sibling hardware_firmware_gaps (contracts.rs:24098). Change the signature to take the session and make site optional, then resolve the
- [x] **logs_volume** [high] `sources/ryuki-api/src/contracts.rs:10679` — Add the session and enforce site scope before the DB read. Change the signature to `async fn logs_volume(AuthExtractor(session): AuthExtractor, Query(params): Query<LogsSiteQuery>)
- [x] **logs_retention** [high] `sources/ryuki-api/src/contracts.rs:10696` — Add `AuthExtractor(session): AuthExtractor` to the logs_retention signature, then before the DB read compute the effective site: `let site = enforce_site_scope(&session, Some(&para
- [x] **logs_disable** [high] `sources/ryuki-api/src/contracts.rs:10715` — Make the disable site-aware (a post-hoc retain won't help — the UPDATE already wrote across sites). Preferred: add a scoped repo variant disable_all_for_hostname_scoped(conn, hostn
- [x] **logs_validate** [medium] `sources/ryuki-api/src/contracts.rs:10611` — Add `AuthExtractor(session): AuthExtractor` to the logs_validate signature (sources/ryuki-api/src/contracts.rs:10611). After loading `hosts` via list_by_hostname (line 10613-10615)
- [x] **logs_verify** [medium] `sources/ryuki-api/src/contracts.rs:10628` — In logs_verify (sources/ryuki-api/src/contracts.rs:10628) add `session: AuthSession` to the signature, then after `list_by_hostname` returns `hosts` apply the per-row helper `retai

## ad  (7)
- [x] **ad_prestage** [high] `sources/ryuki-api/src/contracts.rs:4118` — Insert `guard_body_site_scope(&session, &body.site)?;` immediately after the get_db() line at contracts.rs:4122, BEFORE prestage_computer/insert (4123-4126). The helper at contract
- [x] **ad_move** [high] `sources/ryuki-api/src/contracts.rs:4160` — The row is already loaded with computer.site BEFORE any mutation, so the guard is a one-liner with no extra DB round-trip. Insert immediately after the 404 check (after line 4169, 
- [x] **ad_disable** [high] `sources/ryuki-api/src/contracts.rs:4203` — After loading the row at line 4216 (the `let (computer, updated_at) = get_by_name(...).ok_or_else(status_404)?` result) and BEFORE the disable_computer_model/transition write at 42
- [x] **ad_delete** [high] `sources/ryuki-api/src/contracts.rs:4274` — After loading the row at line 4279, before delete_computer_model at 4281, add a by-id scope guard mapping out-of-scope to 404: `scope_guard_or_404(&session, &computer.site, "", &na
- [x] **ad_move / ad_disable / ad_enable / ad_delete (by-name AD computer writes)** [high] `sources/ryuki-api/src/contracts.rs:4160` — The row's site is already loaded in `computer.site` immediately after get_by_name. Insert a post-load single-axis site guard in each handler right after the `.ok_or_else(|| status_
- [x] **ad_enable** [medium] `sources/ryuki-api/src/contracts.rs:4243` — In ad_enable, after loading `computer` (contracts.rs:4245-4248) and BEFORE the lifecycle transition at line 4249, add a site-only scope guard using the loaded row's site as the (si
- [x] **ad_get** [medium] `sources/ryuki-api/src/contracts.rs:4341` — In ad_get (contracts.rs:4341): change the signature to bind the session (AuthExtractor(session): AuthExtractor) instead of _session, then gate on the loaded site BEFORE returning. 

## gmsa  (7)
- [ ] **gmsa_assign** [high] `sources/ryuki-api/src/contracts.rs:4436` — Load the account's site before the mutation and guard it with the site-only write helper. Cleanest oracle-safe approach: extend add_host in sources/ryuki-api/src/repos/gmsa_account
- [ ] **gmsa_remove** [high] `sources/ryuki-api/src/contracts.rs:4485` — Load the account's site before mutating and gate it, failing CLOSED with a 404 (same as a missing row, to avoid a cross-scope existence oracle). In gmsa_remove at contracts.rs:4485
- [ ] **gmsa_rotate** [high] `sources/ryuki-api/src/contracts.rs:4540` — In gmsa_rotate, immediately after loading `account` (contracts.rs:4546) and before the revoked pre-check / CAS rotate, add a by-id-style scope guard using row_scope_permits (the he
- [ ] **gmsa_test** [high] `sources/ryuki-api/src/contracts.rs:4593` — Add `AuthExtractor(session): AuthExtractor` as the first parameter of gmsa_test (mirroring gmsa_inventory at line 4607). After loading `account` (line 4599) and BEFORE the `test_re
- [ ] **gmsa_expiring** [high] `sources/ryuki-api/src/contracts.rs:4623` — Add `AuthExtractor(session): AuthExtractor` to the gmsa_expiring signature (and optionally `Query(query): Query<GmsaInventoryQuery>` to accept an optional ?site), mirroring gmsa_in
- [ ] **gmsa_assign / gmsa_remove / gmsa_rotate** [high] `sources/ryuki-api/src/contracts.rs:4436` — 
- [ ] **gmsa_create** [?] `sources/ryuki-api/src/contracts.rs:4376` — Add the canonical site-only write guard at the top of gmsa_create, immediately after the session is extracted and before any DB work. body.site is the required CONCRETE (non-Option

## patch  (7)
- [x] **patch_plan** [high] `sources/ryuki-api/src/contracts.rs:8062` — Insert the canonical site-only write guard at the top of patch_plan, before plan_patch_wave: add `guard_body_site_scope(&session, &body.site)?;` immediately after `let pool = get_d
- [x] **patch_validate** [high] `sources/ryuki-api/src/contracts.rs:8097` — In patch_validate, immediately after the wave is loaded (contracts.rs:8106, before computing `before`/transitioning), add a scope guard using ryuki_engine::auth::scope_permits over
- [x] **patch_approve** [high] `sources/ryuki-api/src/contracts.rs:8136` — After loading the wave (line 8145, before approve_patch_wave at 8151), enforce both scope dimensions per-element against the principal using ryuki_engine::auth::scope_permits, retu
- [x] **patch_execute** [high] `sources/ryuki-api/src/contracts.rs:8178` — Add a scope gate immediately after the wave loads (after contracts.rs:8187, before the engine call at 8192). Since the wave carries Vec-valued scope, deny unless EVERY targeted sit
- [x] **patch_verify** [high] `sources/ryuki-api/src/contracts.rs:8218` — Add `AuthExtractor(session): AuthExtractor` to patch_verify's signature (matching patch_validate at contracts.rs:8097), then after loading the wave (line 8224) and BEFORE patch_eng
- [x] **patch_wave_get** [high] `sources/ryuki-api/src/contracts.rs:8266` — Add `AuthExtractor(session): AuthExtractor` to patch_wave_get's signature, then after loading the wave (the Ok(Some(wave)) arm at contracts.rs:8269) and BEFORE returning Json, appl
- [x] **patch_waves_list** [medium] `sources/ryuki-api/src/contracts.rs:8252` — 

## legal_hold  (7)
- [x] **legal_hold_extend** [high] `sources/ryuki-api/src/contracts.rs:9392` — Add a by-id scope guard BEFORE the CAS UPDATE in legal_hold_extend. Since legal_holds is site-only (no environment column), pre-load the hold's site and guard on it. Two equivalent
- [x] **legal_hold_release** [high] `sources/ryuki-api/src/contracts.rs:9462` — legal_holds has a site column but no environment axis, so use enforce_site_scope as the scope source and fold the effective site into the CAS predicate so an out-of-scope hold simp
- [x] **legal_hold_active** [high] `sources/ryuki-api/src/contracts.rs:9526` — Add scope enforcement before the DB read, mirroring the site-only pattern used by legal_hold_place and the no-environment-axis helpers. Concretely: change the signature to `async f
- [x] **legal_hold_expiring** [high] `sources/ryuki-api/src/contracts.rs:9546` — Add `session: AuthSession` to the handler signature. Then enforce site scope before returning data, two equivalent options: (a) per-row: after `fetch_all`, call `retain_site_scoped
- [x] **legal_hold_evidence** [high] `sources/ryuki-api/src/contracts.rs:9566` — Add an AuthSession extractor and gate on the loaded row's site before returning. Change signature to `async fn legal_hold_evidence(session: AuthSession, Path(id): Path<String>)`. I
- [x] **legal_hold_compliance** [high] `sources/ryuki-api/src/contracts.rs:9596` — This is a list-style substring read, so use per-row site filtering (not scope_guard_or_404, which is for true single-row by-id). Step 1: add `AuthExtractor(session): AuthExtractor`
- [x] **legal_hold_validate** [medium] `sources/ryuki-api/src/contracts.rs:9329` — Add `AuthExtractor(session): AuthExtractor` as the first param of legal_hold_validate (contracts.rs:9329), mirroring legal_hold_extend (9392-9396). Then immediately after `let Some

## emergency  (6)
- [x] **emergency_initiate** [high] `sources/ryuki-api/src/contracts.rs:6324` — 
- [x] **emergency_approve** [high] `sources/ryuki-api/src/contracts.rs:6392` — Reuse existing scope_guard_or_404 (contracts.rs:21108) + row_scope_permits (:21099). (site,env) source = the persisted row's own column. emergency_changes has `site` but no `enviro
- [x] **emergency_execute** [high] `sources/ryuki-api/src/contracts.rs:6505` — After the row is loaded and confirmed to exist (immediately after the `let Some(row) = row else {...404...}` block ending at contracts.rs:6536, BEFORE the status check and tx begin
- [x] **emergency_verify** [high] `sources/ryuki-api/src/contracts.rs:6650` — Add a by-id site-scope guard BEFORE the CAS UPDATE (i.e. right after `let mut tx = pool.begin()...` at ~6661, or before opening the tx). Source of (site, env): load the row's site 
- [x] **emergency_close** [high] `sources/ryuki-api/src/contracts.rs:6772` — The handler does not pre-load the row, so add a site read + guard BEFORE the CAS UPDATE (insert right after `let now = ...` at line 6778, before `pool.begin()` at 6781). Source the
- [x] **emergency_active** [high] `sources/ryuki-api/src/contracts.rs:6888` — Make emergency_active mirror its siblings. 1) Change the signature to `async fn emergency_active(AuthExtractor(session): AuthExtractor, Query(params): Query<EmergencySiteQuery>) ->

## storage  (6)
- [ ] **storage_volume_get** [high] `sources/ryuki-api/src/contracts.rs:28228` — Add `AuthExtractor(session): AuthExtractor` to the signature of storage_volume_get (contracts.rs:28228), then after loading the row (after L28237) and before returning, call `scope
- [ ] **storage_volume_extend** [high] `sources/ryuki-api/src/contracts.rs:28242` — 
- [ ] **storage_volume_map** [high] `sources/ryuki-api/src/contracts.rs:28268` — 
- [ ] **storage_volume_unmap** [high] `sources/ryuki-api/src/contracts.rs:28287` — Add `AuthExtractor(session): AuthExtractor` to the storage_volume_unmap signature. Before mutating, load the row's site and guard: `let v = crate::repos::storage_provisioning::get_
- [ ] **storage_volume_retire** [high] `sources/ryuki-api/src/contracts.rs:28303` — Add `AuthExtractor(session): AuthExtractor` to storage_volume_retire's signature, then before the retire_volume call load the volume and guard: `let volume = crate::repos::storage_
- [ ] **storage_array_get** [high] `sources/ryuki-api/src/contracts.rs:28335` — Add `AuthExtractor(session): AuthExtractor` to the storage_array_get signature (matching storage_array_register at contracts.rs:28363). After loading the row (`let array = ... .ok_

## secrets  (6)
- [x] **secrets_register** [high] `sources/ryuki-api/src/contracts.rs:29849` — Insert `guard_body_site_scope(&session, &b.site)?;` as the first statement of secrets_register, before the `if let Some(pool) = get_db()` at L29853. The (site) source is the reques
- [x] **secrets_get** [high] `sources/ryuki-api/src/contracts.rs:29919` — In sources/ryuki-api/src/contracts.rs, change secrets_get's signature from `async fn secrets_get(Path(id): Path<String>)` to `async fn secrets_get(AuthExtractor(session): AuthExtra
- [x] **secrets_update** [high] `sources/ryuki-api/src/contracts.rs:29969` — In secrets_update, after loading `existing` (L29982) and computing the effective `site` (L30001), add two guards before the tx at L30019 using guard_body_site_scope (defined L21033
- [x] **secrets_deregister** [high] `sources/ryuki-api/src/contracts.rs:30068` — By-id write -> guard the RETURNING row's site BEFORE commit, mapping out-of-scope to the same 404 a missing row produces (so it is not a cross-scope oracle), mirroring scope_guard_
- [x] **secrets_rotate** [high] `sources/ryuki-api/src/contracts.rs:30112` — After loading `secret` (immediately after the None->404 match, around contracts.rs:30129) and before the retired-status check, add: `scope_guard_or_404(&session, &secret.site, "", 
- [x] **secrets_rotation_fail** [high] `sources/ryuki-api/src/contracts.rs:30381` — In secrets_rotation_fail (contracts.rs:30381), after loading `run`/`failed` and BEFORE opening the tx (before L30407), load the parent secret's site from managed_secrets and guard 

## sql_deploy  (6)
- [x] **sql_deploy_plan** [high] `sources/ryuki-api/src/contracts.rs:31177` — Add the canonical site-only body guard as the FIRST statement of sql_deploy_plan, before get_db()/plan_deployment/insert: `guard_body_site_scope(&session, &body.site)?;` at contrac
- [x] **sql_deploy_install** [high] `sources/ryuki-api/src/contracts.rs:31263` — In sql_deploy_install, insert a scope guard immediately after the deployment is loaded — between `.ok_or_else(|| status_404(&id))?` (contracts.rs:31271) and the guard_install call 
- [x] **sql_deploy_configure** [high] `sources/ryuki-api/src/contracts.rs:31306` — After loading the deployment at contracts.rs:31314 and BEFORE the transition at :31317, insert: `scope_guard_or_404(&session, &deployment.site, "", &id)?;`. (site,env) source = the
- [x] **sql_deploy_verify** [high] `sources/ryuki-api/src/contracts.rs:31349` — In sql_deploy_verify, immediately after the deployment is loaded (after contracts.rs:31357 `.ok_or_else(|| status_404(&id))?`) and BEFORE guard_verify / the transaction, insert: `s
- [x] **sql_deploy_backup** [high] `sources/ryuki-api/src/contracts.rs:31392` — Insert a by-id scope guard immediately after the deployment is loaded and before guard_backup, at contracts.rs:31401:      scope_guard_or_404(&session, &deployment.site, "", &id)?;
- [x] **sql_deploy_monitoring** [high] `sources/ryuki-api/src/contracts.rs:31435` — Add `AuthExtractor(session): AuthExtractor,` as the first extractor in the sql_deploy_monitoring signature (mirroring sql_deploy_install at contracts.rs:31264). Then, immediately a

## shares  (5)
- [x] **shares_get** [high] `sources/ryuki-api/src/contracts.rs:4718` — Add `AuthExtractor(session): AuthExtractor` as the first handler parameter (the route is GET so the extractor composes fine), then guard after loading the share but before loading 
- [x] **shares_recertify** [high] `sources/ryuki-api/src/contracts.rs:4748` — Add `AuthExtractor(session): AuthExtractor` as the first handler argument, then immediately after `current` is loaded (right after line 4760) insert `scope_guard_or_404(&session, &
- [x] **shares_open_access** [high] `sources/ryuki-api/src/contracts.rs:4784` — 
- [x] **shares_permission_report** [high] `sources/ryuki-api/src/contracts.rs:4818` — 1) Add AuthExtractor to the handler: change the signature to `async fn shares_permission_report(AuthExtractor(session): AuthExtractor, Path(id): Path<String>) -> ApiResult`. 2) Aft
- [x] **shares_revoke** [high] `sources/ryuki-api/src/contracts.rs:4834` — In shares_revoke (contracts.rs:4834), after obtaining `pool` (line 4838) and before the revoke_permission DELETE (line 4840), load the parent share and guard by its site: `let shar

## degradation  (5)
- [ ] **degradation_enter** [high] `sources/ryuki-api/src/contracts.rs:7507` — Add a site-scope write guard at the top of degradation_enter (contracts.rs:7507), BEFORE pool.begin()/the repos::degradation::enter DB write. The (site,env) source is Path(site) ch
- [ ] **degradation_exit** [high] `sources/ryuki-api/src/contracts.rs:7537` — Add `guard_body_site_scope(&session, &site)?;` (helper defined at contracts.rs:21033) as the FIRST statement in degradation_exit, before `if let Some(pool) = get_db()` (i.e. right 
- [ ] **degradation_check** [medium] `sources/ryuki-api/src/contracts.rs:7451` — Add AuthExtractor to the handler and a by-id scope guard before returning. Change signature to `async fn degradation_check(AuthExtractor(session): AuthExtractor, Path(site): Path<S
- [ ] **degradation_global** [medium] `sources/ryuki-api/src/contracts.rs:7467` — Add `AuthExtractor(session): AuthExtractor` to degradation_global's signature, then before aggregating filter the loaded Vec<SiteStatus> to the principal's scope: `let scoped = ret
- [ ] **degradation_degraded** [medium] `sources/ryuki-api/src/contracts.rs:7484` — 1) Add `AuthExtractor(session): AuthExtractor` as the first handler parameter: `async fn degradation_degraded(AuthExtractor(session): AuthExtractor) -> Json<Value>`. 2) Scope the r

## maintenance  (5)
- [ ] **maintenance_calendar_conflicts** [high] `sources/ryuki-api/src/contracts.rs:7873` — Add `AuthExtractor(session): AuthExtractor` as the first extractor param and change the return type to ApiResult. Before the DB read, replace direct binding of the caller-supplied 
- [ ] **maintenance_calendar_upcoming** [high] `sources/ryuki-api/src/contracts.rs:7898` — Add `Extension(session): Extension<AuthSession>` to the handler signature, then replace the direct `q.site` bind with the canonical query-param helper: `let site = enforce_site_sco
- [ ] **maintenance_calendar_active** [high] `sources/ryuki-api/src/contracts.rs:7919` — Add `Extension(session): Extension<AuthSession>` to the maintenance_calendar_active signature, then before the DB read at contracts.rs:7920 compute the effective site via the exist
- [ ] **maintenance_calendar_month** [high] `sources/ryuki-api/src/contracts.rs:7937` — Add a session to the handler signature and narrow the site before the DB read. Change `async fn maintenance_calendar_month(Query(q): Query<MaintenanceCalendarMonthQuery>)` to also 
- [ ] **maintenance_calendar_cancel** [high] `sources/ryuki-api/src/contracts.rs:7992` — Resource is site-only (no environment axis) and the row is already loaded by the pre-SELECT, so use the post-load site guard. Right before `let mut tx = pool.begin()` (line 8022), 

## zabbix  (5)
- [ ] **zabbix_drift_summary** [high] `sources/ryuki-api/src/contracts.rs:9727` — Add `AuthExtractor(session): AuthExtractor` as the first extractor param of zabbix_drift_summary, then replace `let site = query.site.unwrap_or_else(|| "DEFRA".to_string());` with 
- [ ] **zabbix_drift_plan** [high] `sources/ryuki-api/src/contracts.rs:9758` — Add `AuthExtractor(session): AuthExtractor` to the handler signature, then AFTER loading the report and BEFORE the transition, enforce site scope using the row's loaded site. Since
- [ ] **zabbix_drift_validate** [high] `sources/ryuki-api/src/contracts.rs:9779` — Add AuthSession + the canonical by-id post-load guard. Change the signature to `async fn zabbix_drift_validate(AuthExtractor(session): AuthExtractor, Path(drift_id): Path<String>)`
- [ ] **zabbix_drift_execute** [high] `sources/ryuki-api/src/contracts.rs:9800` — Add a session arg to the handler: `async fn zabbix_drift_execute(session: AuthSession, Path(drift_id): Path<String>)`. After loading the report (contracts.rs:9805), before execute_
- [ ] **zabbix_drift_verify** [high] `sources/ryuki-api/src/contracts.rs:9822` — Change the signature to take the session: `async fn zabbix_drift_verify(session: AuthSession, Path(drift_id): Path<String>)`. After the report is fetched (contracts.rs:9824-9827) a

## firmware  (5)
- [ ] **firmware_device_get / firmware_check_compliance** [high] `sources/ryuki-api/src/contracts.rs:25619` — Inject AuthExtractor(session): AuthExtractor into both handlers and guard the loaded row by site before returning/mutating, mirroring sibling firmware_devices_list. (site,env) sour
- [ ] **firmware_noncompliant / firmware_eol / firmware_compliance_report / firmware_vendor_summary** [high] `sources/ryuki-api/src/contracts.rs:25664` — For all four handlers, thread the session in and apply per-row scoping before returning/aggregating. Concretely:  1. Add `Extension(session): Extension<AuthSession>` to each handle
- [ ] **firmware_request_exception** [high] `sources/ryuki-api/src/contracts.rs:25700` — In firmware_request_exception (contracts.rs:25700), after acquiring `pool` and BEFORE calling request_exception, load the device and scope-guard it. Concretely: `let device = crate
- [ ] **firmware_revoke_exception** [medium] `sources/ryuki-api/src/contracts.rs:25749` — Add Extension(session): Extension<AuthSession> to firmware_revoke_exception's signature, then enforce the device's site BEFORE the revoke commits. The (site,env) source is the devi
- [ ] **firmware_exceptions_list** [medium] `sources/ryuki-api/src/contracts.rs:25731` — Two coordinated changes. (1) Repo: change list_active_exceptions(pool) in sources/ryuki-api/src/repos/firmware_lifecycle.rs:194 to accept a `site: &str` (mirroring list_devices at 

## k8s  (5)
- [ ] **k8s_namespace_get** [high] `sources/ryuki-api/src/contracts.rs:28690` — 1) Add the session to the handler signature: change `Path(id): Path<String>,` to also take `AuthExtractor(session): AuthExtractor,` first, matching sibling handlers like k8s_namesp
- [ ] **k8s_namespace_update_quota** [high] `sources/ryuki-api/src/contracts.rs:28702` — The repo already returns the full row's site+environment. Capture the model and guard AFTER the update, BEFORE commit/return: in k8s_namespace_update_quota, on `TransitionOutcome::
- [ ] **k8s_namespace_suspend** [high] `sources/ryuki-api/src/contracts.rs:28749` — Add a by-id scope guard BEFORE the mutation. Load the namespace's site first via the existing repo read (repos/container_namespace.rs:253 `SELECT {NS_COLUMNS} FROM k8s_namespaces W
- [ ] **k8s_namespace_resume** [high] `sources/ryuki-api/src/contracts.rs:28792` — Add a post-load by-id scope guard after the UPDATE returns the row but BEFORE commit, and roll back if out of scope so the mutation is never persisted. After `let ns = match outcom
- [ ] **k8s_namespace_terminate** [high] `sources/ryuki-api/src/contracts.rs:28835` — The handler already loads the row as `ns` (TransitionOutcome::Updated(ns), L28853), and ns carries ns.site. Because the namespace has ONLY a site dimension (no environment), use a 

## compliance  (5)
- [ ] **compliance_control_get** [high] `sources/ryuki-api/src/contracts.rs:29381` — Add `AuthExtractor(session): AuthExtractor` (matching the sibling compliance_controls_list signature) to compliance_control_get at contracts.rs:29381. After loading `ctrl` (L29388-
- [ ] **compliance_control_assess** [high] `sources/ryuki-api/src/contracts.rs:29400` — By-id write whose row carries the authoritative `site` (compliance_controls.site). Two equivalent options, both sourcing (site) from the control row itself: (A) Post-load guard: be
- [ ] **compliance_report_get** [high] `sources/ryuki-api/src/contracts.rs:29484` — Add `AuthExtractor(session): AuthExtractor` to the handler signature, then guard by the loaded row's site BEFORE returning. The (site) source is the report itself: after `let repor
- [ ] **compliance_finding_resolve** [high] `sources/ryuki-api/src/contracts.rs:29533` — compliance_findings has no site column, so load the owning report's site via report_id before the write. Add a repo helper in repos/compliance_reporting.rs, e.g. finding_site(execu
- [ ] **compliance_finding_waive** [high] `sources/ryuki-api/src/contracts.rs:29571` — Before the DB mutation, load the finding's owning report site and scope-guard it. There is no existing helper for this, so add one to repos/compliance_reporting.rs, e.g. `pub async

## noise  (4)
- [ ] **noise_suppress** [high] `sources/ryuki-api/src/contracts.rs:10114` — Add a row-scope guard BEFORE the CAS UPDATE commits, since site is host-derived (no site/env input param to bind). Inside the `if let Some(pool) = get_db()` branch, after `parse_no
- [ ] **noise_report** [high] `sources/ryuki-api/src/contracts.rs:10243` — Add the session and enforce before the DB read, mirroring synthetic_run_all (10347-10352). 1) Change signature to `async fn noise_report(AuthExtractor(session): AuthExtractor, Quer
- [ ] **noise_suppressed_list** [high] `sources/ryuki-api/src/contracts.rs:10301` — Add `AuthExtractor(session): AuthExtractor` to the handler signature, then filter the returned rows per-row by the host-derived site before serializing — mirroring noise_report's c
- [ ] **noise_resolve** [medium] `sources/ryuki-api/src/contracts.rs:10191` — Helper: ryuki_engine::auth::scope_permits against the DERIVED site (there is no site column to bind, and enforce_scope_filters expects a real (site,env) — not applicable here). Sou

## vm_day2  (4)
- [ ] **vm_day2_plan** [high] `sources/ryuki-api/src/contracts.rs:20205` — 
- [ ] **vm_day2_validate** [high] `sources/ryuki-api/src/contracts.rs:20244` — Add `Extension(session): Extension<AuthSession>` to the vm_day2_validate signature (the auth middleware already injects it for sibling enforced handlers). Then immediately after lo
- [ ] **vm_day2_execute** [high] `sources/ryuki-api/src/contracts.rs:20285` — 
- [ ] **vm_day2_verify** [high] `sources/ryuki-api/src/contracts.rs:20317` — Add `AuthExtractor(session): AuthExtractor` as the first param of vm_day2_verify (contracts.rs:20317). After the op is loaded (after line 20323, before the status check at 20326), 

## oob  (4)
- [ ] **oob_inventory / oob_failing** [high] `sources/ryuki-api/src/contracts.rs:22900` — 
- [ ] **oob_cert_expiring / oob_firmware_outdated** [high] `sources/ryuki-api/src/contracts.rs:22990` — Add `session: AuthSession` (AuthExtractor) to both handler signatures, then filter rows by scope BEFORE building JSON using the existing per-row helper. (site,env) source = the pri
- [ ] **oob_validate_site** [high] `sources/ryuki-api/src/contracts.rs:23087` — Add `AuthExtractor(session): AuthExtractor,` as the first param of oob_validate_site (mirroring oob_test_endpoint at 22762). Then inside `if let Some(pool) = get_db()` and BEFORE t
- [ ] **oob_test_endpoint / oob_validate_cert / oob_check_defaults** [high] `sources/ryuki-api/src/contracts.rs:22761` — For oob_validate_cert and oob_check_defaults: add `AuthExtractor(session): AuthExtractor` to the signature, and after the `row.ok_or_else(...)?` unwrap call `scope_guard_or_404(&se

## image_factory  (4)
- [ ] **image_factory_initiate_build / image_factory_schedule_monthly** [high] `sources/ryuki-api/src/contracts.rs:24616` — Add `AuthExtractor(session): AuthExtractor` as the first extractor param to both handlers, then call `guard_body_site_scope(&session, &body.site)?` (defined contracts.rs:21033) bef
- [ ] **image_factory_run_tests / image_factory_promote / image_factory_reject** [high] `sources/ryuki-api/src/contracts.rs:24644` — These by-id handlers cannot use enforce_site_scope (no ?site param). Add an AuthSession/AuthExtractor extractor to each handler signature (mirroring enforced siblings around :14346
- [ ] **image_factory_active / image_factory_history** [high] `sources/ryuki-api/src/contracts.rs:24706` — 
- [ ] **image_factory_superseded** [high] `sources/ryuki-api/src/contracts.rs:24754` — Add an AuthSession extractor to the handler and narrow the rows in-handler before returning, keyed on the model's site_scope field, using the existing helper retain_site_scoped (co

## runbook  (4)
- [ ] **runbook_start** [high] `sources/ryuki-api/src/contracts.rs:25250` — In runbook_start (contracts.rs:25250), insert `guard_body_site_scope(&session, &body.site)?;` BEFORE the build_execution/insert call — right after `let pool = get_db()...?;` at lin
- [ ] **runbook_get_execution** [high] `sources/ryuki-api/src/contracts.rs:25287` — Add the session to the signature and a post-load site scope guard before returning, mirroring scope_guard_or_404 usage elsewhere and the sibling list handler's site-only scoping. C
- [ ] **runbook_execute_step / runbook_approve / runbook_complete / runbook_fail / runbook_rollback** [high] `sources/ryuki-api/src/contracts.rs:25299` — 
- [ ] **runbook_active** [high] `sources/ryuki-api/src/contracts.rs:25520` — 

## access_review  (4)
- [ ] **access_review_get** [high] `sources/ryuki-api/src/contracts.rs:26197` — In access_review_get (contracts.rs:26197), add the session extractor to the signature: `async fn access_review_get(Path(id): Path<String>, AuthExtractor(session): AuthExtractor)` (
- [ ] **access_review_start / access_review_approve / access_review_revoke / access_review_exempt** [high] `sources/ryuki-api/src/contracts.rs:26238` — 
- [ ] **access_review_summary** [medium] `sources/ryuki-api/src/contracts.rs:26373` — 
- [ ] **access_reviews_due / access_reviews_expiring** [?] `sources/ryuki-api/src/contracts.rs:26210` — Mirror the enforcement the sibling access_reviews_list already uses, but since list_due/list_expiring don't take a site param, enforce per-row after the DB read. Concretely: (a) ad

## network  (3)
- [ ] **network_readiness_check / network_capacity / network_ports_inventory / network_vlans_inventory** [high] `sources/ryuki-api/src/contracts.rs:22489` — Add `AuthExtractor(session): AuthExtractor` to each of the four handler signatures, then replace the fixed-default unwrap with the effective in-scope site. For network_readiness_ch
- [ ] **network_reserve_ports / network_reserve_ips** [high] `sources/ryuki-api/src/contracts.rs:22526` — Apply the canonical site-only WRITE pattern to BOTH handlers. 1) Add `AuthExtractor(session): AuthExtractor` as the first param of network_reserve_ports (contracts.rs:22526) and ne
- [ ] **network_release** [high] `sources/ryuki-api/src/contracts.rs:22575` — In network_release at sources/ryuki-api/src/contracts.rs, after `resv` is bound (after line 22592) and BEFORE tx.commit() (line 22605), insert `guard_body_site_scope(&session, &res

## outage  (3)
- [ ] **outage_notices_create** [high] `sources/ryuki-api/src/contracts.rs:24334` — Add `guard_body_site_scope(&session, &body.site)?;` in outage_notices_create immediately after `let pool = get_db().ok_or_else(status_503_no_db)?;` (contracts.rs:24338), before bui
- [ ] **outage_notices_send / outage_notices_acknowledge / outage_notices_complete / outage_notices_cancel** [high] `sources/ryuki-api/src/contracts.rs:24405` — Add `guard_body_site_scope(&session, &notice.site)?;` immediately after the notice is loaded and BEFORE the lifecycle guard / tx in each of the four handlers — mirroring outage_not
- [ ] **outage_notices_active / outage_notices_history / outage_notices_upcoming** [high] `sources/ryuki-api/src/contracts.rs:24559` — Add `session: AuthSession` (AuthExtractor) as a parameter to each of the three handlers, then before the DB call resolve the effective site: `let site = enforce_site_scope(&session

## synthetic  (2)
- [ ] **synthetic_run_check** [high] `sources/ryuki-api/src/contracts.rs:10329` — Add `AuthExtractor(session): AuthExtractor` to the synthetic_run_check signature (contracts.rs:10329). After loading the check (after line 10334) and BEFORE run_check/insert_result
- [ ] **synthetic_status** [medium] `sources/ryuki-api/src/contracts.rs:10371` — Add `AuthExtractor(session): AuthExtractor` to the handler signature. Since check_results carries no site column, load the parent check to obtain its site: `let check = crate::repo

## metrics_budget  (2)
- [ ] **metrics_budget_update** [high] `sources/ryuki-api/src/contracts.rs:19569` — In metrics_budget_update (contracts.rs:19569), after opening the transaction (after line 19600) and BEFORE the UPDATE, load the row scope and guard: let existing: Option<(Option<St
- [ ] **metrics_budget_delete** [?] `sources/ryuki-api/src/contracts.rs:19640` — Load the row's scope first, then guard before the DELETE. Inside the existing tx (after pool.begin()), add: let row: Option<(Option<String>, Option<String>)> = sqlx::query_as("SELE

## slo  (2)
- [ ] **slo_update** [high] `sources/ryuki-api/src/contracts.rs:19683` — After loading the row but BEFORE applying the UPDATE, add a by-id scope guard. Concretely: change the UPDATE to first read the target's (site, environment) — either a `SELECT site,
- [ ] **slo_delete** [high] `sources/ryuki-api/src/contracts.rs:19754` — Before the DELETE, load the row's scope and gate with the canonical pattern. Because slo_definitions.site/environment are NULLABLE (platform-wide rows must stay deletable by any in

## decommission  (2)
- [ ] **decommission_plan** [high] `sources/ryuki-api/src/contracts.rs:21147` — Add `guard_body_site_scope(&session, &body.site)?;` as the first statement of decommission_plan in sources/ryuki-api/src/contracts.rs (immediately after the fn opens at line 21150,
- [ ] **decommission_approve / decommission_quarantine / decommission_execute / decommission_verify / decommission_rollback / decommission_get / decommission_quarantine_inventory** [high] `sources/ryuki-api/src/contracts.rs:21220-21437` — By-id handlers (approve after 21229, quarantine after 21275, execute after 21319, verify after 21359, rollback after 21377, get at 21430): immediately after `let req = repos::decom

## linux_deploy  (2)
- [ ] **linux_deploy_plan** [high] `sources/ryuki-api/src/contracts.rs:21481` — Insert the canonical site-only WRITE guard at the top of linux_deploy_plan, immediately after `let pool = get_db()...?;` (contracts.rs:21485) and BEFORE plan_linux_deployment/inser
- [ ] **linux_deploy_validate / linux_deploy_execute / linux_deploy_verify** [high] `sources/ryuki-api/src/contracts.rs:21529` — Insert guard_body_site_scope(&session, &req.site)?; in each handler immediately after the load line that yields req (right after .ok_or_else(|| status_404(&body.operation_id))? at 

## approvals  (1)
- [ ] **approvals_pending** [high] `sources/ryuki-api/src/contracts.rs:3980` — Mirror the sibling requests_list pattern. After computing `role` (3987), derive the effective scope filters and push them into the SQL as bound params:    let (f_site, f_env) = enf

## software  (1)
- [ ] **software_compliance** [high] `sources/ryuki-api/src/contracts.rs:8763` — Add `AuthExtractor(session): AuthExtractor` as the first param of software_compliance (mirror software_packages_list at contracts.rs:8412-8414). Then, before the VALID_SITES check 

## aiops  (1)
- [ ] **aiops_review** [high] `sources/ryuki-api/src/contracts.rs:11898` — Add the sibling guard in aiops_review (sources/ryuki-api/src/contracts.rs) immediately after the suggestion is loaded and before the `guard_review` / `review` write, exactly mirror

## apply  (1)
- [ ] **apply_transition_audited** [high] `sources/ryuki-api/src/contracts.rs:13319` — Enforce scope inside the helper itself — it is the single chokepoint every transition flows through and it already holds `session` + `current.site`/`current.environment`. At the to

## backup  (1)
- [ ] **backup_restore_approve / backup_restore_execute / backup_restore_validate / backup_restores_list / backup_restore_get / backup_restore_plan** [high] `sources/ryuki-api/src/contracts.rs:20592` — By-id reads/actions (validate:20626, approve:20639, execute:20689, get:20753): after loading r (or record), add scope_guard_or_404(&session, &r.target_site, &r.target_environment, 

## repo_capacity  (1)
- [ ] **repo_capacity_forecast / repo_capacity_trend / repo_capacity_recommendations** [high] `sources/ryuki-api/src/contracts.rs:23936` — Add `AuthExtractor(session): AuthExtractor` as the first param to each handler, then guard on the LOADED row's site before returning, mirroring hardware_firmware_check (contracts.r

## firewall  (1)
- [ ] **firewall_rule_set_list** [high] `sources/ryuki-api/src/contracts.rs:27958` — Add `AuthExtractor(session): AuthExtractor` to the handler signature alongside Query(q) (mirror firewall_rule_set_get). For the ?site path, replace the bare list_by_site with `let 

## on_call  (3)
- [ ] **on_call_contact_create** [medium] `sources/ryuki-api/src/contracts.rs:17365` — 
- [ ] **on_call_contact_get** [medium] `sources/ryuki-api/src/contracts.rs:17445` — 1) Add AuthExtractor(session): AuthExtractor to the on_call_contact_get signature (contracts.rs:17445-17447). 2) After loading the row (the Some(r) arm at 17457), guard on the row'
- [ ] **on_call_contact_delete** [medium] `sources/ryuki-api/src/contracts.rs:17567` — In on_call_contact_delete (contracts.rs:17567), enforce site scope on the target row BEFORE the DELETE. on_call_contacts has no environment column, so use the site-only helper, NOT

## cancel  (1)
- [ ] **cancel_one (shared by requests_cancel / POST /requests/{id}/cancel and requests_batch_cancel / POST /requests/batch/cancel)** [medium] `sources/ryuki-api/src/contracts.rs:16276` — Add the post-load by-id guard using the already-loaded row values (no extra query). DB path: immediately after the cancel_permitted check (after line 16296), insert `scope_guard_or

## events  (1)
- [ ] **events_alert_ack** [medium] `sources/ryuki-api/src/contracts.rs:17064` — Apply the canonical by-id guard before the mutation. Step 1: add a loader in sources/ryuki-api/src/repos/domain_events.rs, e.g. pub async fn event_site_env(pool, event_id: i64) -> 

## dr_  (1)
- [ ] **dr_tests_due** [medium] `sources/ryuki-api/src/contracts.rs:29243-29247` — Mirror the sibling handlers. In contracts.rs change the signature to `async fn dr_tests_due(AuthExtractor(session): AuthExtractor, Query(q): Query<DrSiteQuery>)`, then before the e
