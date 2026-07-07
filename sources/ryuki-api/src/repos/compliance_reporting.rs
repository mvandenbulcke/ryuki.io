//! Repository functions for compliance_reporting tables.
//!
//! # ID type
//! All tables use TEXT PKs bound/decoded as String.
//!
//! # Enum encoding
//! All 4 enums have #[serde(rename_all = "kebab-case")] so serde form is kebab
//! but DB CHECK values are PascalCase (from Display impl). Use match helpers for
//! both to_db and from_db — serde round-trip would produce wrong values.
//!   ControlStatus: Compliant|NonCompliant|NotApplicable (DB CHECK PascalCase)
//!   OverallStatus: Compliant|NonCompliant|AtRisk
//!   FindingSeverity: Critical|High|Medium|Low
//!   FindingStatus: Open|InProgress|Resolved|Waived
//!
//! # Integer discipline
//! compliant_controls / total_controls are usize in engine, INTEGER in DB.
//! Write: i32::try_from(usize) → Decode error on overflow (>2^31-1).
//! Read:  usize::try_from(i32) → Decode error on negative.
//! get_compliance_summary counts come from plain COUNT(*) — returns i64; cast to usize.
//!
//! # findings child table
//! ComplianceReport.findings is Vec<Finding>. Stored in compliance_findings with
//! report_id FK. Loaded via a separate query when loading a report.
//! generate_report: INSERT report + INSERT findings in ONE transaction.
//! resolve_finding / create_waiver: UPDATE compliance_findings.

use ryuki_engine::compliance_reporting::{
    ComplianceControl, ComplianceFramework, ComplianceReport, ControlStatus, Finding,
    FindingSeverity, FindingStatus, OverallStatus,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

// ─── Enum to_db helpers (PascalCase as stored in DB CHECK constraints) ────────

fn control_status_to_db(s: &ControlStatus) -> &'static str {
    match s {
        ControlStatus::Compliant => "Compliant",
        ControlStatus::NonCompliant => "NonCompliant",
        ControlStatus::NotApplicable => "NotApplicable",
    }
}

fn control_status_from_db(raw: &str) -> Result<ControlStatus, sqlx::Error> {
    match raw {
        "Compliant" => Ok(ControlStatus::Compliant),
        "NonCompliant" => Ok(ControlStatus::NonCompliant),
        "NotApplicable" => Ok(ControlStatus::NotApplicable),
        other => Err(sqlx::Error::Decode(
            format!("compliance_controls.status: unknown value '{other}'").into(),
        )),
    }
}

fn overall_status_to_db(s: &OverallStatus) -> &'static str {
    match s {
        OverallStatus::Compliant => "Compliant",
        OverallStatus::NonCompliant => "NonCompliant",
        OverallStatus::AtRisk => "AtRisk",
    }
}

fn overall_status_from_db(raw: &str) -> Result<OverallStatus, sqlx::Error> {
    match raw {
        "Compliant" => Ok(OverallStatus::Compliant),
        "NonCompliant" => Ok(OverallStatus::NonCompliant),
        "AtRisk" => Ok(OverallStatus::AtRisk),
        other => Err(sqlx::Error::Decode(
            format!("compliance_reports.overall_status: unknown value '{other}'").into(),
        )),
    }
}

fn severity_to_db(s: &FindingSeverity) -> &'static str {
    match s {
        FindingSeverity::Critical => "Critical",
        FindingSeverity::High => "High",
        FindingSeverity::Medium => "Medium",
        FindingSeverity::Low => "Low",
    }
}

fn severity_from_db(raw: &str) -> Result<FindingSeverity, sqlx::Error> {
    match raw {
        "Critical" => Ok(FindingSeverity::Critical),
        "High" => Ok(FindingSeverity::High),
        "Medium" => Ok(FindingSeverity::Medium),
        "Low" => Ok(FindingSeverity::Low),
        other => Err(sqlx::Error::Decode(
            format!("compliance_findings.severity: unknown value '{other}'").into(),
        )),
    }
}

fn finding_status_to_db(s: &FindingStatus) -> &'static str {
    match s {
        FindingStatus::Open => "Open",
        FindingStatus::InProgress => "InProgress",
        FindingStatus::Resolved => "Resolved",
        FindingStatus::Waived => "Waived",
    }
}

fn finding_status_from_db(raw: &str) -> Result<FindingStatus, sqlx::Error> {
    match raw {
        "Open" => Ok(FindingStatus::Open),
        "InProgress" => Ok(FindingStatus::InProgress),
        "Resolved" => Ok(FindingStatus::Resolved),
        "Waived" => Ok(FindingStatus::Waived),
        other => Err(sqlx::Error::Decode(
            format!("compliance_findings.status: unknown value '{other}'").into(),
        )),
    }
}

// ─── Row structs ─────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct FrameworkRow {
    id: String,
    name: String,
    version: String,
    last_assessed: String,
    next_assessment_due: String,
}

impl FrameworkRow {
    fn into_model(self) -> ComplianceFramework {
        ComplianceFramework {
            id: self.id,
            name: self.name,
            version: self.version,
            last_assessed: self.last_assessed,
            next_assessment_due: self.next_assessment_due,
        }
    }
}

#[derive(sqlx::FromRow)]
struct ControlRow {
    id: String,
    framework_id: String,
    control_id: String,
    title: String,
    description: String,
    status: String,
    evidence_ref: Option<String>,
    assessed_by: Option<String>,
    assessed_at: Option<String>,
    site: String,
}

impl ControlRow {
    fn into_model(self) -> Result<ComplianceControl, sqlx::Error> {
        let status = control_status_from_db(&self.status)?;
        Ok(ComplianceControl {
            id: self.id,
            framework_id: self.framework_id,
            control_id: self.control_id,
            title: self.title,
            description: self.description,
            status,
            evidence_ref: self.evidence_ref,
            assessed_by: self.assessed_by,
            assessed_at: self.assessed_at,
            site: self.site,
        })
    }
}

#[derive(sqlx::FromRow)]
struct ReportRow {
    id: String,
    framework_id: String,
    site: String,
    generated_at: String,
    overall_status: String,
    compliant_controls: i32,
    total_controls: i32,
}

impl ReportRow {
    fn into_model_with_findings(
        self,
        findings: Vec<Finding>,
    ) -> Result<ComplianceReport, sqlx::Error> {
        let overall_status = overall_status_from_db(&self.overall_status)?;
        let compliant_controls = usize::try_from(self.compliant_controls).map_err(|e| {
            sqlx::Error::Decode(
                format!("compliance_reports.compliant_controls negative: {e}").into(),
            )
        })?;
        let total_controls = usize::try_from(self.total_controls).map_err(|e| {
            sqlx::Error::Decode(format!("compliance_reports.total_controls negative: {e}").into())
        })?;
        Ok(ComplianceReport {
            id: self.id,
            framework_id: self.framework_id,
            site: self.site,
            generated_at: self.generated_at,
            overall_status,
            compliant_controls,
            total_controls,
            findings,
        })
    }
}

#[derive(sqlx::FromRow)]
struct FindingRow {
    id: String,
    report_id: String,
    control_id: String,
    severity: String,
    description: String,
    remediation: String,
    status: String,
}

impl FindingRow {
    fn into_model(self) -> Result<Finding, sqlx::Error> {
        let severity = severity_from_db(&self.severity)?;
        let status = finding_status_from_db(&self.status)?;
        Ok(Finding {
            id: self.id,
            control_id: self.control_id,
            severity,
            description: self.description,
            remediation: self.remediation,
            status,
        })
    }
}

// ─── Outcome types ────────────────────────────────────────────────────────────

pub enum AssessOutcome {
    Updated(Box<ComplianceControl>),
    NotFound,
}

pub enum MutationOutcome {
    Updated(Box<Finding>),
    NotFound,
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

async fn load_findings_for_report(
    pool: &PgPool,
    report_id: &str,
) -> Result<Vec<Finding>, sqlx::Error> {
    let rows: Vec<FindingRow> = sqlx::query_as(
        "SELECT id, report_id, control_id, severity, description, remediation, status \
         FROM compliance_findings WHERE report_id = $1 ORDER BY id",
    )
    .bind(report_id)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_model()).collect()
}

// ─── Framework functions ──────────────────────────────────────────────────────

pub async fn list_frameworks(pool: &PgPool) -> Result<Vec<ComplianceFramework>, sqlx::Error> {
    let rows: Vec<FrameworkRow> = sqlx::query_as(
        "SELECT id, name, version, last_assessed, next_assessment_due \
         FROM compliance_frameworks ORDER BY name",
    )
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| r.into_model()).collect())
}

pub async fn get_framework(
    pool: &PgPool,
    id: &str,
) -> Result<Option<ComplianceFramework>, sqlx::Error> {
    let row: Option<FrameworkRow> = sqlx::query_as(
        "SELECT id, name, version, last_assessed, next_assessment_due \
         FROM compliance_frameworks WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| r.into_model()))
}

// ─── Control functions ────────────────────────────────────────────────────────

pub async fn list_controls(
    pool: &PgPool,
    framework_id: &str,
    site: &str,
) -> Result<Vec<ComplianceControl>, sqlx::Error> {
    let rows: Vec<ControlRow> = match (framework_id.is_empty(), site.is_empty()) {
        (true, true) => {
            sqlx::query_as(
                "SELECT id, framework_id, control_id, title, description, status, \
              evidence_ref, assessed_by, assessed_at, site \
             FROM compliance_controls ORDER BY id",
            )
            .fetch_all(pool)
            .await?
        }
        (false, true) => {
            sqlx::query_as(
                "SELECT id, framework_id, control_id, title, description, status, \
              evidence_ref, assessed_by, assessed_at, site \
             FROM compliance_controls WHERE framework_id = $1 ORDER BY id",
            )
            .bind(framework_id)
            .fetch_all(pool)
            .await?
        }
        (true, false) => {
            sqlx::query_as(
                "SELECT id, framework_id, control_id, title, description, status, \
              evidence_ref, assessed_by, assessed_at, site \
             FROM compliance_controls WHERE site = $1 ORDER BY id",
            )
            .bind(site)
            .fetch_all(pool)
            .await?
        }
        (false, false) => {
            sqlx::query_as(
                "SELECT id, framework_id, control_id, title, description, status, \
              evidence_ref, assessed_by, assessed_at, site \
             FROM compliance_controls WHERE framework_id = $1 AND site = $2 ORDER BY id",
            )
            .bind(framework_id)
            .bind(site)
            .fetch_all(pool)
            .await?
        }
    };

    rows.into_iter().map(|r| r.into_model()).collect()
}

pub async fn get_control(
    pool: &PgPool,
    id: &str,
) -> Result<Option<ComplianceControl>, sqlx::Error> {
    let row: Option<ControlRow> = sqlx::query_as(
        "SELECT id, framework_id, control_id, title, description, status, \
          evidence_ref, assessed_by, assessed_at, site \
         FROM compliance_controls WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    row.map(|r| r.into_model()).transpose()
}

/// Read ONE compliance finding by id (the read-by-id companion to `list_findings`
/// and `resolve_finding`/`waive_finding`). `None` when missing. The caller scopes on
/// the parent report's site (findings have no own site column), mirroring the resolve
/// path — kept out of this query so the repo fn stays scope-agnostic.
pub async fn get_finding(pool: &PgPool, id: &str) -> Result<Option<Finding>, sqlx::Error> {
    let row: Option<FindingRow> = sqlx::query_as(
        "SELECT f.id, f.report_id, f.control_id, f.severity, f.description, f.remediation, \
                f.status \
         FROM compliance_findings f WHERE f.id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    row.map(|r| r.into_model()).transpose()
}

/// Atomically assess a control — UPDATE...RETURNING in one round-trip.
pub async fn assess_control(
    pool: &PgPool,
    control_id: &str,
    status: &ControlStatus,
    assessed_by: &str,
    evidence_ref: &str,
) -> Result<AssessOutcome, sqlx::Error> {
    let assessed_at = chrono::Utc::now().to_rfc3339();
    let row: Option<ControlRow> = sqlx::query_as(
        "UPDATE compliance_controls \
         SET status = $1, evidence_ref = $2, assessed_by = $3, assessed_at = $4, updated_at = NOW() \
         WHERE id = $5 \
         RETURNING id, framework_id, control_id, title, description, status, \
                   evidence_ref, assessed_by, assessed_at, site",
    )
    .bind(control_status_to_db(status))
    .bind(evidence_ref)
    .bind(assessed_by)
    .bind(&assessed_at)
    .bind(control_id)
    .fetch_optional(pool)
    .await?;

    match row {
        None => Ok(AssessOutcome::NotFound),
        Some(r) => Ok(AssessOutcome::Updated(Box::new(r.into_model()?))),
    }
}

// ─── Report functions ─────────────────────────────────────────────────────────

/// Generate a compliance report for a framework+site.
/// Caller must pre-load and pass the controls slice.
/// Inserts report + findings in a single transaction.
pub async fn generate_report(
    pool: &PgPool,
    framework_id: &str,
    site: &str,
    controls: &[ComplianceControl],
) -> Result<ComplianceReport, sqlx::Error> {
    use ryuki_engine::compliance_reporting::summarize_controls;

    let (compliant, total, overall_status) = summarize_controls(controls);

    let compliant_i32 = i32::try_from(compliant)
        .map_err(|e| sqlx::Error::Decode(format!("compliant_controls overflow: {e}").into()))?;
    let total_i32 = i32::try_from(total)
        .map_err(|e| sqlx::Error::Decode(format!("total_controls overflow: {e}").into()))?;

    // Full UUID (not an 8-hex prefix) so a generated id can't birthday-collide
    // with the report PK and surface as a 500.
    let report_id = format!(
        "cr-{}-{}-{}",
        site.to_lowercase(),
        framework_id.trim_start_matches("cf-"),
        Uuid::new_v4()
    );
    let generated_at = chrono::Utc::now().to_rfc3339();

    let findings: Vec<Finding> = controls
        .iter()
        .filter(|c| c.status == ControlStatus::NonCompliant)
        .map(|c| Finding {
            id: format!("cr-find-{}", Uuid::new_v4()),
            control_id: c.id.clone(),
            severity: FindingSeverity::High,
            description: format!("Control {} is non-compliant at {}", c.control_id, site),
            remediation: "Review control evidence, remediate the gap, and reassess the control."
                .into(),
            status: FindingStatus::Open,
        })
        .collect();

    let mut tx = pool.begin().await?;

    sqlx::query(
        "INSERT INTO compliance_reports \
         (id, framework_id, site, generated_at, overall_status, compliant_controls, total_controls) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(&report_id)
    .bind(framework_id)
    .bind(site)
    .bind(&generated_at)
    .bind(overall_status_to_db(&overall_status))
    .bind(compliant_i32)
    .bind(total_i32)
    .execute(&mut *tx)
    .await?;

    for finding in &findings {
        sqlx::query(
            "INSERT INTO compliance_findings \
             (id, report_id, control_id, severity, description, remediation, status) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(&finding.id)
        .bind(&report_id)
        .bind(&finding.control_id)
        .bind(severity_to_db(&finding.severity))
        .bind(&finding.description)
        .bind(&finding.remediation)
        .bind(finding_status_to_db(&finding.status))
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    Ok(ComplianceReport {
        id: report_id,
        framework_id: framework_id.to_string(),
        site: site.to_string(),
        generated_at,
        overall_status,
        compliant_controls: compliant,
        total_controls: total,
        findings,
    })
}

pub async fn get_report(pool: &PgPool, id: &str) -> Result<Option<ComplianceReport>, sqlx::Error> {
    let row: Option<ReportRow> = sqlx::query_as(
        "SELECT id, framework_id, site, generated_at, overall_status, \
          compliant_controls, total_controls \
         FROM compliance_reports WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    let Some(row) = row else { return Ok(None) };
    let findings = load_findings_for_report(pool, &row.id).await?;
    Ok(Some(row.into_model_with_findings(findings)?))
}

/// List all reports with their findings, optionally filtered by site.
#[allow(dead_code)]
pub async fn list_reports(pool: &PgPool, site: &str) -> Result<Vec<ComplianceReport>, sqlx::Error> {
    let rows: Vec<ReportRow> = if site.is_empty() {
        sqlx::query_as(
            "SELECT id, framework_id, site, generated_at, overall_status, \
              compliant_controls, total_controls \
             FROM compliance_reports ORDER BY generated_at DESC",
        )
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as(
            "SELECT id, framework_id, site, generated_at, overall_status, \
              compliant_controls, total_controls \
             FROM compliance_reports WHERE site = $1 ORDER BY generated_at DESC",
        )
        .bind(site)
        .fetch_all(pool)
        .await?
    };

    let mut reports = Vec::with_capacity(rows.len());
    for row in rows {
        let findings = load_findings_for_report(pool, &row.id).await?;
        reports.push(row.into_model_with_findings(findings)?);
    }
    Ok(reports)
}

// ─── Finding functions ────────────────────────────────────────────────────────

/// List findings with report context, filtered by site and/or severity.
pub async fn list_findings(
    pool: &PgPool,
    site: &str,
    severity: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<Value>, sqlx::Error> {
    // JOIN findings with reports to include site/framework_id context. Bounded to
    // one LIMIT/OFFSET page (#14); `ORDER BY f.id` is the finding PK, a unique
    // tie-breaker, so paging is stable.
    let rows: Vec<FindingRow> = match (site.is_empty(), severity.is_empty()) {
        (true, true) => sqlx::query_as(
            "SELECT f.id, f.report_id, f.control_id, f.severity, f.description, f.remediation, f.status \
             FROM compliance_findings f \
             JOIN compliance_reports r ON r.id = f.report_id \
             ORDER BY f.id LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?,
        (false, true) => sqlx::query_as(
            "SELECT f.id, f.report_id, f.control_id, f.severity, f.description, f.remediation, f.status \
             FROM compliance_findings f \
             JOIN compliance_reports r ON r.id = f.report_id \
             WHERE r.site = $1 \
             ORDER BY f.id LIMIT $2 OFFSET $3",
        )
        .bind(site)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?,
        (true, false) => sqlx::query_as(
            "SELECT f.id, f.report_id, f.control_id, f.severity, f.description, f.remediation, f.status \
             FROM compliance_findings f \
             JOIN compliance_reports r ON r.id = f.report_id \
             WHERE f.severity = $1 \
             ORDER BY f.id LIMIT $2 OFFSET $3",
        )
        .bind(severity)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?,
        (false, false) => sqlx::query_as(
            "SELECT f.id, f.report_id, f.control_id, f.severity, f.description, f.remediation, f.status \
             FROM compliance_findings f \
             JOIN compliance_reports r ON r.id = f.report_id \
             WHERE r.site = $1 AND f.severity = $2 \
             ORDER BY f.id LIMIT $3 OFFSET $4",
        )
        .bind(site)
        .bind(severity)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?,
    };

    // We also need report context (framework_id, site) for the response envelope.
    // Re-query to include those columns — build the result with a separate lookup.
    // Simpler: use a second pass with the report_ids we have.
    // But to keep queries minimal: load report context in bulk.

    // Collect unique report_ids
    let report_ids: Vec<String> = {
        let mut ids: Vec<String> = rows.iter().map(|r| r.report_id.clone()).collect();
        ids.sort();
        ids.dedup();
        ids
    };

    // Load report metadata for context
    let mut report_meta: std::collections::HashMap<String, (String, String)> =
        std::collections::HashMap::new();
    for rid in &report_ids {
        let meta: Option<(String, String)> =
            sqlx::query_as("SELECT framework_id, site FROM compliance_reports WHERE id = $1")
                .bind(rid)
                .fetch_optional(pool)
                .await?;
        if let Some((fw, s)) = meta {
            report_meta.insert(rid.clone(), (fw, s));
        }
    }

    let mut result = Vec::with_capacity(rows.len());
    for row in rows {
        let (framework_id, report_site) =
            report_meta.get(&row.report_id).cloned().unwrap_or_default();
        let report_id = row.report_id.clone();
        let finding = row.into_model()?;
        result.push(json!({
            "report_id": report_id,
            "framework_id": framework_id,
            "site": report_site,
            "finding": finding
        }));
    }

    Ok(result)
}

/// Count findings (optionally site/severity-filtered) — the pagination total for
/// [`list_findings`], using the SAME JOIN + `WHERE` so the count matches the
/// paged set.
pub async fn count_findings(pool: &PgPool, site: &str, severity: &str) -> Result<i64, sqlx::Error> {
    let count: i64 = match (site.is_empty(), severity.is_empty()) {
        (true, true) => sqlx::query_scalar(
            "SELECT COUNT(*) FROM compliance_findings f \
             JOIN compliance_reports r ON r.id = f.report_id",
        )
        .fetch_one(pool)
        .await?,
        (false, true) => sqlx::query_scalar(
            "SELECT COUNT(*) FROM compliance_findings f \
             JOIN compliance_reports r ON r.id = f.report_id \
             WHERE r.site = $1",
        )
        .bind(site)
        .fetch_one(pool)
        .await?,
        (true, false) => sqlx::query_scalar(
            "SELECT COUNT(*) FROM compliance_findings f \
             JOIN compliance_reports r ON r.id = f.report_id \
             WHERE f.severity = $1",
        )
        .bind(severity)
        .fetch_one(pool)
        .await?,
        (false, false) => sqlx::query_scalar(
            "SELECT COUNT(*) FROM compliance_findings f \
             JOIN compliance_reports r ON r.id = f.report_id \
             WHERE r.site = $1 AND f.severity = $2",
        )
        .bind(site)
        .bind(severity)
        .fetch_one(pool)
        .await?,
    };
    Ok(count)
}

/// Atomically resolve a finding — UPDATE...RETURNING.
///
/// Accepts any `sqlx::PgExecutor` — pass `pool` for a standalone call, or
/// `&mut *tx` to share a transaction with an audit write.
pub async fn resolve_finding(
    executor: impl sqlx::PgExecutor<'_>,
    id: &str,
    resolution: &str,
) -> Result<MutationOutcome, sqlx::Error> {
    let row: Option<FindingRow> = sqlx::query_as(
        "UPDATE compliance_findings \
         SET status = 'Resolved', \
             remediation = remediation || $1, \
             updated_at = NOW() \
         WHERE id = $2 \
         RETURNING id, report_id, control_id, severity, description, remediation, status",
    )
    .bind(format!(" Resolution: {resolution}"))
    .bind(id)
    .fetch_optional(executor)
    .await?;

    match row {
        None => Ok(MutationOutcome::NotFound),
        Some(r) => Ok(MutationOutcome::Updated(Box::new(r.into_model()?))),
    }
}

/// Atomically create a waiver on a finding — UPDATE...RETURNING.
///
/// Accepts any `sqlx::PgExecutor` — pass `pool` for a standalone call, or
/// `&mut *tx` to share a transaction with an audit write.
pub async fn create_waiver(
    executor: impl sqlx::PgExecutor<'_>,
    finding_id: &str,
    reason: &str,
    approved_by: &str,
    expiry: &str,
) -> Result<MutationOutcome, sqlx::Error> {
    let remediation = format!("Waived until {expiry} by {approved_by}. Reason: {reason}");
    let row: Option<FindingRow> = sqlx::query_as(
        "UPDATE compliance_findings \
         SET status = 'Waived', \
             remediation = $1, \
             updated_at = NOW() \
         WHERE id = $2 \
         RETURNING id, report_id, control_id, severity, description, remediation, status",
    )
    .bind(&remediation)
    .bind(finding_id)
    .fetch_optional(executor)
    .await?;

    match row {
        None => Ok(MutationOutcome::NotFound),
        Some(r) => Ok(MutationOutcome::Updated(Box::new(r.into_model()?))),
    }
}

// ─── Summary ──────────────────────────────────────────────────────────────────

/// Compute per-framework compliance summary, optionally filtered by site.
pub async fn get_compliance_summary(pool: &PgPool, site: &str) -> Result<Vec<Value>, sqlx::Error> {
    use ryuki_engine::compliance_reporting::summarize_controls;

    // Load all frameworks
    let frameworks = list_frameworks(pool).await?;
    let mut result = Vec::new();

    for fw in &frameworks {
        // Load controls for this framework (+ optional site filter)
        let controls = list_controls(pool, &fw.id, site).await?;
        if controls.is_empty() {
            continue;
        }

        let (compliant_controls, total_controls, overall_status) = summarize_controls(&controls);

        // Count open findings (Open or InProgress) for this framework+site
        let open_findings: i64 = {
            let count: (i64,) = if site.is_empty() {
                sqlx::query_as(
                    "SELECT COUNT(*) FROM compliance_findings f \
                     JOIN compliance_reports r ON r.id = f.report_id \
                     WHERE r.framework_id = $1 \
                       AND f.status IN ('Open', 'InProgress')",
                )
                .bind(&fw.id)
                .fetch_one(pool)
                .await?
            } else {
                sqlx::query_as(
                    "SELECT COUNT(*) FROM compliance_findings f \
                     JOIN compliance_reports r ON r.id = f.report_id \
                     WHERE r.framework_id = $1 AND r.site = $2 \
                       AND f.status IN ('Open', 'InProgress')",
                )
                .bind(&fw.id)
                .bind(site)
                .fetch_one(pool)
                .await?
            };
            count.0
        };

        let open_findings_usize = usize::try_from(open_findings).unwrap_or(0);
        let pass_rate = if total_controls > 0 {
            (compliant_controls as f64 / total_controls as f64) * 100.0
        } else {
            0.0
        };

        result.push(json!({
            "framework_id": fw.id,
            "framework_name": fw.name,
            "site": site,
            "overall_status": overall_status,
            "compliant_controls": compliant_controls,
            "total_controls": total_controls,
            "pass_rate": pass_rate,
            "open_findings": open_findings_usize
        }));
    }

    Ok(result)
}

// ─── DB tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod compliance_reporting_db_tests {
    use super::*;

    async fn test_pool() -> Option<PgPool> {
        let url = match std::env::var("RYUKI_DATABASE_URL") {
            Ok(u) if !u.is_empty() => u,
            _ => {
                eprintln!("compliance_reporting_db_tests: RYUKI_DATABASE_URL not set — skipping");
                return None;
            }
        };
        let db = PgPool::connect(&url).await.expect("DB connection failed");
        crate::database::run_migrations(&db)
            .await
            .expect("migrations must apply");
        Some(db)
    }

    #[tokio::test]
    async fn test_list_frameworks() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let fws = list_frameworks(&pool)
            .await
            .expect("list_frameworks failed");
        assert!(
            fws.len() >= 3,
            "expected >=3 seeded frameworks, got {}",
            fws.len()
        );
    }

    #[tokio::test]
    async fn test_get_framework_by_id() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let fw = get_framework(&pool, "cf-pci-dss")
            .await
            .expect("get_framework failed")
            .expect("cf-pci-dss must exist");
        assert_eq!(fw.name, "PCI-DSS");
        assert_eq!(fw.version, "4.0");

        let absent = get_framework(&pool, "cf-does-not-exist")
            .await
            .expect("get_framework failed");
        assert!(absent.is_none());
    }

    #[tokio::test]
    async fn test_list_controls_all_and_filtered() {
        let Some(pool) = test_pool().await else {
            return;
        };

        let all = list_controls(&pool, "", "")
            .await
            .expect("list_controls failed");
        assert!(
            all.len() >= 15,
            "expected >=15 seeded controls, got {}",
            all.len()
        );

        let pci = list_controls(&pool, "cf-pci-dss", "")
            .await
            .expect("list_controls(pci) failed");
        assert!(
            pci.len() >= 5,
            "expected >=5 pci controls, got {}",
            pci.len()
        );

        let defra = list_controls(&pool, "", "DEFRA")
            .await
            .expect("list_controls(DEFRA) failed");
        assert!(
            defra.iter().any(|c| c.id == "cc-pci-001"),
            "cc-pci-001 must be in DEFRA controls"
        );
    }

    #[tokio::test]
    async fn test_get_control_by_id() {
        let Some(pool) = test_pool().await else {
            return;
        };

        let ctrl = get_control(&pool, "cc-pci-001")
            .await
            .expect("get_control failed")
            .expect("cc-pci-001 must exist");
        assert_eq!(ctrl.framework_id, "cf-pci-dss");
        assert_eq!(ctrl.status, ControlStatus::Compliant);

        let absent = get_control(&pool, "cc-does-not-exist")
            .await
            .expect("get_control failed");
        assert!(absent.is_none());
    }

    #[tokio::test]
    async fn test_enum_roundtrip_control_status() {
        let Some(pool) = test_pool().await else {
            return;
        };

        let c1 = get_control(&pool, "cc-pci-001").await.unwrap().unwrap();
        assert_eq!(c1.status, ControlStatus::Compliant);

        let c2 = get_control(&pool, "cc-pci-002").await.unwrap().unwrap();
        assert_eq!(c2.status, ControlStatus::NonCompliant);

        let c5 = get_control(&pool, "cc-soc2-005").await.unwrap().unwrap();
        assert_eq!(c5.status, ControlStatus::NotApplicable);
        // NotApplicable: evidence_ref, assessed_by, assessed_at should all be None
        assert!(c5.evidence_ref.is_none());
        assert!(c5.assessed_by.is_none());
        assert!(c5.assessed_at.is_none());
    }

    #[tokio::test]
    async fn test_enum_roundtrip_finding_status() {
        let Some(pool) = test_pool().await else {
            return;
        };

        let report = get_report(&pool, "cr-defra-pci-001")
            .await
            .unwrap()
            .expect("seed report must exist");

        let open = report
            .findings
            .iter()
            .find(|f| f.id == "cr-find-001")
            .expect("cr-find-001 must exist");
        assert_eq!(open.status, FindingStatus::Open);

        let in_progress = report
            .findings
            .iter()
            .find(|f| f.id == "cr-find-002")
            .expect("cr-find-002 must exist");
        assert_eq!(in_progress.status, FindingStatus::InProgress);
    }

    #[tokio::test]
    async fn test_enum_roundtrip_severity() {
        let Some(pool) = test_pool().await else {
            return;
        };

        let r1 = get_report(&pool, "cr-defra-pci-001")
            .await
            .unwrap()
            .unwrap();
        let r2 = get_report(&pool, "cr-gblon-soc2-001")
            .await
            .unwrap()
            .unwrap();

        let high = r1.findings.iter().find(|f| f.id == "cr-find-001").unwrap();
        assert_eq!(high.severity, FindingSeverity::High);

        let medium = r1.findings.iter().find(|f| f.id == "cr-find-002").unwrap();
        assert_eq!(medium.severity, FindingSeverity::Medium);

        let critical = r2.findings.iter().find(|f| f.id == "cr-find-003").unwrap();
        assert_eq!(critical.severity, FindingSeverity::Critical);

        let low = r2.findings.iter().find(|f| f.id == "cr-find-004").unwrap();
        assert_eq!(low.severity, FindingSeverity::Low);
    }

    #[tokio::test]
    async fn test_enum_roundtrip_overall_status() {
        let Some(pool) = test_pool().await else {
            return;
        };

        let r = get_report(&pool, "cr-defra-pci-001")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(r.overall_status, OverallStatus::NonCompliant);
    }

    #[tokio::test]
    async fn test_list_reports_with_findings() {
        let Some(pool) = test_pool().await else {
            return;
        };

        let reports = list_reports(&pool, "").await.expect("list_reports failed");
        assert!(
            reports.len() >= 2,
            "expected >=2 seeded reports, got {}",
            reports.len()
        );

        let r = get_report(&pool, "cr-defra-pci-001")
            .await
            .unwrap()
            .expect("seed report must exist");
        assert!(
            r.findings.len() >= 2,
            "expected >=2 findings on cr-defra-pci-001, got {}",
            r.findings.len()
        );
    }

    /// #14 pagination: `list_findings` bounds to a LIMIT/OFFSET page over the
    /// findings-JOIN-reports query, `count_findings` returns the full filtered
    /// total (SAME JOIN + WHERE), and the unique `ORDER BY f.id` keeps offset
    /// pages disjoint.
    #[tokio::test]
    async fn test_list_findings_pagination() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let total = count_findings(&pool, "", "").await.expect("count_findings");
        let all = list_findings(&pool, "", "", 1000, 0)
            .await
            .expect("list_findings all");
        assert_eq!(
            all.len() as i64,
            total,
            "#14: count_findings matches the full unpaged set"
        );
        assert!(total >= 3, "expected >=3 seeded findings, got {total}");

        // LIMIT bounds the page; OFFSET advances it disjointly (stable f.id).
        let page1 = list_findings(&pool, "", "", 2, 0)
            .await
            .expect("findings page1");
        let page2 = list_findings(&pool, "", "", 2, 2)
            .await
            .expect("findings page2");
        assert_eq!(page1.len(), 2, "LIMIT 2 bounds the first page");
        assert!(!page2.is_empty(), "second page continues (>=3 findings)");
        assert!(
            page2.iter().all(|v| !page1.contains(v)),
            "offset page is disjoint from the first (stable f.id order)"
        );

        // count is filtered by the SAME site predicate as the page.
        let defra_total = count_findings(&pool, "DEFRA", "")
            .await
            .expect("count DEFRA");
        let defra = list_findings(&pool, "DEFRA", "", 1000, 0)
            .await
            .expect("list DEFRA");
        assert_eq!(
            defra.len() as i64,
            defra_total,
            "#14: site-filtered count matches the site page"
        );
    }

    #[tokio::test]
    async fn test_get_report_child_findings_aggregation() {
        let Some(pool) = test_pool().await else {
            return;
        };

        let report = get_report(&pool, "cr-defra-pci-001")
            .await
            .unwrap()
            .expect("cr-defra-pci-001 must exist");
        assert!(
            report.findings.len() >= 2,
            "expected >=2 findings, got {}",
            report.findings.len()
        );
        assert!(
            report.findings.iter().any(|f| f.id == "cr-find-001"),
            "cr-find-001 must be in findings"
        );
    }

    #[tokio::test]
    async fn test_assess_control_updates_control() {
        let Some(pool) = test_pool().await else {
            return;
        };

        // Save original so we can restore
        let original = get_control(&pool, "cc-pci-002").await.unwrap().unwrap();

        // Assess → Compliant
        let outcome = assess_control(
            &pool,
            "cc-pci-002",
            &ControlStatus::Compliant,
            "test.auditor",
            "ev-test-001",
        )
        .await
        .expect("assess_control failed");

        match outcome {
            AssessOutcome::Updated(ctrl) => {
                assert_eq!(ctrl.status, ControlStatus::Compliant);
                assert_eq!(ctrl.assessed_by.as_deref(), Some("test.auditor"));
                assert_eq!(ctrl.evidence_ref.as_deref(), Some("ev-test-001"));
            }
            AssessOutcome::NotFound => panic!("cc-pci-002 must exist"),
        }

        // Verify DB was updated
        let updated = get_control(&pool, "cc-pci-002").await.unwrap().unwrap();
        assert_eq!(updated.status, ControlStatus::Compliant);

        // Restore original
        assess_control(
            &pool,
            "cc-pci-002",
            &original.status,
            original.assessed_by.as_deref().unwrap_or("static.auditor"),
            original.evidence_ref.as_deref().unwrap_or("ev-cc-pci-002"),
        )
        .await
        .expect("restore failed");

        // NotFound for absent
        let absent = assess_control(
            &pool,
            "cc-does-not-exist",
            &ControlStatus::Compliant,
            "a",
            "e",
        )
        .await
        .expect("assess_control failed");
        assert!(matches!(absent, AssessOutcome::NotFound));
    }

    #[tokio::test]
    async fn test_generate_report_inserts_report_and_findings_in_tx() {
        let Some(pool) = test_pool().await else {
            return;
        };

        let controls = list_controls(&pool, "cf-pci-dss", "DEFRA")
            .await
            .expect("list_controls failed");
        assert!(!controls.is_empty(), "need controls to generate report");

        let report = generate_report(&pool, "cf-pci-dss", "DEFRA", &controls)
            .await
            .expect("generate_report failed");

        // Verify report in DB
        let loaded = get_report(&pool, &report.id)
            .await
            .unwrap()
            .expect("generated report must be in DB");
        assert_eq!(loaded.framework_id, "cf-pci-dss");
        assert_eq!(loaded.site, "DEFRA");
        // usize types — confirm not panicked
        let _: usize = loaded.compliant_controls;
        let _: usize = loaded.total_controls;
        // cc-pci-002 is NonCompliant → at least 1 finding
        assert!(
            !loaded.findings.is_empty(),
            "NonCompliant cc-pci-002 must produce at least 1 finding"
        );

        // Cleanup
        sqlx::query("DELETE FROM compliance_reports WHERE id = $1")
            .bind(&report.id)
            .execute(&pool)
            .await
            .expect("cleanup failed");
    }

    #[tokio::test]
    async fn test_resolve_finding_updates_status() {
        let Some(pool) = test_pool().await else {
            return;
        };

        // Generate a transient report + finding to avoid mutating seed data
        let controls = list_controls(&pool, "cf-soc2", "GBLON")
            .await
            .expect("list_controls failed");
        let report = generate_report(&pool, "cf-soc2", "GBLON", &controls)
            .await
            .expect("generate_report failed");

        // Should have at least 1 finding (cc-soc2-003 is NonCompliant)
        assert!(
            !report.findings.is_empty(),
            "need at least 1 finding to resolve"
        );
        let finding_id = report.findings[0].id.clone();

        // Resolve it
        let outcome = resolve_finding(&pool, &finding_id, "Evidence attached")
            .await
            .expect("resolve_finding failed");
        match outcome {
            MutationOutcome::Updated(f) => {
                assert_eq!(f.status, FindingStatus::Resolved);
                assert!(
                    f.remediation.contains("Resolution:"),
                    "remediation must contain 'Resolution:'"
                );
                assert!(
                    f.remediation.contains("Evidence attached"),
                    "remediation must contain resolution text"
                );
            }
            MutationOutcome::NotFound => panic!("finding must exist"),
        }

        // NotFound for absent
        let absent = resolve_finding(&pool, "cr-find-does-not-exist", "x")
            .await
            .expect("resolve_finding failed");
        assert!(matches!(absent, MutationOutcome::NotFound));

        // Cleanup
        sqlx::query("DELETE FROM compliance_reports WHERE id = $1")
            .bind(&report.id)
            .execute(&pool)
            .await
            .expect("cleanup failed");
    }

    #[tokio::test]
    async fn test_create_waiver_updates_finding() {
        let Some(pool) = test_pool().await else {
            return;
        };

        // Generate a transient report
        let controls = list_controls(&pool, "cf-iso27001", "FRPAR")
            .await
            .expect("list_controls failed");
        let report = generate_report(&pool, "cf-iso27001", "FRPAR", &controls)
            .await
            .expect("generate_report failed");
        assert!(
            !report.findings.is_empty(),
            "need at least 1 finding to waive"
        );
        let finding_id = report.findings[0].id.clone();

        let outcome = create_waiver(
            &pool,
            &finding_id,
            "Compensating control approved",
            "risk.owner",
            "2027-12-31T23:59:59Z",
        )
        .await
        .expect("create_waiver failed");

        match outcome {
            MutationOutcome::Updated(f) => {
                assert_eq!(f.status, FindingStatus::Waived);
                assert!(
                    f.remediation.contains("Waived until"),
                    "remediation must contain 'Waived until'"
                );
                assert!(
                    f.remediation.contains("risk.owner"),
                    "remediation must contain approved_by"
                );
                assert!(
                    f.remediation.contains("Compensating control approved"),
                    "remediation must contain reason"
                );
            }
            MutationOutcome::NotFound => panic!("finding must exist"),
        }

        // NotFound for absent
        let absent = create_waiver(
            &pool,
            "cr-find-does-not-exist",
            "r",
            "a",
            "2027-01-01T00:00:00Z",
        )
        .await
        .expect("create_waiver failed");
        assert!(matches!(absent, MutationOutcome::NotFound));

        // Cleanup
        sqlx::query("DELETE FROM compliance_reports WHERE id = $1")
            .bind(&report.id)
            .execute(&pool)
            .await
            .expect("cleanup failed");
    }

    #[tokio::test]
    async fn test_get_compliance_summary_counts_and_no_numeric_trap() {
        let Some(pool) = test_pool().await else {
            return;
        };

        let summaries = get_compliance_summary(&pool, "DEFRA")
            .await
            .expect("get_compliance_summary failed");
        assert!(
            !summaries.is_empty(),
            "DEFRA must have at least one framework summary"
        );

        for s in &summaries {
            // Verify compliant_controls and total_controls are integers (usize)
            assert!(
                s["compliant_controls"].is_number(),
                "compliant_controls must be a number"
            );
            assert!(
                s["total_controls"].is_number(),
                "total_controls must be a number"
            );
            // Verify pass_rate is f64
            assert!(s["pass_rate"].is_number(), "pass_rate must be a number");
            // Verify open_findings is a number (usize cast)
            assert!(
                s["open_findings"].is_number(),
                "open_findings must be a number"
            );
            // Verify pass_rate is in [0, 100]
            let rate = s["pass_rate"].as_f64().unwrap();
            assert!(
                (0.0..=100.0).contains(&rate),
                "pass_rate {rate} out of range"
            );
        }

        // Must have pci-dss in DEFRA (controls cc-pci-001/002/003 are DEFRA)
        assert!(
            summaries.iter().any(|s| s["framework_id"] == "cf-pci-dss"),
            "cf-pci-dss must appear in DEFRA summary"
        );
    }
}
