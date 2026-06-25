use chrono::{Days, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{Mutex, OnceLock};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SecretType {
    ServiceAccount,
    DatabaseCredential,
    APIKey,
    SSLCertificate,
    SSHKey,
    Token,
}

impl std::fmt::Display for SecretType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecretType::ServiceAccount => write!(f, "ServiceAccount"),
            SecretType::DatabaseCredential => write!(f, "DatabaseCredential"),
            SecretType::APIKey => write!(f, "APIKey"),
            SecretType::SSLCertificate => write!(f, "SSLCertificate"),
            SecretType::SSHKey => write!(f, "SSHKey"),
            SecretType::Token => write!(f, "Token"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SecretStatus {
    Active,
    Expired,
    Rotating,
    Failed,
    /// Soft-retired (deregistered): the secret record and its rotation history are
    /// PRESERVED, but it no longer rotates (excluded from due/expiring/rotate-all,
    /// and a direct rotate is refused). DB form is `retired` (serde kebab-case).
    Retired,
}

impl std::fmt::Display for SecretStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecretStatus::Active => write!(f, "Active"),
            SecretStatus::Expired => write!(f, "Expired"),
            SecretStatus::Rotating => write!(f, "Rotating"),
            SecretStatus::Failed => write!(f, "Failed"),
            SecretStatus::Retired => write!(f, "Retired"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RotationStatus {
    Running,
    Completed,
    Failed,
}

impl std::fmt::Display for RotationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RotationStatus::Running => write!(f, "Running"),
            RotationStatus::Completed => write!(f, "Completed"),
            RotationStatus::Failed => write!(f, "Failed"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedSecret {
    pub id: String,
    pub name: String,
    pub secret_type: SecretType,
    pub vault_path: String,
    pub rotation_interval_days: u64,
    pub last_rotated: String,
    pub next_rotation_due: String,
    pub status: SecretStatus,
    pub owner: String,
    pub site: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationRun {
    pub id: String,
    pub secret_id: String,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub status: RotationStatus,
    pub rotated_by: String,
    pub new_version: Option<String>,
    pub error_message: Option<String>,
}

type SecretStore = (Vec<ManagedSecret>, Vec<RotationRun>);

static SECRET_STORE: OnceLock<Mutex<SecretStore>> = OnceLock::new();

fn secret_store() -> &'static Mutex<SecretStore> {
    SECRET_STORE.get_or_init(|| Mutex::new(seed_data()))
}

fn now_iso() -> String {
    Utc::now().to_rfc3339()
}

fn parse_iso_time(time: &str) -> Option<chrono::DateTime<Utc>> {
    chrono::DateTime::parse_from_rfc3339(time)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

pub fn parse_secret_type(secret_type: &str) -> Result<SecretType, String> {
    match secret_type {
        "ServiceAccount" | "service-account" | "service_account" => Ok(SecretType::ServiceAccount),
        "DatabaseCredential" | "database-credential" | "database_credential" => {
            Ok(SecretType::DatabaseCredential)
        }
        "APIKey" | "api-key" | "api_key" => Ok(SecretType::APIKey),
        "SSLCertificate" | "ssl-certificate" | "ssl_certificate" => Ok(SecretType::SSLCertificate),
        "SSHKey" | "ssh-key" | "ssh_key" => Ok(SecretType::SSHKey),
        "Token" | "token" => Ok(SecretType::Token),
        other => Err(format!(
            "Invalid secret_type: {}. Must be ServiceAccount, DatabaseCredential, APIKey, SSLCertificate, SSHKey, or Token",
            other
        )),
    }
}

fn seed_data() -> SecretStore {
    let now = Utc::now();
    let secrets = vec![
        ManagedSecret {
            id: "sr-defra-001".into(),
            name: "defra-api-deploy-token".into(),
            secret_type: SecretType::Token,
            vault_path: "kv/defra/app/deploy-token".into(),
            rotation_interval_days: 30,
            last_rotated: (now - Days::new(45)).to_rfc3339(),
            next_rotation_due: (now - Days::new(15)).to_rfc3339(),
            status: SecretStatus::Expired,
            owner: "platform.security".into(),
            site: "DEFRA".into(),
        },
        ManagedSecret {
            id: "sr-defra-002".into(),
            name: "defra-postgres-admin".into(),
            secret_type: SecretType::DatabaseCredential,
            vault_path: "database/defra/postgres/admin".into(),
            rotation_interval_days: 14,
            last_rotated: (now - Days::new(8)).to_rfc3339(),
            next_rotation_due: (now + Days::new(6)).to_rfc3339(),
            status: SecretStatus::Active,
            owner: "database.ops".into(),
            site: "DEFRA".into(),
        },
        ManagedSecret {
            id: "sr-defra-003".into(),
            name: "defra-ingress-cert".into(),
            secret_type: SecretType::SSLCertificate,
            vault_path: "pki/defra/ingress".into(),
            rotation_interval_days: 60,
            last_rotated: (now - Days::new(58)).to_rfc3339(),
            next_rotation_due: (now + Days::new(2)).to_rfc3339(),
            status: SecretStatus::Active,
            owner: "network.security".into(),
            site: "DEFRA".into(),
        },
        ManagedSecret {
            id: "sr-gblon-001".into(),
            name: "gblon-backup-service".into(),
            secret_type: SecretType::ServiceAccount,
            vault_path: "kv/gblon/backup/service-account".into(),
            rotation_interval_days: 30,
            last_rotated: (now - Days::new(31)).to_rfc3339(),
            next_rotation_due: (now - Days::new(1)).to_rfc3339(),
            status: SecretStatus::Active,
            owner: "backup.ops".into(),
            site: "GBLON".into(),
        },
        ManagedSecret {
            id: "sr-gblon-002".into(),
            name: "gblon-automation-api".into(),
            secret_type: SecretType::APIKey,
            vault_path: "kv/gblon/automation/api-key".into(),
            rotation_interval_days: 45,
            last_rotated: (now - Days::new(12)).to_rfc3339(),
            next_rotation_due: (now + Days::new(33)).to_rfc3339(),
            status: SecretStatus::Active,
            owner: "automation.ops".into(),
            site: "GBLON".into(),
        },
        ManagedSecret {
            id: "sr-gblon-003".into(),
            name: "gblon-breakglass-ssh".into(),
            secret_type: SecretType::SSHKey,
            vault_path: "ssh/gblon/breakglass".into(),
            rotation_interval_days: 90,
            last_rotated: (now - Days::new(92)).to_rfc3339(),
            next_rotation_due: (now - Days::new(2)).to_rfc3339(),
            status: SecretStatus::Failed,
            owner: "site.reliability".into(),
            site: "GBLON".into(),
        },
        ManagedSecret {
            id: "sr-frpar-001".into(),
            name: "frpar-monitoring-token".into(),
            secret_type: SecretType::Token,
            vault_path: "kv/frpar/monitoring/token".into(),
            rotation_interval_days: 30,
            last_rotated: (now - Days::new(18)).to_rfc3339(),
            next_rotation_due: (now + Days::new(12)).to_rfc3339(),
            status: SecretStatus::Active,
            owner: "observability.ops".into(),
            site: "FRPAR".into(),
        },
        ManagedSecret {
            id: "sr-frpar-002".into(),
            name: "frpar-vault-replication".into(),
            secret_type: SecretType::ServiceAccount,
            vault_path: "kv/frpar/vault/replication".into(),
            rotation_interval_days: 30,
            last_rotated: (now - Days::new(1)).to_rfc3339(),
            next_rotation_due: (now + Days::new(29)).to_rfc3339(),
            status: SecretStatus::Rotating,
            owner: "platform.security".into(),
            site: "FRPAR".into(),
        },
    ];

    let runs = vec![
        RotationRun {
            id: "rr-defra-001".into(),
            secret_id: "sr-defra-002".into(),
            started_at: (now - Days::new(8)).to_rfc3339(),
            completed_at: Some((now - Days::new(8) + chrono::Duration::minutes(3)).to_rfc3339()),
            status: RotationStatus::Completed,
            rotated_by: "alice.operator".into(),
            new_version: Some("v12".into()),
            error_message: None,
        },
        RotationRun {
            id: "rr-defra-002".into(),
            secret_id: "sr-defra-001".into(),
            started_at: (now - Days::new(15)).to_rfc3339(),
            completed_at: Some((now - Days::new(15) + chrono::Duration::minutes(1)).to_rfc3339()),
            status: RotationStatus::Failed,
            rotated_by: "vault-rotation-job".into(),
            new_version: None,
            error_message: Some("mock policy denied".into()),
        },
        RotationRun {
            id: "rr-gblon-001".into(),
            secret_id: "sr-gblon-001".into(),
            started_at: (now - Days::new(31)).to_rfc3339(),
            completed_at: Some((now - Days::new(31) + chrono::Duration::minutes(2)).to_rfc3339()),
            status: RotationStatus::Completed,
            rotated_by: "backup.ops".into(),
            new_version: Some("v7".into()),
            error_message: None,
        },
        RotationRun {
            id: "rr-frpar-001".into(),
            secret_id: "sr-frpar-002".into(),
            started_at: (now - chrono::Duration::minutes(45)).to_rfc3339(),
            completed_at: None,
            status: RotationStatus::Running,
            rotated_by: "platform.security".into(),
            new_version: None,
            error_message: None,
        },
    ];

    (secrets, runs)
}

pub fn list_secrets(site: &str, secret_type: &str) -> Result<Value, String> {
    let parsed_type = if secret_type.trim().is_empty() {
        None
    } else {
        Some(parse_secret_type(secret_type)?)
    };
    let store = secret_store().lock().unwrap();
    let secrets: Vec<ManagedSecret> = store
        .0
        .iter()
        .filter(|secret| site.is_empty() || secret.site == site)
        .filter(|secret| {
            parsed_type
                .as_ref()
                .is_none_or(|secret_type| &secret.secret_type == secret_type)
        })
        .cloned()
        .collect();

    Ok(json!({
        "source": "static-seed",
        "dry_run": true,
        "count": secrets.len(),
        "secrets": secrets
    }))
}

pub fn get_secret(id: &str) -> Result<Value, String> {
    let store = secret_store().lock().unwrap();
    let secret = store
        .0
        .iter()
        .find(|secret| secret.id == id)
        .cloned()
        .ok_or_else(|| format!("Secret '{}' not found", id))?;
    let rotation_history: Vec<RotationRun> = store
        .1
        .iter()
        .filter(|run| run.secret_id == id)
        .cloned()
        .collect();

    Ok(json!({
        "source": "static-seed",
        "dry_run": true,
        "secret": secret,
        "rotation_history": rotation_history
    }))
}

/// PURE: validate inputs, parse the type, and construct a freshly-registered
/// secret — WITHOUT touching the static store. ryuki-api calls this to persist
/// durably; the static `register_secret` below calls it then pushes to the
/// in-process fallback. Keeping id/timestamp minting here means DB mode and the
/// no-DB demo register identical secrets.
pub fn build_secret(
    name: &str,
    secret_type: &str,
    vault_path: &str,
    interval_days: u64,
    owner: &str,
    site: &str,
) -> Result<ManagedSecret, String> {
    if name.trim().is_empty() {
        return Err("name cannot be empty".into());
    }
    if vault_path.trim().is_empty() {
        return Err("vault_path cannot be empty".into());
    }
    if owner.trim().is_empty() {
        return Err("owner cannot be empty".into());
    }
    if site.trim().is_empty() {
        return Err("site cannot be empty".into());
    }

    let parsed_type = parse_secret_type(secret_type)?;
    let now = Utc::now();
    Ok(ManagedSecret {
        id: format!(
            "sr-{}-{}",
            site.to_lowercase(),
            Uuid::new_v4()
                .to_string()
                .split('-')
                .next()
                .unwrap_or("unknown")
        ),
        name: name.to_string(),
        secret_type: parsed_type,
        vault_path: vault_path.to_string(),
        rotation_interval_days: interval_days,
        last_rotated: now.to_rfc3339(),
        next_rotation_due: (now + Days::new(interval_days)).to_rfc3339(),
        status: SecretStatus::Active,
        owner: owner.to_string(),
        site: site.to_string(),
    })
}

/// PURE: the next rotation-due timestamp = `last_rotated` + `interval_days`,
/// RFC3339. Falls back to `now` when `last_rotated` is unparseable. Matches
/// `build_secret`'s scheduling, so changing the cadence reschedules from the real
/// last rotation rather than resetting the clock.
pub fn next_rotation_due_from(last_rotated: &str, interval_days: u64) -> String {
    let base = chrono::DateTime::parse_from_rfc3339(last_rotated)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());
    (base + Days::new(interval_days)).to_rfc3339()
}

/// PURE: produce the rotated secret state AND its completed rotation run, given
/// the existing run count (for the `v{n}` version label) — no store access.
pub fn rotate_secret_record(
    secret: &ManagedSecret,
    rotated_by: &str,
    existing_run_count: usize,
) -> (ManagedSecret, RotationRun) {
    let now = Utc::now();
    let completed_at = now + chrono::Duration::seconds(2);
    let updated = ManagedSecret {
        status: SecretStatus::Active,
        last_rotated: completed_at.to_rfc3339(),
        next_rotation_due: (completed_at + Days::new(secret.rotation_interval_days)).to_rfc3339(),
        ..secret.clone()
    };
    let run = RotationRun {
        id: format!(
            "rr-{}",
            Uuid::new_v4()
                .to_string()
                .split('-')
                .next()
                .unwrap_or("unknown")
        ),
        secret_id: secret.id.clone(),
        started_at: now.to_rfc3339(),
        completed_at: Some(completed_at.to_rfc3339()),
        status: RotationStatus::Completed,
        rotated_by: rotated_by.to_string(),
        new_version: Some(format!("v{}", existing_run_count + 1)),
        error_message: None,
    };
    (updated, run)
}

/// PURE: produce the failed-rotation run state — no store access. The caller
/// also flips the owning secret to Failed.
pub fn fail_rotation_record(run: &RotationRun, error: &str) -> RotationRun {
    RotationRun {
        status: RotationStatus::Failed,
        completed_at: Some(now_iso()),
        error_message: Some(error.to_string()),
        ..run.clone()
    }
}

pub fn register_secret(
    name: &str,
    secret_type: &str,
    vault_path: &str,
    interval_days: u64,
    owner: &str,
    site: &str,
) -> Result<Value, String> {
    let secret = build_secret(name, secret_type, vault_path, interval_days, owner, site)?;
    secret_store().lock().unwrap().0.push(secret.clone());

    Ok(json!({
        "source": "dry-run",
        "dry_run": true,
        "provider_calls_enabled": false,
        "secret": secret
    }))
}

pub fn rotate_secret(id: &str, rotated_by: &str) -> Result<Value, String> {
    if rotated_by.trim().is_empty() {
        return Err("rotated_by cannot be empty".into());
    }

    let mut store = secret_store().lock().unwrap();
    let run_count = store.1.len();
    let index = store
        .0
        .iter()
        .position(|secret| secret.id == id)
        .ok_or_else(|| format!("Secret '{}' not found", id))?;

    if store.0[index].status == SecretStatus::Retired {
        return Err(format!("Secret '{}' is retired and cannot be rotated", id));
    }

    let (updated, run) = rotate_secret_record(&store.0[index], rotated_by, run_count);
    store.0[index] = updated;
    store.1.push(run.clone());

    Ok(json!({
        "source": "dry-run",
        "dry_run": true,
        "provider": "vault-mock",
        "provider_calls_enabled": false,
        "secret_id": id,
        "rotation": run
    }))
}

pub fn get_rotation_history(id: &str) -> Result<Value, String> {
    let store = secret_store().lock().unwrap();
    if !store.0.iter().any(|secret| secret.id == id) {
        return Err(format!("Secret '{}' not found", id));
    }
    let runs: Vec<RotationRun> = store
        .1
        .iter()
        .filter(|run| run.secret_id == id)
        .cloned()
        .collect();

    Ok(json!({
        "source": "static-seed",
        "dry_run": true,
        "secret_id": id,
        "count": runs.len(),
        "rotation_history": runs
    }))
}

pub fn list_due_rotations() -> Result<Value, String> {
    let now = Utc::now();
    let store = secret_store().lock().unwrap();
    let secrets: Vec<ManagedSecret> = store
        .0
        .iter()
        // Retired secrets no longer rotate — never "due".
        .filter(|secret| secret.status != SecretStatus::Retired)
        .filter(|secret| match parse_iso_time(&secret.next_rotation_due) {
            Some(next_due) => next_due <= now,
            None => false,
        })
        .cloned()
        .collect();

    Ok(json!({
        "source": "static-seed",
        "dry_run": true,
        "count": secrets.len(),
        "secrets": secrets
    }))
}

pub fn list_expiring(days: u64) -> Result<Value, String> {
    let now = Utc::now();
    let cutoff = now + Days::new(days);
    let store = secret_store().lock().unwrap();
    let secrets: Vec<ManagedSecret> = store
        .0
        .iter()
        // Retired secrets no longer rotate — never "expiring".
        .filter(|secret| secret.status != SecretStatus::Retired)
        .filter(|secret| match parse_iso_time(&secret.next_rotation_due) {
            Some(next_due) => next_due >= now && next_due <= cutoff,
            None => false,
        })
        .cloned()
        .collect();

    Ok(json!({
        "source": "static-seed",
        "dry_run": true,
        "days": days,
        "count": secrets.len(),
        "secrets": secrets
    }))
}

pub fn force_rotate_all(site: &str) -> Result<Value, String> {
    if site.trim().is_empty() {
        return Err("site cannot be empty".into());
    }

    let now = Utc::now();
    let mut store = secret_store().lock().unwrap();
    let due_ids: Vec<String> = store
        .0
        .iter()
        .filter(|secret| secret.site == site)
        // Retired secrets are skipped by a force-rotate-all.
        .filter(|secret| secret.status != SecretStatus::Retired)
        .filter(|secret| match parse_iso_time(&secret.next_rotation_due) {
            Some(next_due) => next_due <= now,
            None => false,
        })
        .map(|secret| secret.id.clone())
        .collect();

    let mut rotations = Vec::new();
    for secret_id in due_ids {
        let completed_at = Utc::now() + chrono::Duration::seconds(2);
        if let Some(secret) = store.0.iter_mut().find(|secret| secret.id == secret_id) {
            secret.status = SecretStatus::Active;
            secret.last_rotated = completed_at.to_rfc3339();
            secret.next_rotation_due =
                (completed_at + Days::new(secret.rotation_interval_days)).to_rfc3339();
        }

        let run = RotationRun {
            id: format!(
                "rr-{}",
                Uuid::new_v4()
                    .to_string()
                    .split('-')
                    .next()
                    .unwrap_or("unknown")
            ),
            secret_id,
            started_at: now.to_rfc3339(),
            completed_at: Some(completed_at.to_rfc3339()),
            status: RotationStatus::Completed,
            rotated_by: "force-rotate-all".into(),
            new_version: Some(format!("v{}", store.1.len() + rotations.len() + 1)),
            error_message: None,
        };
        rotations.push(run.clone());
        store.1.push(run);
    }

    Ok(json!({
        "source": "dry-run",
        "dry_run": true,
        "provider": "vault-mock",
        "provider_calls_enabled": false,
        "site": site,
        "rotated_count": rotations.len(),
        "rotations": rotations
    }))
}

pub fn get_rotation_summary(site: &str) -> Result<Value, String> {
    let now = Utc::now();
    let store = secret_store().lock().unwrap();
    let secrets: Vec<&ManagedSecret> = store
        .0
        .iter()
        .filter(|secret| site.is_empty() || secret.site == site)
        .collect();
    let total = secrets.len();
    let active = secrets
        .iter()
        .filter(|secret| secret.status == SecretStatus::Active)
        .count();
    let due = secrets
        .iter()
        // Retired secrets no longer rotate — they are not "due" (consistent with
        // list_due_rotations / force_rotate_all).
        .filter(|secret| secret.status != SecretStatus::Retired)
        .filter(|secret| match parse_iso_time(&secret.next_rotation_due) {
            Some(next_due) => next_due <= now,
            None => false,
        })
        .count();
    let failed = secrets
        .iter()
        .filter(|secret| secret.status == SecretStatus::Failed)
        .count();

    Ok(json!({
        "source": "static-seed",
        "dry_run": true,
        "site": site,
        "total": total,
        "active": active,
        "due": due,
        "failed": failed
    }))
}

pub fn mark_rotation_failed(rotation_id: &str, error: &str) -> Result<Value, String> {
    if error.trim().is_empty() {
        return Err("error cannot be empty".into());
    }

    let mut store = secret_store().lock().unwrap();
    let run = store
        .1
        .iter_mut()
        .find(|run| run.id == rotation_id)
        .ok_or_else(|| format!("Rotation '{}' not found", rotation_id))?;
    run.status = RotationStatus::Failed;
    run.completed_at = Some(now_iso());
    run.error_message = Some(error.to_string());
    let secret_id = run.secret_id.clone();
    let run = run.clone();

    if let Some(secret) = store.0.iter_mut().find(|secret| secret.id == secret_id) {
        // A retired secret stays RETIRED — failing a (preserved) historical run
        // must never re-arm it for rotation.
        if secret.status != SecretStatus::Retired {
            secret.status = SecretStatus::Failed;
        }
    }

    Ok(json!({
        "source": "dry-run",
        "dry_run": true,
        "rotation": run
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_rotation_due_from_reschedules_off_last_rotated() {
        // 2026-01-01 + 90 days = 2026-04-01 (rescheduled from the real last
        // rotation, NOT from now).
        let due = next_rotation_due_from("2026-01-01T00:00:00+00:00", 90);
        assert!(due.starts_with("2026-04-01"), "got {due}");
        // An unparseable timestamp falls back to now()+interval (never panics).
        let fallback = next_rotation_due_from("not-a-date", 7);
        assert!(
            fallback.len() >= 20,
            "produces a valid rfc3339, got {fallback}"
        );
    }

    #[test]
    fn build_secret_and_transition_helpers_are_pure() {
        // No store access: ryuki-api drives these against DB-loaded rows.
        let secret =
            build_secret("db-token", "api-key", "kv/db/token", 30, "owner.x", "DEFRA").unwrap();
        assert_eq!(secret.secret_type, SecretType::APIKey);
        assert_eq!(secret.status, SecretStatus::Active);
        assert!(secret.id.starts_with("sr-defra-"));
        // serde rename_all="kebab-case" hyphenates EACH consecutive capital, so
        // APIKey serializes "a-p-i-key" (NOT "api-key"). Persistence must store
        // and round-trip this exact serde form.
        assert_eq!(
            serde_json::to_value(&secret).unwrap()["secret_type"],
            "a-p-i-key"
        );

        // rotation transition: secret goes Active, a completed run is minted
        // with the next sequential version.
        let (rotated, run) = rotate_secret_record(&secret, "rotator", 11);
        assert_eq!(rotated.status, SecretStatus::Active);
        assert_eq!(run.status, RotationStatus::Completed);
        assert_eq!(run.new_version.as_deref(), Some("v12"));
        assert_eq!(run.rotated_by, "rotator");

        // fail transition flips the run to Failed with the error recorded.
        let failed = fail_rotation_record(&run, "policy denied");
        assert_eq!(failed.status, RotationStatus::Failed);
        assert_eq!(failed.error_message.as_deref(), Some("policy denied"));
        assert!(failed.completed_at.is_some());

        // validation rejects empties.
        assert!(build_secret("", "token", "p", 30, "o", "S").is_err());
    }

    #[test]
    fn test_register_and_list_secrets() {
        let site = format!(
            "TREG{}",
            Uuid::new_v4().to_string().split('-').next().unwrap()
        );
        let registered = register_secret(
            "test-service-account",
            "ServiceAccount",
            "kv/test/service-account",
            30,
            "test.owner",
            &site,
        )
        .unwrap();
        assert_eq!(registered["secret"]["site"], site);
        assert_eq!(registered["secret"]["secret_type"], "service-account");

        let listed = list_secrets(&site, "ServiceAccount").unwrap();
        assert_eq!(listed["count"], 1);
        assert_eq!(listed["secrets"][0]["name"], "test-service-account");
    }

    #[test]
    fn test_rotate_secret() {
        let site = format!(
            "TROT{}",
            Uuid::new_v4().to_string().split('-').next().unwrap()
        );
        let secret = register_secret(
            "test-token",
            "Token",
            "kv/test/token",
            30,
            "test.owner",
            &site,
        )
        .unwrap();
        let secret_id = secret["secret"]["id"].as_str().unwrap();

        let rotated = rotate_secret(secret_id, "test.runner").unwrap();
        assert_eq!(rotated["secret_id"], secret_id);
        assert_eq!(rotated["rotation"]["status"], "completed");
        assert_eq!(rotated["provider_calls_enabled"], false);
    }

    #[test]
    fn test_list_due_rotations() {
        let site = format!(
            "TDUE{}",
            Uuid::new_v4().to_string().split('-').next().unwrap()
        );
        let secret = register_secret(
            "test-due-token",
            "Token",
            "kv/test/due-token",
            0,
            "test.owner",
            &site,
        )
        .unwrap();
        let secret_id = secret["secret"]["id"].as_str().unwrap();

        let due = list_due_rotations().unwrap();
        let secrets = due["secrets"].as_array().unwrap();
        assert!(secrets.iter().any(|secret| secret["id"] == secret_id));
    }

    #[test]
    fn test_rotation_history() {
        let site = format!(
            "THIS{}",
            Uuid::new_v4().to_string().split('-').next().unwrap()
        );
        let secret = register_secret(
            "test-history-token",
            "Token",
            "kv/test/history-token",
            30,
            "test.owner",
            &site,
        )
        .unwrap();
        let secret_id = secret["secret"]["id"].as_str().unwrap();
        let rotation = rotate_secret(secret_id, "test.runner").unwrap();
        let rotation_id = rotation["rotation"]["id"].as_str().unwrap();

        let history = get_rotation_history(secret_id).unwrap();
        assert_eq!(history["count"], 1);
        assert_eq!(history["rotation_history"][0]["id"], rotation_id);
    }

    #[test]
    fn test_force_rotate_all() {
        let site = format!(
            "TFOR{}",
            Uuid::new_v4().to_string().split('-').next().unwrap()
        );
        register_secret(
            "test-force-one",
            "Token",
            "kv/test/force-one",
            0,
            "test.owner",
            &site,
        )
        .unwrap();
        register_secret(
            "test-force-two",
            "APIKey",
            "kv/test/force-two",
            0,
            "test.owner",
            &site,
        )
        .unwrap();

        let result = force_rotate_all(&site).unwrap();
        assert_eq!(result["site"], site);
        assert_eq!(result["rotated_count"], 2);
        assert_eq!(result["provider_calls_enabled"], false);
    }

    #[test]
    fn test_get_rotation_summary() {
        let site = format!(
            "TSUM{}",
            Uuid::new_v4().to_string().split('-').next().unwrap()
        );
        register_secret(
            "test-summary-token",
            "Token",
            "kv/test/summary-token",
            0,
            "test.owner",
            &site,
        )
        .unwrap();

        let summary = get_rotation_summary(&site).unwrap();
        assert_eq!(summary["total"], 1);
        assert_eq!(summary["active"], 1);
        assert_eq!(summary["due"], 1);
        assert_eq!(summary["failed"], 0);
    }

    #[test]
    fn test_mark_rotation_failed() {
        let site = format!(
            "TFAI{}",
            Uuid::new_v4().to_string().split('-').next().unwrap()
        );
        let secret = register_secret(
            "test-failed-token",
            "Token",
            "kv/test/failed-token",
            30,
            "test.owner",
            &site,
        )
        .unwrap();
        let secret_id = secret["secret"]["id"].as_str().unwrap();
        let rotation = rotate_secret(secret_id, "test.runner").unwrap();
        let rotation_id = rotation["rotation"]["id"].as_str().unwrap();

        let failed = mark_rotation_failed(rotation_id, "mock vault timeout").unwrap();
        assert_eq!(failed["rotation"]["status"], "failed");
        assert_eq!(failed["rotation"]["error_message"], "mock vault timeout");

        let summary = get_rotation_summary(&site).unwrap();
        assert_eq!(summary["failed"], 1);
    }

    #[test]
    fn test_get_secret_includes_rotation_history() {
        let secret = get_secret("sr-defra-002").unwrap();
        assert_eq!(secret["secret"]["id"], "sr-defra-002");
        assert!(!secret["rotation_history"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_list_expiring() {
        let expiring = list_expiring(7).unwrap();
        let secrets = expiring["secrets"].as_array().unwrap();
        assert!(secrets.iter().any(|secret| secret["id"] == "sr-defra-003"));
    }

    #[test]
    fn retired_status_display_and_serde_round_trip() {
        // Display is PascalCase (human); the DB/serde form is kebab-case.
        assert_eq!(SecretStatus::Retired.to_string(), "Retired");
        assert_eq!(
            serde_json::to_value(SecretStatus::Retired).unwrap(),
            serde_json::json!("retired")
        );
        assert_eq!(
            serde_json::from_value::<SecretStatus>(serde_json::json!("retired")).unwrap(),
            SecretStatus::Retired
        );
    }
}
