//! Build-owned identity and selector inventory used by production admission.
//!
//! This table is deliberately compiled into the API. A detached manifest must
//! exactly match it; the manifest cannot redefine which selectors or adapter
//! implementations the executing artifact contains.

use ryuki_core::config::{AuthMode, SecretProvider};
use ryuki_core::production_build::{
    BuildComponent, BuildEndian, BuildSelectorDisposition, BuildTarget,
    MandatoryCapabilityBaseline, SelectorDisposition, SelectorDomain, ShippedAdapter,
    PRODUCTION_BUILD_COMPONENT_ID, PRODUCTION_BUILD_EXECUTABLE_NAME,
};
use ryuki_engine::models::AdapterType;

const BASELINE_ID: &str = "baseline:repository-development-fixture-v1";
const BASELINE_VERSION: u64 = 1;
const BASELINE_DIGEST: &str =
    "sha256:8f758b63ae8d08f04c0a49ce046da46c25be82e3c1f450666280f05ef9787bb8";
const BASELINE_LOCATOR: &str = "docs/architecture/platform-security-boundary.md";
const BASELINE_TRACE_IDS: [&str; 3] = [
    "TRACE-SB-CONF-03-AC-048",
    "TRACE-SB-CONF-04-AC-048",
    "TRACE-SB-IDL-02-AC-004",
];
const INTEGRATION_CAPABILITIES: [&str; 5] = [
    "connect",
    "disconnect",
    "execute",
    "health-check",
    "sync-inventory",
];

pub(crate) fn embedded_source_revision() -> Option<&'static str> {
    option_env!("RYUKI_SOURCE_REVISION")
}

pub(crate) fn current_component() -> BuildComponent {
    BuildComponent {
        component_id: PRODUCTION_BUILD_COMPONENT_ID.into(),
        component_version: env!("CARGO_PKG_VERSION").into(),
        executable_name: PRODUCTION_BUILD_EXECUTABLE_NAME.into(),
        target: BuildTarget {
            architecture: std::env::consts::ARCH.into(),
            operating_system: std::env::consts::OS.into(),
            family: std::env::consts::FAMILY.into(),
            pointer_width_bits: usize::BITS as u16,
            endian: if cfg!(target_endian = "little") {
                BuildEndian::Little
            } else {
                BuildEndian::Big
            },
        },
    }
}

pub(crate) fn compiled_shipped_adapters() -> Vec<ShippedAdapter> {
    let mut adapters = vec![
        shipped(
            "auth.entra-id",
            &["authenticate", "generic-oidc", "logout", "token-validation"],
        ),
        shipped(
            "auth.local",
            &["authenticate", "password-verification", "recovery-ceremony"],
        ),
        shipped("secret.hashicorp-vault", &["kv-v2-read", "kv-v2-resolve"]),
    ];
    for adapter in all_integration_adapter_types() {
        if !matches!(adapter, AdapterType::VeeamOne) {
            adapters.push(shipped(
                &format!("integration.{adapter}"),
                &INTEGRATION_CAPABILITIES,
            ));
        }
    }
    adapters.sort_by(|left, right| left.adapter_kind.cmp(&right.adapter_kind));
    adapters
}

pub(crate) fn compiled_selector_dispositions() -> Vec<BuildSelectorDisposition> {
    let mut selectors = all_auth_modes()
        .into_iter()
        .map(auth_mode_disposition)
        .chain(
            all_secret_providers()
                .into_iter()
                .map(secret_provider_disposition),
        )
        .chain(
            all_integration_adapter_types()
                .into_iter()
                .map(integration_adapter_disposition),
        )
        .collect::<Vec<_>>();
    selectors.sort_by(|left, right| {
        (left.selector_domain.as_str(), left.selector.as_str())
            .cmp(&(right.selector_domain.as_str(), right.selector.as_str()))
    });
    selectors
}

fn shipped(adapter_kind: &str, capability_ids: &[&str]) -> ShippedAdapter {
    let mut capability_ids = capability_ids
        .iter()
        .map(|capability| (*capability).to_string())
        .collect::<Vec<_>>();
    capability_ids.sort();
    ShippedAdapter {
        adapter_kind: adapter_kind.into(),
        adapter_version: env!("CARGO_PKG_VERSION").into(),
        production_eligible: false,
        capability_ids,
        mandatory_baseline: MandatoryCapabilityBaseline {
            document_id: BASELINE_ID.into(),
            document_version: BASELINE_VERSION,
            content_digest: BASELINE_DIGEST.into(),
            artifact_locator: BASELINE_LOCATOR.into(),
            required_trace_ids: BASELINE_TRACE_IDS
                .iter()
                .map(|trace| (*trace).into())
                .collect(),
        },
    }
}

fn auth_mode_disposition(mode: AuthMode) -> BuildSelectorDisposition {
    let (disposition, adapter_kind) = match mode {
        AuthMode::EntraId => (
            SelectorDisposition::Implemented,
            Some("auth.entra-id".into()),
        ),
        AuthMode::Local => (SelectorDisposition::Implemented, Some("auth.local".into())),
        AuthMode::MockDryRun | AuthMode::StaticDryRun => (SelectorDisposition::Sentinel, None),
    };
    BuildSelectorDisposition {
        selector_domain: SelectorDomain::AuthMode,
        selector: mode.as_str().into(),
        disposition,
        adapter_kind,
    }
}

fn secret_provider_disposition(provider: SecretProvider) -> BuildSelectorDisposition {
    let (disposition, adapter_kind) = match provider {
        SecretProvider::HashicorpVault => (
            SelectorDisposition::Implemented,
            Some("secret.hashicorp-vault".into()),
        ),
        // Catalog-only is the closed manifest representation of this unsupported,
        // unshipped, non-production-eligible adapter. OpenBao must not inherit
        // Vault's implementation claim; it can become implemented only after its
        // own real, version-pinned compatibility suite exists.
        SecretProvider::OpenBao => (
            SelectorDisposition::CatalogOnly,
            Some("secret.openbao".into()),
        ),
        SecretProvider::None => (SelectorDisposition::Sentinel, None),
        SecretProvider::AwsSecretsManager
        | SecretProvider::AzureKeyVault
        | SecretProvider::GcpSecretManager
        | SecretProvider::BitwardenSecretsManager => (SelectorDisposition::Unsupported, None),
    };
    BuildSelectorDisposition {
        selector_domain: SelectorDomain::SecretProvider,
        selector: provider.as_str().into(),
        disposition,
        adapter_kind,
    }
}

fn integration_adapter_disposition(adapter: AdapterType) -> BuildSelectorDisposition {
    let selector = adapter.to_string();
    let (disposition, adapter_kind) = if matches!(adapter, AdapterType::VeeamOne) {
        (
            SelectorDisposition::CatalogOnly,
            Some(format!("integration.{selector}")),
        )
    } else {
        (
            SelectorDisposition::Implemented,
            Some(format!("integration.{selector}")),
        )
    };
    BuildSelectorDisposition {
        selector_domain: SelectorDomain::IntegrationAdapter,
        selector,
        disposition,
        adapter_kind,
    }
}

fn all_auth_modes() -> [AuthMode; 4] {
    [
        AuthMode::MockDryRun,
        AuthMode::StaticDryRun,
        AuthMode::EntraId,
        AuthMode::Local,
    ]
}

fn all_secret_providers() -> [SecretProvider; 7] {
    [
        SecretProvider::HashicorpVault,
        SecretProvider::OpenBao,
        SecretProvider::AwsSecretsManager,
        SecretProvider::AzureKeyVault,
        SecretProvider::GcpSecretManager,
        SecretProvider::BitwardenSecretsManager,
        SecretProvider::None,
    ]
}

fn all_integration_adapter_types() -> [AdapterType; 18] {
    [
        AdapterType::VMware,
        AdapterType::HyperV,
        AdapterType::Proxmox,
        AdapterType::NutanixAhv,
        AdapterType::Xen,
        AdapterType::Kvm,
        AdapterType::Veeam,
        AdapterType::VeeamOne,
        AdapterType::Commvault,
        AdapterType::Rubrik,
        AdapterType::Cohesity,
        AdapterType::NetBackup,
        AdapterType::Zabbix,
        AdapterType::Prometheus,
        AdapterType::Datadog,
        AdapterType::Grafana,
        AdapterType::SolarWinds,
        AdapterType::ServiceNow,
    ]
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use sha2::{Digest, Sha256};

    use super::*;

    #[test]
    fn build_surface_is_closed_sorted_and_honest() {
        let adapters = compiled_shipped_adapters();
        assert_eq!(adapters.len(), 20);
        assert!(adapters
            .windows(2)
            .all(|pair| pair[0].adapter_kind < pair[1].adapter_kind));
        assert!(adapters.iter().all(|adapter| !adapter.production_eligible));
        assert!(!adapters
            .iter()
            .any(|adapter| adapter.adapter_kind == "integration.veeam-one"));

        let selectors = compiled_selector_dispositions();
        assert_eq!(selectors.len(), 29);
        assert!(selectors.windows(2).all(|pair| {
            (pair[0].selector_domain.as_str(), pair[0].selector.as_str())
                < (pair[1].selector_domain.as_str(), pair[1].selector.as_str())
        }));
        let veeam_one = selectors
            .iter()
            .find(|row| row.selector == "veeam-one")
            .unwrap();
        assert_eq!(veeam_one.disposition, SelectorDisposition::CatalogOnly);
        assert_eq!(
            veeam_one.adapter_kind.as_deref(),
            Some("integration.veeam-one")
        );
    }

    #[test]
    fn openbao_is_distinct_catalog_only_and_not_shipped() {
        let adapters = compiled_shipped_adapters();
        let selectors = compiled_selector_dispositions();
        let openbao = selectors
            .iter()
            .find(|row| {
                row.selector_domain == SelectorDomain::SecretProvider && row.selector == "openbao"
            })
            .unwrap();
        assert_eq!(openbao.disposition, SelectorDisposition::CatalogOnly);
        assert_eq!(openbao.adapter_kind.as_deref(), Some("secret.openbao"));
        assert_ne!(
            openbao.adapter_kind.as_deref(),
            Some("secret.hashicorp-vault")
        );
        assert!(!adapters
            .iter()
            .any(|adapter| adapter.adapter_kind == "secret.openbao"));
    }

    #[test]
    fn integration_selector_inventory_matches_the_enum_backed_catalog() {
        let expected = ryuki_engine::vendor_catalog::catalog()
            .into_iter()
            .map(|entry| entry.vendor_type)
            .collect::<BTreeSet<_>>();
        let actual = compiled_selector_dispositions()
            .into_iter()
            .filter(|row| row.selector_domain == SelectorDomain::IntegrationAdapter)
            .map(|row| row.selector)
            .collect::<BTreeSet<_>>();
        assert_eq!(actual, expected);
    }

    #[test]
    fn baseline_digest_tracks_the_exact_normative_source_bytes() {
        let bytes = include_bytes!("../../../docs/architecture/platform-security-boundary.md");
        let actual = format!("sha256:{:x}", Sha256::digest(bytes));
        assert_eq!(actual, BASELINE_DIGEST);
    }

    #[test]
    fn release_revision_is_absent_or_a_full_lowercase_git_object_id() {
        if let Some(revision) = embedded_source_revision() {
            assert!(matches!(revision.len(), 40 | 64));
            assert!(revision
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
        }
    }
}
