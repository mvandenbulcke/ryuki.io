//! Code-owned production dependency topology.
//!
//! The deployment receipt states the dependency inventory that production is
//! expected to have. It is not allowed to define or discover that inventory.
//! This module owns the independent API component set and, once every entry is
//! backed by an exact retained live allocation, derives the receipt-comparison
//! inventory through `ryuki-core`.
//!
//! Current routing and worker composition still has production-reachable mock
//! implementations. Those entries are typed blockers, so supplying plausible
//! live-looking rows cannot make this plan emit an inventory or a runtime
//! witness prematurely.

use std::collections::HashSet;
use std::fmt;

use ryuki_core::security_profile::{
    measure_production_dependency_inventory, GuardId, MeasuredProductionDependencyInventory,
    ProductionDependencyRuntimeBinding, RuntimeGuardDigestError,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProductionDependencyMeasurementSource {
    /// The component-specific guard must export its exact retained allocation
    /// and independently measured binding; the receipt value is not a source.
    RuntimeGuard(GuardId),
    /// The current implementation can select or invoke a mock/static/local
    /// substitute. It remains an unconditional plan blocker.
    BlockedByImplementation {
        implementation_id: &'static str,
        reason: &'static str,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProductionDependencyPlanComponent {
    component_id: &'static str,
    measurement_source: ProductionDependencyMeasurementSource,
}

/// Closed API component set. Entries are strictly bytewise-sorted by
/// `component_id`; changing the production route or worker topology requires a
/// deliberate edit to this list and its exact-set tests.
const PRODUCTION_DEPENDENCY_COMPONENTS: [ProductionDependencyPlanComponent; 20] = [
    ProductionDependencyPlanComponent {
        component_id: "runtime-component:audit-authority",
        measurement_source: ProductionDependencyMeasurementSource::BlockedByImplementation {
            implementation_id: "runtime-implementation:postgresql-or-process-audit-store",
            reason: "audit retains a process-local no-database store",
        },
    },
    ProductionDependencyPlanComponent {
        component_id: "runtime-component:authenticator",
        measurement_source: ProductionDependencyMeasurementSource::RuntimeGuard(
            GuardId::NonDevelopmentAuthenticator,
        ),
    },
    ProductionDependencyPlanComponent {
        component_id: "runtime-component:cmdb-provider",
        measurement_source: ProductionDependencyMeasurementSource::BlockedByImplementation {
            implementation_id: "runtime-implementation:static-cmdb-fixtures",
            reason: "CMDB import and reconciliation select hard-coded fixture providers",
        },
    },
    ProductionDependencyPlanComponent {
        component_id: "runtime-component:configuration-authority",
        measurement_source: ProductionDependencyMeasurementSource::BlockedByImplementation {
            implementation_id: "runtime-implementation:file-default-config-store",
            reason: "configuration can fall back to defaults and a process-local file",
        },
    },
    ProductionDependencyPlanComponent {
        component_id: "runtime-component:database",
        measurement_source: ProductionDependencyMeasurementSource::RuntimeGuard(
            GuardId::DurablePostgresql,
        ),
    },
    ProductionDependencyPlanComponent {
        component_id: "runtime-component:first-owner-authority",
        measurement_source: ProductionDependencyMeasurementSource::RuntimeGuard(
            GuardId::FirstOwnerPathClosed,
        ),
    },
    ProductionDependencyPlanComponent {
        component_id: "runtime-component:integration-credential-encryption",
        measurement_source: ProductionDependencyMeasurementSource::BlockedByImplementation {
            implementation_id: "runtime-implementation:ambient-env-encryption-key",
            reason: "integration encryption rereads a mutable process environment key",
        },
    },
    ProductionDependencyPlanComponent {
        component_id: "runtime-component:integration-provider",
        measurement_source: ProductionDependencyMeasurementSource::BlockedByImplementation {
            implementation_id: "runtime-implementation:connection-reachability-stub",
            reason: "integration tests and scheduled health use a generic reachability stub",
        },
    },
    ProductionDependencyPlanComponent {
        component_id: "runtime-component:inventory-provider",
        measurement_source: ProductionDependencyMeasurementSource::BlockedByImplementation {
            implementation_id: "runtime-implementation:static-inventory-fixtures",
            reason: "inventory synchronization selects hard-coded provider data",
        },
    },
    ProductionDependencyPlanComponent {
        component_id: "runtime-component:public-ingress",
        measurement_source: ProductionDependencyMeasurementSource::RuntimeGuard(
            GuardId::HttpsPublicUrls,
        ),
    },
    ProductionDependencyPlanComponent {
        component_id: "runtime-component:repository-dispatch",
        measurement_source: ProductionDependencyMeasurementSource::BlockedByImplementation {
            implementation_id: "runtime-implementation:ambient-database-or-process-store",
            reason: "handlers can select process-local stores when the ambient database is absent",
        },
    },
    ProductionDependencyPlanComponent {
        component_id: "runtime-component:request-publisher",
        measurement_source: ProductionDependencyMeasurementSource::BlockedByImplementation {
            implementation_id: "runtime-implementation:mock-cmdb-request-publisher",
            reason: "request publication can persist mock CMDB evidence as operational state",
        },
    },
    ProductionDependencyPlanComponent {
        component_id: "runtime-component:route-dispatch",
        measurement_source: ProductionDependencyMeasurementSource::BlockedByImplementation {
            implementation_id: "runtime-implementation:mixed-live-dry-run-router",
            reason: "the production router does not exclude mock-backed routes",
        },
    },
    ProductionDependencyPlanComponent {
        component_id: "runtime-component:scheduler-dispatch",
        measurement_source: ProductionDependencyMeasurementSource::BlockedByImplementation {
            implementation_id: "runtime-implementation:mixed-live-dry-run-scheduler",
            reason: "the scheduler admits enabled simulated and stub-backed jobs",
        },
    },
    ProductionDependencyPlanComponent {
        component_id: "runtime-component:secret-provider",
        measurement_source: ProductionDependencyMeasurementSource::RuntimeGuard(
            GuardId::ApprovedSecretProvider,
        ),
    },
    ProductionDependencyPlanComponent {
        component_id: "runtime-component:secure-cookie-runtime",
        measurement_source: ProductionDependencyMeasurementSource::RuntimeGuard(
            GuardId::SecureCookies,
        ),
    },
    ProductionDependencyPlanComponent {
        component_id: "runtime-component:servicenow-provider",
        measurement_source: ProductionDependencyMeasurementSource::BlockedByImplementation {
            implementation_id: "runtime-implementation:local-servicenow-queue",
            reason: "ServiceNow submission only changes local queue state",
        },
    },
    ProductionDependencyPlanComponent {
        component_id: "runtime-component:signing-key-material",
        measurement_source: ProductionDependencyMeasurementSource::RuntimeGuard(
            GuardId::ExternalSigningKeyMaterial,
        ),
    },
    ProductionDependencyPlanComponent {
        component_id: "runtime-component:site-authority",
        measurement_source: ProductionDependencyMeasurementSource::BlockedByImplementation {
            implementation_id: "runtime-implementation:seeded-site-registry-cache",
            reason: "site hydration can retain or fall back to process seed data",
        },
    },
    ProductionDependencyPlanComponent {
        component_id: "runtime-component:synthetic-health-provider",
        measurement_source: ProductionDependencyMeasurementSource::BlockedByImplementation {
            implementation_id: "runtime-implementation:simulated-synthetic-health",
            reason: "synthetic health persists simulated probe outcomes",
        },
    },
];

#[derive(Debug, Clone, Copy)]
struct ProductionDependencyPlan<'a> {
    components: &'a [ProductionDependencyPlanComponent],
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ProductionDependencyPlanError {
    InvalidPlan(&'static str),
    BlockedComponents(Vec<&'static str>),
    MeasurementSetMismatch {
        expected: Vec<&'static str>,
        observed: Vec<String>,
    },
    InvalidMeasurement(RuntimeGuardDigestError),
}

impl fmt::Display for ProductionDependencyPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPlan(reason) => {
                write!(formatter, "invalid production dependency plan: {reason}")
            }
            Self::BlockedComponents(component_ids) => write!(
                formatter,
                "production dependency plan has non-production consumers: {}",
                component_ids.join(", ")
            ),
            Self::MeasurementSetMismatch { expected, observed } => write!(
                formatter,
                "production dependency measurement set differs from the code-owned plan (expected [{}], observed [{}])",
                expected.join(", "),
                observed.join(", ")
            ),
            Self::InvalidMeasurement(error) => {
                write!(
                    formatter,
                    "production dependency measurement is invalid: {error}"
                )
            }
        }
    }
}

impl From<RuntimeGuardDigestError> for ProductionDependencyPlanError {
    fn from(error: RuntimeGuardDigestError) -> Self {
        Self::InvalidMeasurement(error)
    }
}

impl ProductionDependencyPlan<'_> {
    fn validate_shape(&self) -> Result<(), ProductionDependencyPlanError> {
        if self.components.is_empty()
            || !self
                .components
                .windows(2)
                .all(|pair| pair[0].component_id < pair[1].component_id)
            || self
                .components
                .iter()
                .any(|component| !canonical_scoped_id(component.component_id, "runtime-component:"))
        {
            return Err(ProductionDependencyPlanError::InvalidPlan(
                "component ids must be nonempty, canonical, strictly sorted, and unique",
            ));
        }

        let mut guard_sources = HashSet::new();
        for component in self.components {
            match component.measurement_source {
                ProductionDependencyMeasurementSource::RuntimeGuard(guard_id) => {
                    if guard_id == GuardId::MockDependenciesDisabled
                        || !guard_sources.insert(guard_id)
                    {
                        return Err(ProductionDependencyPlanError::InvalidPlan(
                            "runtime guard sources must be unique and cycle-free",
                        ));
                    }
                }
                ProductionDependencyMeasurementSource::BlockedByImplementation {
                    implementation_id,
                    reason,
                } => {
                    if !canonical_scoped_id(implementation_id, "runtime-implementation:")
                        || reason.trim().is_empty()
                    {
                        return Err(ProductionDependencyPlanError::InvalidPlan(
                            "blocked implementations require a canonical id and reason",
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    fn measure(
        &self,
        bindings: &[ProductionDependencyRuntimeBinding],
    ) -> Result<MeasuredProductionDependencyInventory, ProductionDependencyPlanError> {
        self.validate_shape()?;

        let blocked = self
            .components
            .iter()
            .filter_map(|component| {
                matches!(
                    component.measurement_source,
                    ProductionDependencyMeasurementSource::BlockedByImplementation { .. }
                )
                .then_some(component.component_id)
            })
            .collect::<Vec<_>>();
        if !blocked.is_empty() {
            return Err(ProductionDependencyPlanError::BlockedComponents(blocked));
        }

        let expected = self
            .components
            .iter()
            .map(|component| component.component_id)
            .collect::<Vec<_>>();
        let observed = bindings
            .iter()
            .map(|binding| binding.component_id.clone())
            .collect::<Vec<_>>();
        if expected
            .iter()
            .copied()
            .ne(observed.iter().map(String::as_str))
        {
            return Err(ProductionDependencyPlanError::MeasurementSetMismatch {
                expected,
                observed,
            });
        }

        measure_production_dependency_inventory(bindings).map_err(Into::into)
    }
}

fn canonical_scoped_id(value: &str, prefix: &str) -> bool {
    let Some(suffix) = value.strip_prefix(prefix) else {
        return false;
    };
    let bytes = suffix.as_bytes();
    (3..=127).contains(&bytes.len())
        && bytes
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn current_production_dependency_plan() -> ProductionDependencyPlan<'static> {
    ProductionDependencyPlan {
        components: &PRODUCTION_DEPENDENCY_COMPONENTS,
    }
}

/// Return the current typed blocker after exercising the same exact-set seam
/// that the future retained-handle verifier will use. This must remain an
/// error until every blocked entry has a concrete live owner and measurement.
pub(crate) fn current_production_dependency_admission_blocker() -> String {
    current_production_dependency_plan()
        .measure(&[])
        .expect_err("the current production dependency plan must remain fail-closed")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ryuki_core::security_profile::{
        ProductionDependencyAuthorityBinding, ProductionDependencyAuthorityMode,
        ProductionDependencyPosture, ProductionDependencyRuntimeOwnership,
    };

    fn digest(character: char) -> String {
        format!("sha256:{}", character.to_string().repeat(64))
    }

    fn binding(
        component: &str,
        implementation: &str,
        digest_character: char,
    ) -> ProductionDependencyRuntimeBinding {
        let component_suffix = component
            .strip_prefix("runtime-component:")
            .expect("test component namespace");
        ProductionDependencyRuntimeBinding {
            component_id: component.into(),
            implementation_id: implementation.into(),
            implementation_version: "1.0.0".into(),
            production_posture: ProductionDependencyPosture::Production,
            authority_mode: ProductionDependencyAuthorityMode::Live,
            fallback_allowed: false,
            authority_bindings: vec![ProductionDependencyAuthorityBinding {
                binding_id: format!("runtime-binding:{component_suffix}"),
                binding_contract: "ryuki-test-runtime-binding-v1".into(),
                binding_digest: digest(digest_character),
            }],
            retained_consumer_ids: vec!["runtime-consumer:api-test".into()],
            ownership: ProductionDependencyRuntimeOwnership {
                runtime_owner_id: format!("runtime-owner:{component_suffix}"),
                single_runtime_owner: true,
                ambient_reconfiguration_allowed: false,
            },
        }
    }

    #[test]
    fn current_plan_is_closed_sorted_and_fails_on_known_mock_consumers() {
        let plan = current_production_dependency_plan();
        plan.validate_shape().expect("code-owned plan shape");
        assert_eq!(plan.components.len(), 20);
        assert!(plan
            .components
            .windows(2)
            .all(|pair| pair[0].component_id < pair[1].component_id));
        let guard_sources = plan
            .components
            .iter()
            .filter_map(|component| match component.measurement_source {
                ProductionDependencyMeasurementSource::RuntimeGuard(guard_id) => Some(guard_id),
                ProductionDependencyMeasurementSource::BlockedByImplementation { .. } => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            guard_sources,
            vec![
                GuardId::NonDevelopmentAuthenticator,
                GuardId::DurablePostgresql,
                GuardId::FirstOwnerPathClosed,
                GuardId::HttpsPublicUrls,
                GuardId::ApprovedSecretProvider,
                GuardId::SecureCookies,
                GuardId::ExternalSigningKeyMaterial,
            ]
        );

        let error = plan.measure(&[]).unwrap_err();
        let public_error = error.to_string();
        assert!(!public_error.contains("runtime-implementation:"));
        assert!(!public_error.contains("RYUKI_"));
        assert!(!public_error.contains('/'));
        let ProductionDependencyPlanError::BlockedComponents(blocked) = error else {
            panic!("current plan must fail on concrete mock consumers");
        };
        assert_eq!(
            blocked,
            vec![
                "runtime-component:audit-authority",
                "runtime-component:cmdb-provider",
                "runtime-component:configuration-authority",
                "runtime-component:integration-credential-encryption",
                "runtime-component:integration-provider",
                "runtime-component:inventory-provider",
                "runtime-component:repository-dispatch",
                "runtime-component:request-publisher",
                "runtime-component:route-dispatch",
                "runtime-component:scheduler-dispatch",
                "runtime-component:servicenow-provider",
                "runtime-component:site-authority",
                "runtime-component:synthetic-health-provider",
            ]
        );
    }

    #[test]
    fn blocked_component_cannot_be_overridden_by_a_live_looking_binding() {
        let components = [ProductionDependencyPlanComponent {
            component_id: "runtime-component:inventory-provider",
            measurement_source: ProductionDependencyMeasurementSource::BlockedByImplementation {
                implementation_id: "runtime-implementation:static-inventory-fixtures",
                reason: "fixture provider remains reachable",
            },
        }];
        let plan = ProductionDependencyPlan {
            components: &components,
        };
        let supplied = [binding(
            "runtime-component:inventory-provider",
            "runtime-implementation:claimed-live-provider",
            'a',
        )];
        assert!(matches!(
            plan.measure(&supplied),
            Err(ProductionDependencyPlanError::BlockedComponents(_))
        ));
    }

    #[test]
    fn ready_plan_requires_the_exact_code_owned_set_and_derives_one_inventory() {
        let components = [
            ProductionDependencyPlanComponent {
                component_id: "runtime-component:database",
                measurement_source: ProductionDependencyMeasurementSource::RuntimeGuard(
                    GuardId::DurablePostgresql,
                ),
            },
            ProductionDependencyPlanComponent {
                component_id: "runtime-component:secret-provider",
                measurement_source: ProductionDependencyMeasurementSource::RuntimeGuard(
                    GuardId::ApprovedSecretProvider,
                ),
            },
        ];
        let plan = ProductionDependencyPlan {
            components: &components,
        };
        let bindings = [
            binding(
                "runtime-component:database",
                "runtime-implementation:postgresql",
                'a',
            ),
            binding(
                "runtime-component:secret-provider",
                "runtime-implementation:vault",
                'b',
            ),
        ];

        let measured = plan.measure(&bindings).expect("exact retained set");
        assert_eq!(
            measured.required_component_ids,
            vec![
                "runtime-component:database".to_string(),
                "runtime-component:secret-provider".to_string(),
            ]
        );
        assert_eq!(measured.dependencies.len(), 2);

        assert!(matches!(
            plan.measure(&bindings[..1]),
            Err(ProductionDependencyPlanError::MeasurementSetMismatch { .. })
        ));
        let mut extra = bindings.to_vec();
        extra.push(binding(
            "runtime-component:site-authority",
            "runtime-implementation:postgresql-site-authority",
            'c',
        ));
        assert!(matches!(
            plan.measure(&extra),
            Err(ProductionDependencyPlanError::MeasurementSetMismatch { .. })
        ));
    }

    #[test]
    fn plan_rejects_receipt_guard_cycles_and_duplicate_guard_sources() {
        let cyclic = [ProductionDependencyPlanComponent {
            component_id: "runtime-component:dependency-inventory",
            measurement_source: ProductionDependencyMeasurementSource::RuntimeGuard(
                GuardId::MockDependenciesDisabled,
            ),
        }];
        assert!(matches!(
            (ProductionDependencyPlan {
                components: &cyclic,
            })
            .validate_shape(),
            Err(ProductionDependencyPlanError::InvalidPlan(_))
        ));

        let duplicated = [
            ProductionDependencyPlanComponent {
                component_id: "runtime-component:database",
                measurement_source: ProductionDependencyMeasurementSource::RuntimeGuard(
                    GuardId::DurablePostgresql,
                ),
            },
            ProductionDependencyPlanComponent {
                component_id: "runtime-component:database-reconnect",
                measurement_source: ProductionDependencyMeasurementSource::RuntimeGuard(
                    GuardId::DurablePostgresql,
                ),
            },
        ];
        assert!(matches!(
            (ProductionDependencyPlan {
                components: &duplicated,
            })
            .validate_shape(),
            Err(ProductionDependencyPlanError::InvalidPlan(_))
        ));
    }
}
