//! Repository-wide validation for the normative production-security contracts.
//!
//! This validator deliberately has no network-capable schema resolver.  The
//! versioned contract set is a closed repository input: a `$ref` that cannot be
//! resolved from its own schema is an error, never an invitation to fetch code
//! or policy from the network.

use chrono::{DateTime, Utc};
use jsonschema::{Retrieve, Uri};
use ryuki_core::production_build::ProductionBuildManifest;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

const CONTRACT_DIR: &str = "catalog/security-contracts/v1";
const CONFORMANCE_BUNDLE_LOCATOR_PREFIX: &str =
    "catalog/security-contracts/v1/conformance-bundles/";
const PACKAGE_EXIT_RECEIPT_LOCATOR_PREFIX: &str =
    "catalog/security-contracts/v1/package-exit-receipts/";
const DEPLOYMENT_PROFILE_LOCATOR: &str =
    "catalog/security-contracts/v1/deployment-security-profile.implementation.json";
const DEPLOYMENT_PROFILE_BINDING_DIGEST_CONTRACT: &str =
    "ryuki-deployment-profile-conformance-binding-v1";
const ZERO_SHA256_DIGEST: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const TRUST_REGISTRY_HEAD_LOCATOR: &str =
    "catalog/security-contracts/v1/conformance-trust-root-registry.implementation.json";
const TRUST_REGISTRY_SCHEMA_NAME: &str = "conformance-trust-root-registry.schema.json";
const MAX_TRUST_REGISTRY_LINEAGE: usize = 16;
const MAX_TRUST_REGISTRY_BYTES: u64 = 4 * 1024 * 1024;
const MAX_TRUST_REGISTRY_KEYS: usize = 256;
const MAX_TRUST_REGISTRY_TOMBSTONES: usize = 4096;
const MAX_TRUST_REGISTRY_SCOPE_ITEMS: usize = 256;
const MAX_TRUST_REGISTRY_PROFILES: usize = 3;
const MAX_TRUST_KEY_PURPOSES: usize = 2;
const MAX_TRUST_KEY_EVIDENCE_TIERS: usize = 3;
const MAX_TRUST_KEY_PACKAGES: usize = 10;
const MAX_PRODUCTION_BUILD_SEMANTIC_ERRORS: usize = 1024;
const MAX_APPLICABILITY_EXPRESSION_DEPTH: usize = 32;
const MAX_APPLICABILITY_EXPRESSION_NODES: usize = 4096;
const MAX_APPLICABILITY_EXPRESSION_OPERANDS: usize = 64;
const MAX_RECEIPT_DIGESTS: usize = 4096;

const SCHEMAS: [(&str, &str); 12] = [
    (
        "action-resource-registry.schema.json",
        "https://ryuki.io/schemas/security-contracts/v1/action-resource-registry.schema.json",
    ),
    (
        "conformance-bundle.schema.json",
        "https://ryuki.io/schemas/security-contracts/v1/conformance-bundle.schema.json",
    ),
    (
        "conformance-trust-checkpoint-envelope.schema.json",
        "https://ryuki.io/schemas/security-contracts/v1/conformance-trust-checkpoint-envelope.schema.json",
    ),
    (
        "deployed-workload-attestation-envelope.schema.json",
        "https://ryuki.io/schemas/security-contracts/v1/deployed-workload-attestation-envelope.schema.json",
    ),
    (
        "conformance-trust-root-registry.schema.json",
        "https://ryuki.io/schemas/security-contracts/v1/conformance-trust-root-registry.schema.json",
    ),
    (
        "control-trace.schema.json",
        "https://ryuki.io/schemas/security-contracts/v1/control-trace.schema.json",
    ),
    (
        "deployment-security-profile.schema.json",
        "https://ryuki.io/schemas/security-contracts/v1/deployment-security-profile.schema.json",
    ),
    (
        "package-exit-receipt.schema.json",
        "https://ryuki.io/schemas/security-contracts/v1/package-exit-receipt.schema.json",
    ),
    (
        "provider-registry.schema.json",
        "https://ryuki.io/schemas/security-contracts/v1/provider-registry.schema.json",
    ),
    (
        "production-build-manifest.schema.json",
        "https://ryuki.io/schemas/security-contracts/v1/production-build-manifest.schema.json",
    ),
    (
        "public-ingress-attestation-envelope.schema.json",
        "https://ryuki.io/schemas/security-contracts/v1/public-ingress-attestation-envelope.schema.json",
    ),
    (
        "security-limit-profile.schema.json",
        "https://ryuki.io/schemas/security-contracts/v1/security-limit-profile.schema.json",
    ),
];

const INSTANCES: [(&str, &str); 6] = [
    (
        "action-resource-registry.implementation.json",
        "action-resource-registry.schema.json",
    ),
    (
        "control-trace.implementation.json",
        "control-trace.schema.json",
    ),
    (
        "conformance-trust-root-registry.implementation.json",
        "conformance-trust-root-registry.schema.json",
    ),
    (
        "deployment-security-profile.implementation.json",
        "deployment-security-profile.schema.json",
    ),
    (
        "provider-registry.implementation.json",
        "provider-registry.schema.json",
    ),
    (
        "security-limit-profile.implementation.json",
        "security-limit-profile.schema.json",
    ),
];

// This list is intentionally independent of control-trace.implementation.json.
// Editing the ledger cannot silently redefine the normative control inventory.
const CANONICAL_CONTROL_IDS: [&str; 135] = [
    "SB-BOUND-01",
    "SB-BOUND-02",
    "SB-IDL-01",
    "SB-AUTH-14",
    "SB-AUTH-15",
    "SB-AUTH-16",
    "SB-AUTH-17",
    "SB-IDL-02",
    "SB-EXT-04",
    "SB-EXT-05",
    "SB-EGR-03",
    "SB-MIG-01",
    "SB-MIG-02",
    "SB-MIG-03",
    "SB-OPS-07",
    "SB-OPS-08",
    "SB-CONF-01",
    "SB-CONF-02",
    "SB-CONF-03",
    "SB-CONF-04",
    "SB-CONF-05",
    "SB-CTX-01",
    "SB-SES-08",
    "SB-CFG-01",
    "SB-CFG-02",
    "SB-CFG-03",
    "SB-CFG-04",
    "SB-CFG-05",
    "SB-CFG-06",
    "SB-BOOT-01",
    "SB-BOOT-02",
    "SB-BOOT-03",
    "SB-AUTH-01",
    "SB-AUTH-02",
    "SB-AUTH-03",
    "SB-AUTH-04",
    "SB-AUTH-05",
    "SB-AUTH-06",
    "SB-AUTH-07",
    "SB-AUTH-08",
    "SB-AUTH-09",
    "SB-AUTH-10",
    "SB-AUTH-11",
    "SB-AUTH-12",
    "SB-AUTH-13",
    "SB-SES-01",
    "SB-SES-02",
    "SB-SES-03",
    "SB-SES-04",
    "SB-SES-05",
    "SB-SES-06",
    "SB-SES-07",
    "SB-TOK-01",
    "SB-TOK-02",
    "SB-TOK-03",
    "SB-TOK-04",
    "SB-AZ-01",
    "SB-AZ-02",
    "SB-AZ-03",
    "SB-AZ-04",
    "SB-AZ-05",
    "SB-AZ-06",
    "SB-AZ-07",
    "SB-AZ-08",
    "SB-AZ-09",
    "SB-AZ-09A",
    "SB-AZ-10",
    "SB-APR-01",
    "SB-APR-02",
    "SB-APR-03",
    "SB-APR-04",
    "SB-APR-05",
    "SB-APR-06",
    "SB-MID-01",
    "SB-MID-02",
    "SB-MID-03",
    "SB-MID-04",
    "SB-MID-05",
    "SB-EXEC-01",
    "SB-EXEC-02",
    "SB-EXEC-03",
    "SB-EXEC-04",
    "SB-SEC-01",
    "SB-SEC-02",
    "SB-SEC-03",
    "SB-SEC-04",
    "SB-SEC-05",
    "SB-SEC-06",
    "SB-SEC-07",
    "SB-SEC-08",
    "SB-SEC-09",
    "SB-SEC-10",
    "SB-CERT-01",
    "SB-EXT-01",
    "SB-EXT-02",
    "SB-EXT-03",
    "SB-EGR-01",
    "SB-EGR-02",
    "SB-EVO-01",
    "SB-EVO-02",
    "SB-EVO-03",
    "SB-HA-01",
    "SB-HA-02",
    "SB-HA-03",
    "SB-HA-04",
    "SB-DATA-01",
    "SB-DATA-02",
    "SB-DATA-03",
    "SB-DATA-04",
    "SB-DATA-05",
    "SB-GOV-01",
    "SB-GOV-02",
    "SB-CRY-01",
    "SB-OPS-01",
    "SB-OPS-02",
    "SB-OPS-03",
    "SB-OPS-04",
    "SB-OPS-05",
    "SB-OPS-06",
    "SB-OBS-01",
    "SB-LIM-01",
    "SB-ING-01",
    "SB-ING-02",
    "SB-ING-03",
    "SB-ING-04",
    "SB-AUD-01",
    "SB-AUD-02",
    "SB-AUD-03",
    "SB-AUD-04",
    "SB-SC-01",
    "SB-SC-02",
    "SB-SC-03",
    "SB-SC-04",
    "SB-SC-05",
    "SB-SC-06",
];

#[derive(Debug)]
struct OfflineRetriever;

impl Retrieve for OfflineRetriever {
    fn retrieve(&self, uri: &Uri<String>) -> Result<Value, Box<dyn Error + Send + Sync>> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("offline schema retrieval denied for {uri}"),
        )
        .into())
    }
}

/// A serde_json value decoder that rejects duplicate object keys at every
/// nesting level. Ordinary `serde_json::Value` parsing keeps the last value,
/// which is unsuitable for security contracts because different consumers
/// can otherwise interpret the same bytes differently.
struct DuplicateCheckedValue(Value);

impl<'de> Deserialize<'de> for DuplicateCheckedValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateCheckedValueVisitor)
    }
}

struct DuplicateCheckedValueVisitor;

impl<'de> Visitor<'de> for DuplicateCheckedValueVisitor {
    type Value = DuplicateCheckedValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(DuplicateCheckedValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedValue(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        DuplicateCheckedValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<DuplicateCheckedValue>()? {
            values.push(value.0);
        }
        Ok(DuplicateCheckedValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom(format!(
                    "duplicate JSON object key {key:?}"
                )));
            }
            let value = object.next_value::<DuplicateCheckedValue>()?;
            values.insert(key, value.0);
        }
        Ok(DuplicateCheckedValue(Value::Object(values)))
    }
}

fn parse_json_strict(bytes: &[u8]) -> Result<Value, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = DuplicateCheckedValue::deserialize(&mut deserializer)?.0;
    deserializer.end()?;
    Ok(value)
}

/// Validate the complete repository-local security contract set.
///
/// Infrastructure or operator evidence is intentionally not manufactured by
/// this gate.  With no conformance bundles or receipts checked in, the only
/// honest state is `implementation_only` and `production_accepted: false`.
pub(crate) fn validate_repository(root: &Path) -> Result<Vec<String>, String> {
    let contract_dir = root.join(CONTRACT_DIR);
    let mut errors = Vec::new();

    validate_contract_file_inventory(&contract_dir, &mut errors)?;

    let mut schemas = BTreeMap::new();
    for (file_name, expected_id) in SCHEMAS {
        let path = contract_dir.join(file_name);
        let Some(schema) = read_json_if_present(&path, &mut errors)? else {
            continue;
        };
        validate_schema_document(file_name, expected_id, &schema, &mut errors);
        schemas.insert(file_name, schema);
    }

    let mut instances = BTreeMap::new();
    for (file_name, schema_name) in INSTANCES {
        let path = contract_dir.join(file_name);
        let Some(instance) = read_json_if_present(&path, &mut errors)? else {
            continue;
        };
        if let Some(schema) = schemas.get(schema_name) {
            validate_instance(file_name, schema_name, schema, &instance, &mut errors);
        }
        validate_declared_schema(file_name, schema_name, &instance, &mut errors);
        // The manifest is detached and therefore not an INSTANCES entry today.
        // Keep dispatch here so a future checked-in instance cannot silently
        // bypass the semantic layer when it is added to the inventory.
        if schema_name == "production-build-manifest.schema.json" {
            validate_production_build_manifest_semantics(file_name, &instance, &mut errors);
        }
        validate_recursive_content_references(root, file_name, &instance, "", &mut errors);
        instances.insert(file_name, instance);
    }

    let bundles = load_closure_documents(
        root,
        &contract_dir.join("conformance-bundles"),
        "conformance-bundle.schema.json",
        schemas.get("conformance-bundle.schema.json"),
        &mut errors,
    )?;
    let receipts = load_closure_documents(
        root,
        &contract_dir.join("package-exit-receipts"),
        "package-exit-receipt.schema.json",
        schemas.get("package-exit-receipt.schema.json"),
        &mut errors,
    )?;

    // Repository validation is deliberately structural and implementation-only.
    // A separate production-closure verifier must authenticate signatures and
    // trust roots, derive the complete applicability matrix from authoritative
    // deployment state, bind the current revision/configuration, and validate
    // tuple-scoped waivers. Until that verifier exists, no checked-in closure
    // document can become authority merely by being internally self-consistent.
    reject_untrusted_closure_documents(&bundles, &receipts, &mut errors);

    if let Some(ledger) = instances.get("control-trace.implementation.json") {
        validate_ledger_semantics(ledger, &mut errors);
        validate_closure_semantics(root, ledger, &bundles, &receipts, &mut errors);
    }
    validate_cross_document_semantics(root, &instances, &mut errors);
    validate_implementation_only_honesty(&instances, &bundles, &receipts, &mut errors);

    errors.sort();
    errors.dedup();
    Ok(errors)
}

fn reject_untrusted_closure_documents(
    bundles: &[LoadedDocument],
    receipts: &[LoadedDocument],
    errors: &mut Vec<String>,
) {
    if !bundles.is_empty() || !receipts.is_empty() {
        errors.push(
            "conformance bundles and package exit receipts are not accepted by the repository-local gate; trusted production-closure verification is not implemented"
                .to_string(),
        );
    }
}

fn read_json_if_present(path: &Path, errors: &mut Vec<String>) -> Result<Option<Value>, String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            errors.push(format!("missing required contract file {}", path.display()));
            return Ok(None);
        }
        Err(error) => {
            return Err(format!("failed to inspect {}: {error}", path.display()));
        }
    };
    if !metadata.file_type().is_file() {
        errors.push(format!(
            "contract path must be a regular file: {}",
            path.display()
        ));
        return Ok(None);
    }
    let raw =
        fs::read(path).map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    match parse_json_strict(&raw) {
        Ok(value) => Ok(Some(value)),
        Err(error) => {
            errors.push(format!("invalid JSON in {}: {error}", path.display()));
            Ok(None)
        }
    }
}

#[derive(Clone, Debug)]
struct LoadedDocument {
    label: String,
    value: Value,
    digest: String,
}

fn load_closure_documents(
    root: &Path,
    directory: &Path,
    schema_name: &str,
    schema: Option<&Value>,
    errors: &mut Vec<String>,
) -> Result<Vec<LoadedDocument>, String> {
    if !directory.exists() {
        return Ok(Vec::new());
    }
    let metadata = fs::symlink_metadata(directory)
        .map_err(|error| format!("failed to inspect {}: {error}", directory.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        errors.push(format!(
            "closure evidence path must be a regular directory, not a symlink: {}",
            directory.display()
        ));
        return Ok(Vec::new());
    }

    let mut paths = Vec::new();
    collect_closure_paths(directory, directory, &mut paths, errors)?;
    paths.sort();
    let mut documents = Vec::new();
    for path in paths {
        let relative = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let bytes = fs::read(&path)
            .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
        let value: Value = match parse_json_strict(&bytes) {
            Ok(value) => value,
            Err(error) => {
                errors.push(format!("invalid JSON in {relative}: {error}"));
                continue;
            }
        };
        if let Some(schema) = schema {
            validate_instance(&relative, schema_name, schema, &value, errors);
        }
        validate_recursive_content_references(root, &relative, &value, "", errors);
        documents.push(LoadedDocument {
            label: relative,
            value,
            digest: format!("sha256:{:x}", Sha256::digest(&bytes)),
        });
    }
    Ok(documents)
}

fn collect_closure_paths(
    base: &Path,
    directory: &Path,
    paths: &mut Vec<PathBuf>,
    errors: &mut Vec<String>,
) -> Result<(), String> {
    let mut entries = fs::read_dir(directory)
        .map_err(|error| format!("failed to read {}: {error}", directory.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("failed to enumerate {}: {error}", directory.display()))?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?;
        if file_type.is_symlink() {
            errors.push(format!(
                "closure evidence inventory forbids symlinks: {}",
                path.display()
            ));
        } else if file_type.is_dir() {
            collect_closure_paths(base, &path, paths, errors)?;
        } else if file_type.is_file() {
            if path.extension().and_then(|extension| extension.to_str()) == Some("json") {
                paths.push(path);
            } else {
                errors.push(format!(
                    "closure evidence directory contains a non-JSON file: {}",
                    path.display()
                ));
            }
        } else {
            errors.push(format!(
                "closure evidence inventory contains a non-regular entry below {}: {}",
                base.display(),
                path.display()
            ));
        }
    }
    Ok(())
}

fn validate_contract_file_inventory(
    contract_dir: &Path,
    errors: &mut Vec<String>,
) -> Result<(), String> {
    let expected_schemas: BTreeSet<&str> = SCHEMAS.iter().map(|(name, _)| *name).collect();
    let expected_instances: BTreeSet<&str> = INSTANCES.iter().map(|(name, _)| *name).collect();
    let mut actual_schemas = BTreeSet::new();
    let mut actual_instances = BTreeSet::new();

    let entries = fs::read_dir(contract_dir)
        .map_err(|error| format!("failed to read {}: {error}", contract_dir.display()))?;
    for entry in entries {
        let entry = entry
            .map_err(|error| format!("failed to enumerate {}: {error}", contract_dir.display()))?;
        let file_type = entry
            .file_type()
            .map_err(|error| format!("failed to inspect {}: {error}", entry.path().display()))?;
        if file_type.is_symlink() {
            errors.push(format!(
                "security contract inventory forbids symlinks: {}",
                entry.path().display()
            ));
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(".schema.json") {
            actual_schemas.insert(name);
        } else if name.ends_with(".implementation.json") {
            actual_instances.insert(name);
        } else if name.ends_with(".json") {
            errors.push(format!(
                "unrecognized root security contract JSON file: {}",
                entry.path().display()
            ));
        }
    }

    report_set_delta(
        "schema file",
        &expected_schemas
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
        &actual_schemas,
        errors,
    );
    report_set_delta(
        "implementation instance",
        &expected_instances
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
        &actual_instances,
        errors,
    );
    Ok(())
}

fn validate_schema_document(
    file_name: &str,
    expected_id: &str,
    schema: &Value,
    errors: &mut Vec<String>,
) {
    if schema.get("$schema").and_then(Value::as_str)
        != Some("https://json-schema.org/draft/2020-12/schema")
    {
        errors.push(format!(
            "{file_name}: $schema must select JSON Schema Draft 2020-12"
        ));
    }
    if schema.get("$id").and_then(Value::as_str) != Some(expected_id) {
        errors.push(format!(
            "{file_name}: $id must be the canonical URI {expected_id}"
        ));
    }

    validate_closed_object_schemas(file_name, schema, "", errors);

    let meta = jsonschema::draft202012::meta::validator();
    for error in meta.iter_errors(schema) {
        errors.push(format_schema_error(file_name, "meta-schema", &error));
    }

    if let Err(error) = jsonschema::draft202012::options()
        .should_validate_formats(true)
        .with_retriever(OfflineRetriever)
        .build(schema)
    {
        errors.push(format!(
            "{file_name}: schema compilation failed with offline resolution: {error}"
        ));
    }
}

fn validate_closed_object_schemas(
    file_name: &str,
    schema: &Value,
    pointer: &str,
    errors: &mut Vec<String>,
) {
    match schema {
        Value::Object(object) => {
            if object.get("type").and_then(Value::as_str) == Some("object")
                && object.get("additionalProperties").and_then(Value::as_bool) != Some(false)
            {
                errors.push(format!(
                    "{file_name}: object schema at {} must set additionalProperties to false",
                    display_json_pointer(pointer)
                ));
            }
            for (key, child) in object {
                validate_closed_object_schemas(
                    file_name,
                    child,
                    &format!("{pointer}/{}", escape_json_pointer(key)),
                    errors,
                );
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                validate_closed_object_schemas(
                    file_name,
                    child,
                    &format!("{pointer}/{index}"),
                    errors,
                );
            }
        }
        _ => {}
    }
}

fn validate_instance(
    file_name: &str,
    schema_name: &str,
    schema: &Value,
    instance: &Value,
    errors: &mut Vec<String>,
) {
    let validator = match jsonschema::draft202012::options()
        .should_validate_formats(true)
        .with_retriever(OfflineRetriever)
        .build(schema)
    {
        Ok(validator) => validator,
        Err(error) => {
            errors.push(format!(
                "{file_name}: cannot validate instance because {schema_name} did not compile: {error}"
            ));
            return;
        }
    };

    for error in validator.iter_errors(instance) {
        errors.push(format_schema_error(file_name, schema_name, &error));
    }
}

fn format_schema_error(
    file_name: &str,
    schema_name: &str,
    error: &jsonschema::ValidationError<'_>,
) -> String {
    format!(
        "{file_name}: {schema_name} rejected instance at {} via {}: {}",
        display_json_pointer(error.instance_path().as_str()),
        display_json_pointer(error.schema_path().as_str()),
        error.masked()
    )
}

fn display_json_pointer(pointer: &str) -> &str {
    if pointer.is_empty() {
        "/"
    } else {
        pointer
    }
}

fn validate_declared_schema(
    file_name: &str,
    schema_name: &str,
    instance: &Value,
    errors: &mut Vec<String>,
) {
    let expected = SCHEMAS
        .iter()
        .find_map(|(name, id)| (*name == schema_name).then_some(*id));
    if instance.get("$schema").and_then(Value::as_str) != expected {
        errors.push(format!(
            "{file_name}: $schema must reference the canonical {schema_name} URI"
        ));
    }
}

/// Validate the typed v2 build-manifest contract and its document-internal
/// applicability closure. Exact membership against the independently pinned
/// ControlTrace is still enforced by the runtime loader; this repository gate
/// rejects malformed identities, stale inventory bindings, and cross-field
/// gaps without treating manifest-owned rows as an authority source.
fn validate_production_build_manifest_semantics(
    file_name: &str,
    manifest: &Value,
    errors: &mut Vec<String>,
) {
    let error_start = errors.len();
    let manifest = match serde_json::from_value::<ProductionBuildManifest>(manifest.clone()) {
        Ok(manifest) => manifest,
        Err(error) => {
            errors.push(format!(
                "{file_name}: production build manifest typed decode failed: {error}"
            ));
            return;
        }
    };

    for error in manifest
        .validate_semantics()
        .into_iter()
        .take(MAX_PRODUCTION_BUILD_SEMANTIC_ERRORS)
    {
        if errors.len().saturating_sub(error_start) >= MAX_PRODUCTION_BUILD_SEMANTIC_ERRORS {
            break;
        }
        errors.push(format!(
            "{file_name}: production build manifest semantic error: {error}"
        ));
    }
}

#[derive(Clone, Debug)]
struct Owner {
    package: String,
    team: String,
}

fn validate_ledger_semantics(ledger: &Value, errors: &mut Vec<String>) {
    let canonical_controls: BTreeSet<String> = CANONICAL_CONTROL_IDS
        .iter()
        .map(|id| (*id).to_string())
        .collect();
    let canonical_cases: BTreeSet<String> = (1..=55).map(|n| format!("AC-{n:03}")).collect();

    let controls = array(ledger, "controls");
    let acceptance_cases = array(ledger, "acceptance_cases");
    let traces = array(ledger, "traces");

    let mut control_owners = BTreeMap::new();
    let mut waivable = BTreeMap::new();
    let mut actual_controls = BTreeSet::new();
    for (index, control) in controls.iter().enumerate() {
        let path = format!("control-trace.implementation.json:/controls/{index}");
        let Some(control_id) = string_field(control, "control_id") else {
            continue;
        };
        if !actual_controls.insert(control_id.to_string()) {
            errors.push(format!("{path}: duplicate control_id {control_id}"));
        }
        let owner = owner_from(control, &path, errors);
        if let Some(previous) = control_owners.insert(control_id.to_string(), owner.clone()) {
            if previous.package != owner.package || previous.team != owner.team {
                errors.push(format!(
                    "{path}: control {control_id} is multiply owned by {}/{} and {}/{}",
                    previous.package, previous.team, owner.package, owner.team
                ));
            }
        }
        waivable.insert(
            control_id.to_string(),
            control
                .get("waivable")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        );
    }
    report_set_delta(
        "canonical control",
        &canonical_controls,
        &actual_controls,
        errors,
    );

    let mut case_owners = BTreeMap::new();
    let mut actual_cases = BTreeSet::new();
    for (index, case) in acceptance_cases.iter().enumerate() {
        let path = format!("control-trace.implementation.json:/acceptance_cases/{index}");
        let Some(case_id) = string_field(case, "acceptance_case_id") else {
            continue;
        };
        if !actual_cases.insert(case_id.to_string()) {
            errors.push(format!("{path}: duplicate acceptance_case_id {case_id}"));
        }
        let owner = owner_from(case, &path, errors);
        if let Some(previous) = case_owners.insert(case_id.to_string(), owner.clone()) {
            if previous.package != owner.package || previous.team != owner.team {
                errors.push(format!(
                    "{path}: acceptance case {case_id} is multiply owned by {}/{} and {}/{}",
                    previous.package, previous.team, owner.package, owner.team
                ));
            }
        }
    }
    report_set_delta(
        "permanent acceptance case",
        &canonical_cases,
        &actual_cases,
        errors,
    );

    let mut trace_ids = BTreeSet::new();
    let mut mapping_tuples = BTreeSet::new();
    let mut traced_controls = BTreeSet::new();
    let mut traced_cases = BTreeSet::new();
    let mut active_controls = BTreeSet::new();
    let mut active_cases = BTreeSet::new();
    let mut supersession = BTreeMap::new();

    for (index, trace) in traces.iter().enumerate() {
        let path = format!("control-trace.implementation.json:/traces/{index}");
        let Some(trace_id) = string_field(trace, "trace_id") else {
            continue;
        };
        if !trace_ids.insert(trace_id.to_string()) {
            errors.push(format!("{path}: duplicate trace_id {trace_id}"));
        }

        let control_id = string_field(trace, "control_id").unwrap_or("");
        let case_id = string_field(trace, "acceptance_case_id").unwrap_or("");
        if !actual_controls.contains(control_id) {
            errors.push(format!(
                "{path}: trace {trace_id} references unknown control {control_id}"
            ));
        } else {
            traced_controls.insert(control_id.to_string());
        }
        if !actual_cases.contains(case_id) {
            errors.push(format!(
                "{path}: trace {trace_id} references unknown acceptance case {case_id}"
            ));
        } else {
            traced_cases.insert(case_id.to_string());
        }

        let trace_owner = owner_from(trace, &path, errors);
        if let Some(owner) = control_owners.get(control_id) {
            require_matching_owner("control", control_id, owner, &trace_owner, &path, errors);
        }
        if let Some(owner) = case_owners.get(case_id) {
            require_matching_owner(
                "acceptance case",
                case_id,
                owner,
                &trace_owner,
                &path,
                errors,
            );
        }

        let fixture = string_field(trace, "fixture_or_probe_id").unwrap_or("");
        let applicability = trace
            .get("applicability_expression")
            .map(canonical_json)
            .unwrap_or_else(|| "null".to_string());
        let tuple = format!("{control_id}\u{1f}{case_id}\u{1f}{applicability}\u{1f}{fixture}");
        if !mapping_tuples.insert(tuple) {
            errors.push(format!(
                "{path}: duplicate static mapping tuple for {control_id}/{case_id}/{fixture}"
            ));
        }

        validate_dimension_declarations(trace, &path, errors);
        let lifecycle = string_field(trace, "trace_lifecycle").unwrap_or("");
        if lifecycle == "active" {
            active_controls.insert(control_id.to_string());
            active_cases.insert(case_id.to_string());
        }
        if let Some(target) = trace.get("supersedes_trace_id").and_then(Value::as_str) {
            if target == trace_id {
                errors.push(format!("{path}: trace {trace_id} cannot supersede itself"));
            }
            supersession.insert(trace_id.to_string(), target.to_string());
        }
    }

    for (trace_id, target) in &supersession {
        if !trace_ids.contains(target) {
            errors.push(format!(
                "control-trace.implementation.json: trace {trace_id} supersedes unknown trace {target}"
            ));
        }
    }
    detect_single_edge_cycles("trace supersession", &supersession, errors);
    report_set_delta(
        "control with any trace",
        &actual_controls,
        &traced_controls,
        errors,
    );
    report_set_delta(
        "acceptance case with any trace",
        &actual_cases,
        &traced_cases,
        errors,
    );
    report_set_delta(
        "control with an active trace",
        &actual_controls,
        &active_controls,
        errors,
    );
    report_set_delta(
        "acceptance case with an active trace",
        &actual_cases,
        &active_cases,
        errors,
    );

    // Keep this binding explicit for receipt validation and to make a schema
    // edit unable to broaden waiver authority implicitly.
    for control_id in actual_controls {
        if !waivable.contains_key(&control_id) {
            errors.push(format!(
                "control-trace.implementation.json: control {control_id} has no explicit waivable decision"
            ));
        }
    }
}

/// Validate diagnostic relationships inside untrusted draft closure files.
/// Passing this function never makes a bundle or receipt authoritative; the
/// repository gate rejects all such files until trusted closure mode exists.
fn validate_closure_semantics(
    root: &Path,
    ledger: &Value,
    bundles: &[LoadedDocument],
    receipts: &[LoadedDocument],
    errors: &mut Vec<String>,
) {
    validate_closure_semantics_at(root, ledger, bundles, receipts, Utc::now(), errors);
}

fn validate_closure_semantics_at(
    root: &Path,
    ledger: &Value,
    bundles: &[LoadedDocument],
    receipts: &[LoadedDocument],
    now: DateTime<Utc>,
    errors: &mut Vec<String>,
) {
    let traces: BTreeMap<String, &Value> = array(ledger, "traces")
        .iter()
        .filter_map(|trace| string_field(trace, "trace_id").map(|id| (id.to_string(), trace)))
        .collect();
    let controls: BTreeMap<String, &Value> = array(ledger, "controls")
        .iter()
        .filter_map(|control| {
            string_field(control, "control_id").map(|id| (id.to_string(), control))
        })
        .collect();

    let expected_deployment_profile_binding = load_deployment_profile_binding(root);
    let expected_profile_version_bindings = load_deployment_profile_version_bindings(root);
    for document in bundles {
        validate_deployment_profile_binding(
            document.value.pointer("/bindings/deployment_profile"),
            expected_deployment_profile_binding.as_ref(),
            &format!("{}:/bindings/deployment_profile", document.label),
            errors,
        );
        validate_profile_version_bindings(
            document.value.pointer("/bindings"),
            expected_profile_version_bindings.as_ref(),
            &format!("{}:/bindings", document.label),
            errors,
        );
    }
    for document in receipts {
        validate_deployment_profile_binding(
            document
                .value
                .pointer("/closure_context/deployment_profile"),
            expected_deployment_profile_binding.as_ref(),
            &format!("{}:/closure_context/deployment_profile", document.label),
            errors,
        );
        validate_profile_version_bindings(
            document.value.pointer("/closure_context"),
            expected_profile_version_bindings.as_ref(),
            &format!("{}:/closure_context", document.label),
            errors,
        );
    }

    let mut bundle_ids = BTreeSet::new();
    let mut evidence = BTreeMap::new();
    let mut evidence_supersession = BTreeMap::new();
    let mut evidence_successor_by_target = BTreeMap::new();
    let mut forked_evidence_targets = BTreeSet::new();
    for document in bundles {
        let bundle = &document.value;
        let bundle_id = string_field(bundle, "bundle_id").unwrap_or("");
        let evidence_id = string_field(bundle, "evidence_instance_id").unwrap_or("");
        if !bundle_ids.insert(bundle_id.to_string()) {
            errors.push(format!(
                "{}: duplicate bundle_id {bundle_id}",
                document.label
            ));
        }
        if let Some(previous) = evidence.insert(evidence_id.to_string(), document) {
            errors.push(format!(
                "{}: duplicate evidence_instance_id {evidence_id}; first declared by {}",
                document.label, previous.label
            ));
        }
        let target = bundle
            .get("supersedes_evidence_instance_id")
            .and_then(Value::as_str);
        let has_reference = bundle
            .get("supersedes_evidence_ref")
            .is_some_and(|reference| !reference.is_null());
        if target.is_some() != has_reference {
            errors.push(format!(
                "{}: supersedes_evidence_instance_id and supersedes_evidence_ref must both be null or both identify the predecessor",
                document.label
            ));
        }
        if let Some(target) = target {
            if target == evidence_id {
                errors.push(format!(
                    "{}: evidence instance {evidence_id} cannot supersede itself",
                    document.label
                ));
            }
            if let Some(previous_successor) =
                evidence_successor_by_target.insert(target.to_string(), evidence_id.to_string())
            {
                forked_evidence_targets.insert(target.to_string());
                errors.push(format!(
                    "{}: evidence predecessor {target} has multiple successors {previous_successor} and {evidence_id}",
                    document.label
                ));
            }
            evidence_supersession.insert(evidence_id.to_string(), target.to_string());
        }
        let trace_id = string_field(bundle, "trace_id").unwrap_or("");
        let Some(trace) = traces.get(trace_id) else {
            errors.push(format!(
                "{}: bundle references unknown trace_id {trace_id}",
                document.label
            ));
            continue;
        };
        for key in ["control_id", "acceptance_case_id"] {
            if bundle.get(key) != trace.get(key) {
                errors.push(format!(
                    "{}: {key} does not match ControlTrace row {trace_id}",
                    document.label
                ));
            }
        }
        validate_bundle_applicability(document, trace, errors);
        validate_bundle_timestamps(document, errors);
    }
    let mut superseded_evidence = BTreeSet::new();
    for (source, target) in &evidence_supersession {
        let mut valid_lineage = source != target && !forked_evidence_targets.contains(target);
        let Some(source_bundle) = evidence.get(source) else {
            continue;
        };
        let Some(target_bundle) = evidence.get(target) else {
            errors.push(format!(
                "evidence instance {source} supersedes unknown evidence instance {target}"
            ));
            continue;
        };
        valid_lineage &=
            validate_evidence_supersession_reference(source_bundle, target_bundle, target, errors);
        for field in ["trace_id", "applicability_instance_id"] {
            if source_bundle.value.get(field) != target_bundle.value.get(field) {
                valid_lineage = false;
                errors.push(format!(
                    "{}: evidence {source} cannot supersede {target} with a different {field}",
                    source_bundle.label
                ));
            }
        }
        let source_version = source_bundle
            .value
            .get("document_version")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let target_version = target_bundle
            .value
            .get("document_version")
            .and_then(Value::as_u64)
            .unwrap_or(u64::MAX);
        if source_version <= target_version {
            valid_lineage = false;
            errors.push(format!(
                "{}: superseding evidence {source} document_version {source_version} must exceed {target_version}",
                source_bundle.label
            ));
        }
        let source_tier = source_bundle
            .value
            .pointer("/provenance/evidence_tier/rank")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let target_tier = target_bundle
            .value
            .pointer("/provenance/evidence_tier/rank")
            .and_then(Value::as_u64)
            .unwrap_or(u64::MAX);
        if source_tier < target_tier {
            valid_lineage = false;
            errors.push(format!(
                "{}: superseding evidence {source} tier rank {source_tier} must not be below predecessor {target} rank {target_tier}",
                source_bundle.label
            ));
        }
        if valid_lineage {
            superseded_evidence.insert(target.clone());
        }
    }
    detect_single_edge_cycles("evidence supersession", &evidence_supersession, errors);

    let ledger_digest = fs::read(
        root.join(CONTRACT_DIR)
            .join("control-trace.implementation.json"),
    )
    .ok()
    .map(|bytes| format!("sha256:{:x}", Sha256::digest(bytes)));
    validate_receipts(
        ledger,
        ledger_digest.as_deref(),
        &traces,
        &controls,
        &evidence,
        &superseded_evidence,
        receipts,
        now,
        errors,
    );
}

fn timestamp_field(
    document: &LoadedDocument,
    field: &str,
    errors: &mut Vec<String>,
) -> Option<DateTime<Utc>> {
    let raw = string_field(&document.value, field)?;
    match DateTime::parse_from_rfc3339(raw) {
        Ok(value) => Some(value.with_timezone(&Utc)),
        Err(error) => {
            errors.push(format!(
                "{}: invalid {field} timestamp: {error}",
                document.label
            ));
            None
        }
    }
}

fn optional_timestamp_field(
    document: &LoadedDocument,
    field: &str,
    errors: &mut Vec<String>,
) -> Option<DateTime<Utc>> {
    if document.value.get(field).is_none_or(Value::is_null) {
        None
    } else {
        timestamp_field(document, field, errors)
    }
}

fn validate_bundle_timestamps(document: &LoadedDocument, errors: &mut Vec<String>) {
    let produced = timestamp_field(document, "produced_at", errors);
    let verified = optional_timestamp_field(document, "verified_at", errors);
    let accepted = optional_timestamp_field(document, "accepted_at", errors);
    let expires = timestamp_field(document, "expires_at", errors);

    if produced
        .zip(verified)
        .is_some_and(|(left, right)| left > right)
    {
        errors.push(format!(
            "{}: produced_at must not be after verified_at",
            document.label
        ));
    }
    if verified
        .zip(accepted)
        .is_some_and(|(left, right)| left > right)
    {
        errors.push(format!(
            "{}: verified_at must not be after accepted_at",
            document.label
        ));
    }
    if accepted
        .zip(expires)
        .is_some_and(|(left, right)| left >= right)
    {
        errors.push(format!(
            "{}: accepted_at must be before expires_at",
            document.label
        ));
    }
}

fn validate_bundle_applicability(
    document: &LoadedDocument,
    trace: &Value,
    errors: &mut Vec<String>,
) {
    let bundle = &document.value;
    let evaluated = bundle
        .get("evaluated_applicability")
        .unwrap_or(&Value::Null);
    let declared = trace
        .get("evidence_instance_dimensions")
        .unwrap_or(&Value::Null);
    let expression = trace
        .get("applicability_expression")
        .unwrap_or(&Value::Null);
    let evidence_rank = bundle
        .pointer("/provenance/evidence_tier/rank")
        .and_then(Value::as_u64)
        .unwrap_or(0);

    for scope in ["implementation", "deployment"] {
        let evaluation = evaluated.get(scope).unwrap_or(&Value::Null);
        let applicable = evaluation
            .get("applicable")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let actual_dimensions: BTreeSet<String> = array(evaluation, "dimensions")
            .iter()
            .filter_map(|dimension| string_field(dimension, "name"))
            .map(str::to_string)
            .collect();
        let expected_dimensions = string_set(array(declared, scope));
        if applicable && actual_dimensions != expected_dimensions {
            errors.push(format!(
                "{}: {scope} evidence dimensions {:?} do not exactly match trace dimensions {:?}",
                document.label, actual_dimensions, expected_dimensions
            ));
        }
        if !applicable && !actual_dimensions.is_empty() {
            errors.push(format!(
                "{}: non-applicable {scope} evidence must not carry evaluated dimensions",
                document.label
            ));
        }
        let scope_has_minimum_tier = trace
            .pointer(&format!("/minimum_evidence_tier/{scope}"))
            .is_some_and(|tier| !tier.is_null());
        if !scope_has_minimum_tier {
            if applicable {
                errors.push(format!(
                    "{}: {scope} evidence is applicable even though the trace has no minimum evidence tier for that scope",
                    document.label
                ));
            }
            continue;
        }
        match expression
            .get(scope)
            .and_then(|value| string_field(value, "operator"))
        {
            Some("always") if !applicable => errors.push(format!(
                "{}: applicability mismatch; trace requires {scope} evidence",
                document.label
            )),
            Some("never") if applicable => errors.push(format!(
                "{}: applicability mismatch; trace excludes {scope} evidence",
                document.label
            )),
            _ => {}
        }
        if applicable {
            if let Some(minimum_rank) = trace
                .pointer(&format!("/minimum_evidence_tier/{scope}/rank"))
                .and_then(Value::as_u64)
            {
                if evidence_rank < minimum_rank {
                    errors.push(format!(
                        "{}: evidence tier rank {evidence_rank} is below {scope} minimum {minimum_rank}",
                        document.label
                    ));
                }
            }
        }
    }
}

fn dimension_map(
    value: &Value,
    scope: &str,
    context: &str,
    errors: &mut Vec<String>,
) -> BTreeMap<String, Value> {
    let mut dimensions = BTreeMap::new();
    for dimension in array(value, scope) {
        let name = string_field(dimension, "name").unwrap_or("");
        let selected = dimension.get("value").cloned().unwrap_or(Value::Null);
        if dimensions.insert(name.to_string(), selected).is_some() {
            errors.push(format!(
                "{context}: duplicate {scope} applicability dimension {name}"
            ));
        }
    }
    dimensions
}

fn evaluate_expression(
    expression: &Value,
    dimensions: &BTreeMap<String, Value>,
) -> Result<bool, String> {
    let mut nodes = 0;
    evaluate_expression_bounded(expression, dimensions, 0, &mut nodes)
}

fn evaluate_expression_bounded(
    expression: &Value,
    dimensions: &BTreeMap<String, Value>,
    depth: usize,
    nodes: &mut usize,
) -> Result<bool, String> {
    if depth > MAX_APPLICABILITY_EXPRESSION_DEPTH {
        return Err("applicability expression exceeds maximum depth".to_string());
    }
    *nodes += 1;
    if *nodes > MAX_APPLICABILITY_EXPRESSION_NODES {
        return Err("applicability expression exceeds maximum node count".to_string());
    }
    let operator = string_field(expression, "operator")
        .ok_or_else(|| "applicability expression omits operator".to_string())?;
    match operator {
        "always" => Ok(true),
        "never" => Ok(false),
        "all" | "any" => {
            let operands = array(expression, "operands");
            if operands.is_empty() || operands.len() > MAX_APPLICABILITY_EXPRESSION_OPERANDS {
                return Err(format!(
                    "{operator} applicability expression must have 1 through {MAX_APPLICABILITY_EXPRESSION_OPERANDS} operands"
                ));
            }
            let mut results = Vec::with_capacity(operands.len());
            for operand in operands {
                results.push(evaluate_expression_bounded(
                    operand,
                    dimensions,
                    depth + 1,
                    nodes,
                )?);
            }
            Ok(if operator == "all" {
                results.into_iter().all(|result| result)
            } else {
                results.into_iter().any(|result| result)
            })
        }
        "not" => Ok(!evaluate_expression_bounded(
            expression
                .get("operand")
                .ok_or_else(|| "not expression omits operand".to_string())?,
            dimensions,
            depth + 1,
            nodes,
        )?),
        "equals" | "not_equals" | "contains" => {
            let dimension = string_field(expression, "dimension")
                .ok_or_else(|| format!("{operator} expression omits dimension"))?;
            let actual = dimensions
                .get(dimension)
                .ok_or_else(|| format!("applicability dimension {dimension} is missing"))?;
            let expected = expression
                .get("value")
                .ok_or_else(|| format!("{operator} expression omits value"))?;
            match operator {
                "equals" => Ok(actual == expected),
                "not_equals" => Ok(actual != expected),
                "contains" => match (actual, expected) {
                    (Value::Array(values), expected) => Ok(values.contains(expected)),
                    (Value::String(actual), Value::String(expected)) => {
                        Ok(actual.contains(expected))
                    }
                    _ => Err(format!(
                        "contains requires an array or string dimension: {dimension}"
                    )),
                },
                _ => unreachable!(),
            }
        }
        "in" | "not_in" => {
            let dimension = string_field(expression, "dimension")
                .ok_or_else(|| format!("{operator} expression omits dimension"))?;
            let actual = dimensions
                .get(dimension)
                .ok_or_else(|| format!("applicability dimension {dimension} is missing"))?;
            if actual.is_array() {
                return Err(format!(
                    "{operator} requires a scalar applicability dimension: {dimension}"
                ));
            }
            let present = array(expression, "values").contains(actual);
            Ok(if operator == "in" { present } else { !present })
        }
        _ => Err(format!("unsupported applicability operator {operator}")),
    }
}

fn evaluate_trace_scope(
    document: &LoadedDocument,
    trace: &Value,
    instance: &Value,
    scope: &str,
    errors: &mut Vec<String>,
) -> Option<bool> {
    if trace
        .pointer(&format!("/minimum_evidence_tier/{scope}"))
        .is_none_or(Value::is_null)
    {
        return Some(false);
    }
    let dimensions = dimension_map(
        instance,
        &format!("{scope}_dimensions"),
        &document.label,
        errors,
    );
    let expression = trace.pointer(&format!("/applicability_expression/{scope}"))?;
    match evaluate_expression(expression, &dimensions) {
        Ok(applicable) => Some(applicable),
        Err(error) => {
            let trace_id = string_field(trace, "trace_id").unwrap_or("");
            errors.push(format!(
                "{}: cannot evaluate {scope} applicability for trace {trace_id}: {error}",
                document.label
            ));
            None
        }
    }
}

fn validate_bound_bundle_instance(
    receipt: &LoadedDocument,
    bundle: &LoadedDocument,
    trace: &Value,
    instances: &BTreeMap<String, &Value>,
    errors: &mut Vec<String>,
) -> Option<(String, String)> {
    let trace_id = string_field(trace, "trace_id").unwrap_or("");
    let instance_id = string_field(&bundle.value, "applicability_instance_id").unwrap_or("");
    let Some(instance) = instances.get(instance_id) else {
        errors.push(format!(
            "{}: evidence {} references unknown applicability instance {instance_id}",
            receipt.label, bundle.label
        ));
        return None;
    };

    let mut any_applicable = false;
    for scope in ["implementation", "deployment"] {
        let expected_applicable =
            evaluate_trace_scope(receipt, trace, instance, scope, errors).unwrap_or(false);
        any_applicable |= expected_applicable;
        let evaluation = bundle
            .value
            .pointer(&format!("/evaluated_applicability/{scope}"))
            .unwrap_or(&Value::Null);
        let actual_applicable = evaluation
            .get("applicable")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if actual_applicable != expected_applicable {
            errors.push(format!(
                "{}: evidence {} has incorrect {scope} applicability for instance {instance_id}",
                receipt.label, bundle.label
            ));
        }

        let instance_dimensions = dimension_map(
            instance,
            &format!("{scope}_dimensions"),
            &receipt.label,
            errors,
        );
        let declared = string_set(array(
            trace
                .get("evidence_instance_dimensions")
                .unwrap_or(&Value::Null),
            scope,
        ));
        let expected_dimensions: BTreeMap<String, Value> = if expected_applicable {
            declared
                .iter()
                .filter_map(|name| {
                    instance_dimensions
                        .get(name)
                        .cloned()
                        .map(|value| (name.clone(), value))
                })
                .collect()
        } else {
            BTreeMap::new()
        };
        if expected_applicable && expected_dimensions.len() != declared.len() {
            errors.push(format!(
                "{}: applicability instance {instance_id} omits dimensions required by trace {trace_id} for {scope}",
                receipt.label
            ));
        }
        let actual_dimensions = dimension_map(
            evaluation,
            "dimensions",
            &format!("{}: evidence {}", receipt.label, bundle.label),
            errors,
        );
        if actual_dimensions != expected_dimensions {
            errors.push(format!(
                "{}: evidence {} dimensions do not match applicability instance {instance_id} for {scope}",
                receipt.label, bundle.label
            ));
        }
    }
    if !any_applicable {
        errors.push(format!(
            "{}: evidence {} binds non-applicable trace {trace_id} instance {instance_id}",
            receipt.label, bundle.label
        ));
    }
    Some((trace_id.to_string(), instance_id.to_string()))
}

fn trace_applies_to_instance(
    receipt: &LoadedDocument,
    trace: &Value,
    instance: &Value,
    errors: &mut Vec<String>,
) -> bool {
    let mut applicable = false;
    for scope in ["implementation", "deployment"] {
        applicable |=
            evaluate_trace_scope(receipt, trace, instance, scope, errors).unwrap_or(false);
    }
    applicable
}

fn validate_evidence_binding_reference(
    receipt: &LoadedDocument,
    binding: &Value,
    bundle: &LoadedDocument,
    errors: &mut Vec<String>,
) {
    let evidence_id = string_field(binding, "evidence_instance_id").unwrap_or("");
    let context = format!("{}: evidence binding {evidence_id}", receipt.label);
    require_reference_string(
        binding,
        "artifact_kind",
        "conformance-bundle",
        &context,
        errors,
    );
    require_reference_string(binding, "artifact_locator", &bundle.label, &context, errors);
    require_matching_reference_field(binding, &bundle.value, "bundle_id", &context, errors);
    require_matching_reference_field(binding, &bundle.value, "document_version", &context, errors);
}

fn validate_prerequisite_reference(
    receipt: &LoadedDocument,
    reference: &Value,
    target: &LoadedDocument,
    errors: &mut Vec<String>,
) {
    let target_id = string_field(reference, "receipt_id").unwrap_or("");
    let context = format!("{}: prerequisite {target_id}", receipt.label);
    require_reference_string(
        reference,
        "artifact_kind",
        "package-exit-receipt",
        &context,
        errors,
    );
    require_reference_string(
        reference,
        "artifact_locator",
        &target.label,
        &context,
        errors,
    );
    require_matching_reference_field(reference, &target.value, "receipt_id", &context, errors);
    require_matching_reference_field(
        reference,
        &target.value,
        "document_version",
        &context,
        errors,
    );
}

fn validate_evidence_supersession_reference(
    source: &LoadedDocument,
    target: &LoadedDocument,
    predecessor_id: &str,
    errors: &mut Vec<String>,
) -> bool {
    let errors_before = errors.len();
    let context = format!(
        "{}: supersedes evidence instance {predecessor_id}",
        source.label
    );
    let reference = source
        .value
        .get("supersedes_evidence_ref")
        .unwrap_or(&Value::Null);
    if !reference.is_object() {
        errors.push(format!(
            "{context}: supersedes_evidence_ref must be a typed predecessor reference"
        ));
        return false;
    }
    require_reference_string(
        reference,
        "artifact_kind",
        "conformance-bundle",
        &context,
        errors,
    );
    require_reference_string(
        reference,
        "evidence_instance_id",
        predecessor_id,
        &context,
        errors,
    );
    require_matching_reference_field(reference, &target.value, "bundle_id", &context, errors);
    require_matching_reference_field(
        reference,
        &target.value,
        "document_version",
        &context,
        errors,
    );
    require_matching_reference_field(
        reference,
        &target.value,
        "evidence_instance_id",
        &context,
        errors,
    );
    validate_supersession_locator(
        reference,
        &target.label,
        CONFORMANCE_BUNDLE_LOCATOR_PREFIX,
        &context,
        errors,
    );
    validate_supersession_digest(reference, "bundle_digest", &target.digest, &context, errors);
    errors.len() == errors_before
}

fn validate_receipt_supersession_reference(
    source: &LoadedDocument,
    target: &LoadedDocument,
    predecessor_id: &str,
    errors: &mut Vec<String>,
) -> bool {
    let errors_before = errors.len();
    let context = format!("{}: supersedes receipt {predecessor_id}", source.label);
    let reference = source
        .value
        .get("supersedes_receipt_ref")
        .unwrap_or(&Value::Null);
    if !reference.is_object() {
        errors.push(format!(
            "{context}: supersedes_receipt_ref must be a typed predecessor reference"
        ));
        return false;
    }
    require_reference_string(
        reference,
        "artifact_kind",
        "package-exit-receipt",
        &context,
        errors,
    );
    require_reference_string(reference, "receipt_id", predecessor_id, &context, errors);
    for field in ["receipt_id", "document_version", "package_id"] {
        require_matching_reference_field(reference, &target.value, field, &context, errors);
    }
    if reference.get("package_id") != source.value.get("package_id") {
        errors.push(format!(
            "{context}: package_id must match the superseding receipt"
        ));
    }
    validate_supersession_locator(
        reference,
        &target.label,
        PACKAGE_EXIT_RECEIPT_LOCATOR_PREFIX,
        &context,
        errors,
    );
    validate_supersession_digest(
        reference,
        "receipt_digest",
        &target.digest,
        &context,
        errors,
    );
    errors.len() == errors_before
}

fn validate_supersession_locator(
    reference: &Value,
    expected: &str,
    required_prefix: &str,
    context: &str,
    errors: &mut Vec<String>,
) {
    require_reference_string(reference, "artifact_locator", expected, context, errors);
    let Some(locator) = string_field(reference, "artifact_locator") else {
        return;
    };
    if !is_normalized_closure_locator(locator, required_prefix) {
        errors.push(format!(
            "{context}: artifact_locator must be a normalized JSON path below {required_prefix}"
        ));
    }
}

fn is_normalized_closure_locator(locator: &str, required_prefix: &str) -> bool {
    if locator.len() > 512 || locator.contains('\\') {
        return false;
    }
    let Some(relative) = locator.strip_prefix(required_prefix) else {
        return false;
    };
    relative.ends_with(".json")
        && relative.split('/').all(|component| {
            let mut characters = component.chars();
            characters
                .next()
                .is_some_and(|character| character.is_ascii_alphanumeric())
                && characters.all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
                })
        })
}

fn validate_supersession_digest(
    reference: &Value,
    field: &str,
    expected: &str,
    context: &str,
    errors: &mut Vec<String>,
) {
    let actual = string_field(reference, field);
    if actual != Some(expected) {
        errors.push(format!(
            "{context}: {field} does not match the exact predecessor bytes"
        ));
    }
    if !actual.is_some_and(is_nonzero_sha256_digest) {
        errors.push(format!(
            "{context}: {field} must be a nonzero lowercase SHA-256 digest"
        ));
    }
}

fn is_nonzero_sha256_digest(digest: &str) -> bool {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        && digest != ZERO_SHA256_DIGEST
}

fn validate_receipt_digest_projections(document: &LoadedDocument, errors: &mut Vec<String>) {
    let expected_inputs = receipt_input_digest_projection(&document.value);
    let expected_outputs = receipt_output_digest_projection(&document.value);

    validate_exact_digest_set(
        document,
        "input_digests",
        &expected_inputs,
        "ControlTrace, closure-context, and direct-prerequisite input",
        errors,
    );
    validate_exact_digest_set(
        document,
        "output_digests",
        &expected_outputs,
        "evaluated evidence-bundle output",
        errors,
    );
}

fn receipt_input_digest_projection(receipt: &Value) -> BTreeSet<String> {
    let closure = receipt.get("closure_context").unwrap_or(&Value::Null);
    let mut digests = BTreeSet::new();

    for digest in [
        receipt.pointer("/ledger_binding/ledger_digest"),
        closure.get("artifact_digest"),
        closure.pointer("/deployment_profile/digest"),
        closure.pointer("/security_limit_profile/digest"),
    ]
    .into_iter()
    .flatten()
    .filter_map(Value::as_str)
    {
        digests.insert(digest.to_string());
    }
    for field in [
        "policy_versions",
        "configuration_versions",
        "provider_versions",
        "adapter_versions",
    ] {
        for binding in array(closure, field) {
            if let Some(digest) = string_field(binding, "digest") {
                digests.insert(digest.to_string());
            }
        }
    }
    for prerequisite in array(receipt, "prerequisite_receipts") {
        if let Some(digest) = string_field(prerequisite, "receipt_digest") {
            digests.insert(digest.to_string());
        }
    }
    digests
}

fn receipt_output_digest_projection(receipt: &Value) -> BTreeSet<String> {
    array(
        receipt.get("evaluated_sets").unwrap_or(&Value::Null),
        "evidence_bindings",
    )
    .iter()
    .filter_map(|binding| string_field(binding, "bundle_digest"))
    .map(str::to_string)
    .collect()
}

fn validate_exact_digest_set(
    document: &LoadedDocument,
    field: &str,
    expected: &BTreeSet<String>,
    projection_label: &str,
    errors: &mut Vec<String>,
) {
    let Some(values) = document.value.get(field).and_then(Value::as_array) else {
        errors.push(format!(
            "{}: {field} must be a nonempty bounded digest array",
            document.label
        ));
        return;
    };
    if values.is_empty() || values.len() > MAX_RECEIPT_DIGESTS {
        errors.push(format!(
            "{}: {field} must contain 1 through {MAX_RECEIPT_DIGESTS} digests; got {}",
            document.label,
            values.len()
        ));
    }

    let mut actual = BTreeSet::new();
    let mut previous: Option<&str> = None;
    for (index, value) in values.iter().enumerate() {
        let Some(digest) = value.as_str() else {
            errors.push(format!(
                "{}: {field}/{index} must be a nonzero lowercase SHA-256 digest",
                document.label
            ));
            previous = None;
            continue;
        };
        if !is_nonzero_sha256_digest(digest) {
            errors.push(format!(
                "{}: {field}/{index} must be a nonzero lowercase SHA-256 digest",
                document.label
            ));
        }
        if let Some(previous) = previous {
            if previous >= digest {
                errors.push(format!(
                    "{}: {field} must be strictly bytewise sorted with no duplicates; {digest} is not after {previous}",
                    document.label
                ));
            }
        }
        if !actual.insert(digest.to_string()) {
            errors.push(format!(
                "{}: {field} contains duplicate digest {digest}",
                document.label
            ));
        }
        if digest == document.digest {
            errors.push(format!(
                "{}: {field} cannot contain the receipt's own raw-byte digest",
                document.label
            ));
        }
        previous = Some(digest);
    }

    if &actual != expected {
        errors.push(format!(
            "{}: {field} {:?} is not the exact {projection_label} digest set {:?}",
            document.label, actual, expected
        ));
    }
}

fn load_deployment_profile_binding(root: &Path) -> Option<Value> {
    let bytes = fs::read(root.join(DEPLOYMENT_PROFILE_LOCATOR)).ok()?;
    let profile = parse_json_strict(&bytes).ok()?;
    deployment_profile_binding(&profile)
}

fn load_deployment_profile_version_bindings(root: &Path) -> Option<(Value, Value)> {
    let bytes = fs::read(root.join(DEPLOYMENT_PROFILE_LOCATOR)).ok()?;
    let profile = parse_json_strict(&bytes).ok()?;
    let policies = profile_reference_version_bindings(
        &profile,
        &[
            "/action_resource_registry_ref",
            "/egress_policy_ref",
            "/retention_policy_ref",
            "/trust_topology/federation_policy_ref",
        ],
    )?;
    let configurations = profile_reference_version_bindings(
        &profile,
        &["/provider_registry_ref", "/control_plane_topology_ref"],
    )?;
    Some((Value::Array(policies), Value::Array(configurations)))
}

fn profile_reference_version_bindings(profile: &Value, pointers: &[&str]) -> Option<Vec<Value>> {
    let mut bindings = Vec::new();
    for pointer in pointers {
        let Some(reference) = profile.pointer(pointer) else {
            if *pointer == "/trust_topology/federation_policy_ref" {
                continue;
            }
            return None;
        };
        if reference.is_null() && *pointer == "/trust_topology/federation_policy_ref" {
            continue;
        }
        bindings.push(serde_json::json!({
            "id": string_field(reference, "document_id")?,
            "version": reference.get("document_version")?.as_u64()?.to_string(),
            "digest": string_field(reference, "content_digest")?,
        }));
    }
    bindings.sort_by(|left, right| {
        left.get("id")
            .and_then(Value::as_str)
            .cmp(&right.get("id").and_then(Value::as_str))
    });
    Some(bindings)
}

fn validate_profile_version_bindings(
    closure_context: Option<&Value>,
    expected: Option<&(Value, Value)>,
    context: &str,
    errors: &mut Vec<String>,
) {
    let (Some(closure_context), Some((expected_policies, expected_configurations))) =
        (closure_context, expected)
    else {
        return;
    };
    if closure_context.get("policy_versions") != Some(expected_policies) {
        errors.push(format!(
            "{context}/policy_versions: must exactly equal the profile-derived policy artifact set"
        ));
    }
    if closure_context.get("configuration_versions") != Some(expected_configurations) {
        errors.push(format!(
            "{context}/configuration_versions: must exactly equal the profile-derived configuration artifact set"
        ));
    }
}

fn deployment_profile_binding(profile: &Value) -> Option<Value> {
    let id = string_field(profile, "document_id")?;
    let version = profile.get("document_version")?.as_u64()?;
    let deployment_id = string_field(profile, "deployment_id")?;
    let mut digest_input = profile.clone();
    digest_input
        .as_object_mut()?
        .remove("production_acceptance_receipt_ref");
    if let Some(guards) = digest_input
        .pointer_mut("/runtime_guard_evidence/guards")
        .and_then(Value::as_array_mut)
    {
        for guard in guards {
            if let Some(content_digest) = guard.pointer_mut("/receipt_ref/content_digest") {
                *content_digest = Value::String(ZERO_SHA256_DIGEST.to_string());
            }
        }
    }
    if let Some(content_digest) =
        digest_input.pointer_mut("/migration_overlay/zero_consumer_receipt_ref/content_digest")
    {
        *content_digest = Value::String(ZERO_SHA256_DIGEST.to_string());
    }
    let digest = format!(
        "sha256:{:x}",
        Sha256::digest(canonical_json(&digest_input).as_bytes())
    );
    Some(serde_json::json!({
        "id": id,
        "version": version.to_string(),
        "deployment_id": deployment_id,
        "digest_contract": DEPLOYMENT_PROFILE_BINDING_DIGEST_CONTRACT,
        "digest": digest
    }))
}

fn validate_deployment_profile_binding(
    binding: Option<&Value>,
    expected: Option<&Value>,
    context: &str,
    errors: &mut Vec<String>,
) {
    let Some(binding) = binding else {
        return;
    };
    let Some(expected) = expected else {
        errors.push(format!(
            "{context}: cannot derive the authoritative deployment-profile binding"
        ));
        return;
    };
    for field in [
        "id",
        "version",
        "deployment_id",
        "digest_contract",
        "digest",
    ] {
        if binding.get(field) != expected.get(field) {
            errors.push(format!(
                "{context}: {field} does not match the exact deployment-profile conformance binding"
            ));
        }
    }
}

fn require_reference_string(
    reference: &Value,
    field: &str,
    expected: &str,
    context: &str,
    errors: &mut Vec<String>,
) {
    if string_field(reference, field) != Some(expected) {
        errors.push(format!(
            "{context}: {field} must exactly reference {expected}"
        ));
    }
}

fn require_matching_reference_field(
    reference: &Value,
    target: &Value,
    field: &str,
    context: &str,
    errors: &mut Vec<String>,
) {
    if reference.get(field) != target.get(field) {
        errors.push(format!(
            "{context}: {field} does not match the referenced closure document"
        ));
    }
}

fn validate_receipt_package_constraints(
    document: &LoadedDocument,
    evidence_ids: &BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    let receipt = &document.value;
    let package_id = string_field(receipt, "package_id").unwrap_or("");
    if matches!(package_id, "SB-8" | "SB-9") {
        let tier_name = receipt
            .pointer("/evidence_tier/name")
            .and_then(Value::as_str);
        let tier_rank = receipt
            .pointer("/evidence_tier/rank")
            .and_then(Value::as_u64);
        if !matches!(
            tier_name,
            Some("operator_environment" | "externally_attested")
        ) || !tier_rank.is_some_and(|rank| rank >= 2)
        {
            errors.push(format!(
                "{}: {package_id} evidence tier must be at least operator_environment (rank 2)",
                document.label
            ));
        }
    }

    if package_id != "SB-9" {
        if receipt.get("retirement_closure") != Some(&Value::Null) {
            errors.push(format!(
                "{}: non-SB-9 receipt {package_id} must have retirement_closure=null",
                document.label
            ));
        }
        return;
    }

    if evidence_ids.is_empty() {
        errors.push(format!(
            "{}: SB-9 retirement closure requires a nonempty current evaluated evidence set",
            document.label
        ));
    }
    let Some(retirement) = receipt.get("retirement_closure").and_then(Value::as_object) else {
        errors.push(format!(
            "{}: SB-9 receipt must carry retirement_closure",
            document.label
        ));
        return;
    };
    for field in [
        "zero_consumer_evidence_instance_ids",
        "zero_live_authority_evidence_instance_ids",
        "retired_bypass_evidence_instance_ids",
    ] {
        let Some(values) = retirement.get(field).and_then(Value::as_array) else {
            errors.push(format!(
                "{}: retirement_closure.{field} must be a nonempty strictly sorted evidence-ID array",
                document.label
            ));
            continue;
        };
        if values.is_empty() {
            errors.push(format!(
                "{}: retirement_closure.{field} must be nonempty",
                document.label
            ));
        }
        let mut actual = BTreeSet::new();
        let mut previous: Option<&str> = None;
        for (index, value) in values.iter().enumerate() {
            let Some(evidence_id) = value.as_str() else {
                errors.push(format!(
                    "{}: retirement_closure.{field}/{index} must be an evidence instance ID",
                    document.label
                ));
                previous = None;
                continue;
            };
            if let Some(previous) = previous {
                if previous >= evidence_id {
                    errors.push(format!(
                        "{}: retirement_closure.{field} must be strictly bytewise sorted with no duplicates",
                        document.label
                    ));
                }
            }
            if !actual.insert(evidence_id.to_string()) {
                errors.push(format!(
                    "{}: retirement_closure.{field} contains duplicate evidence ID {evidence_id}",
                    document.label
                ));
            }
            previous = Some(evidence_id);
        }
        if &actual != evidence_ids {
            errors.push(format!(
                "{}: retirement_closure.{field} {:?} is not the exact current SB-9 receipt evidence set {:?}",
                document.label, actual, evidence_ids
            ));
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_receipts(
    ledger: &Value,
    ledger_digest: Option<&str>,
    traces: &BTreeMap<String, &Value>,
    controls: &BTreeMap<String, &Value>,
    evidence: &BTreeMap<String, &LoadedDocument>,
    superseded_evidence: &BTreeSet<String>,
    receipts: &[LoadedDocument],
    now: DateTime<Utc>,
    errors: &mut Vec<String>,
) {
    let mut receipt_map = BTreeMap::new();
    for receipt in receipts {
        let receipt_id = string_field(&receipt.value, "receipt_id").unwrap_or("");
        if let Some(previous) = receipt_map.insert(receipt_id.to_string(), receipt) {
            errors.push(format!(
                "{}: duplicate receipt_id {receipt_id}; first declared by {}",
                receipt.label, previous.label
            ));
        }
    }

    let mut prerequisite_graph = BTreeMap::new();
    let mut receipt_supersession = BTreeMap::new();
    let mut receipt_successor_by_target = BTreeMap::new();
    let mut forked_receipt_targets = BTreeSet::new();
    for document in receipts {
        let receipt_id = string_field(&document.value, "receipt_id").unwrap_or("");
        let target = document
            .value
            .get("supersedes_receipt_id")
            .and_then(Value::as_str);
        let has_reference = document
            .value
            .get("supersedes_receipt_ref")
            .is_some_and(|reference| !reference.is_null());
        if target.is_some() != has_reference {
            errors.push(format!(
                "{}: supersedes_receipt_id and supersedes_receipt_ref must both be null or both identify the predecessor",
                document.label
            ));
        }
        if let Some(target) = target {
            if target == receipt_id {
                errors.push(format!(
                    "{}: receipt {receipt_id} cannot supersede itself",
                    document.label
                ));
            }
            if let Some(previous_successor) =
                receipt_successor_by_target.insert(target.to_string(), receipt_id.to_string())
            {
                forked_receipt_targets.insert(target.to_string());
                errors.push(format!(
                    "{}: receipt predecessor {target} has multiple successors {previous_successor} and {receipt_id}",
                    document.label
                ));
            }
            receipt_supersession.insert(receipt_id.to_string(), target.to_string());
        }
    }
    let mut superseded_receipts = BTreeSet::new();
    for (source, target) in &receipt_supersession {
        let mut valid_lineage = source != target && !forked_receipt_targets.contains(target);
        let Some(source_receipt) = receipt_map.get(source) else {
            continue;
        };
        let Some(target_receipt) = receipt_map.get(target) else {
            errors.push(format!(
                "receipt {source} supersedes unknown receipt {target}"
            ));
            continue;
        };
        valid_lineage &=
            validate_receipt_supersession_reference(source_receipt, target_receipt, target, errors);
        if source_receipt.value.get("package_id") != target_receipt.value.get("package_id") {
            valid_lineage = false;
            errors.push(format!(
                "{}: receipt {source} cannot supersede receipt {target} from another package",
                source_receipt.label
            ));
        }
        let source_version = source_receipt
            .value
            .get("document_version")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let target_version = target_receipt
            .value
            .get("document_version")
            .and_then(Value::as_u64)
            .unwrap_or(u64::MAX);
        if source_version <= target_version {
            valid_lineage = false;
            errors.push(format!(
                "{}: superseding receipt {source} document_version {source_version} must exceed {target_version}",
                source_receipt.label
            ));
        }
        let source_tier = source_receipt
            .value
            .pointer("/evidence_tier/rank")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let target_tier = target_receipt
            .value
            .pointer("/evidence_tier/rank")
            .and_then(Value::as_u64)
            .unwrap_or(u64::MAX);
        if source_tier < target_tier {
            valid_lineage = false;
            errors.push(format!(
                "{}: superseding receipt {source} tier rank {source_tier} must not be below predecessor {target} rank {target_tier}",
                source_receipt.label
            ));
        }
        if valid_lineage {
            superseded_receipts.insert(target.clone());
        }
    }
    for document in receipts {
        let receipt = &document.value;
        let receipt_id = string_field(receipt, "receipt_id").unwrap_or("");
        let package_id = string_field(receipt, "package_id").unwrap_or("");
        let claims_authoritative_closure = claims_authoritative_closure(receipt);
        validate_ledger_binding(document, ledger, ledger_digest, errors);
        validate_receipt_timestamps(document, now, claims_authoritative_closure, errors);
        validate_receipt_digest_projections(document, errors);
        if claims_authoritative_closure && superseded_receipts.contains(receipt_id) {
            errors.push(format!(
                "{}: authoritative receipt {receipt_id} has been superseded",
                document.label
            ));
        }

        let evaluated = receipt.get("evaluated_sets").unwrap_or(&Value::Null);
        let trace_ids = string_set(array(evaluated, "trace_ids"));
        let control_ids = string_set(array(evaluated, "control_ids"));
        let case_ids = string_set(array(evaluated, "acceptance_case_ids"));
        let mut applicability_instances = BTreeMap::new();
        for instance in array(receipt, "applicability_instances") {
            let instance_id = string_field(instance, "instance_id").unwrap_or("");
            if applicability_instances
                .insert(instance_id.to_string(), instance)
                .is_some()
            {
                errors.push(format!(
                    "{}: duplicate applicability instance {instance_id}",
                    document.label
                ));
            }
            for scope in ["implementation", "deployment"] {
                dimension_map(
                    instance,
                    &format!("{scope}_dimensions"),
                    &document.label,
                    errors,
                );
            }
        }
        let mut evidence_bindings = BTreeMap::new();
        for binding in array(evaluated, "evidence_bindings") {
            let evidence_id = string_field(binding, "evidence_instance_id").unwrap_or("");
            if evidence_bindings
                .insert(evidence_id.to_string(), binding)
                .is_some()
            {
                errors.push(format!(
                    "{}: duplicate evidence binding for {evidence_id}",
                    document.label
                ));
            }
        }
        let evaluated_evidence_ids = evidence_bindings.keys().cloned().collect::<BTreeSet<_>>();
        validate_receipt_package_constraints(document, &evaluated_evidence_ids, errors);
        let mut projected_controls = BTreeSet::new();
        let mut projected_cases = BTreeSet::new();
        for trace_id in &trace_ids {
            let Some(trace) = traces.get(trace_id) else {
                errors.push(format!(
                    "{}: receipt references unknown trace_id {trace_id}",
                    document.label
                ));
                continue;
            };
            if string_field(trace, "owning_work_package") != Some(package_id) {
                errors.push(format!(
                    "{}: trace {trace_id} is not owned by package {package_id}",
                    document.label
                ));
            }
            if let Some(id) = string_field(trace, "control_id") {
                projected_controls.insert(id.to_string());
            }
            if let Some(id) = string_field(trace, "acceptance_case_id") {
                projected_cases.insert(id.to_string());
            }
        }
        if control_ids != projected_controls {
            errors.push(format!(
                "{}: evaluated control set {:?} is not the exact trace projection {:?}",
                document.label, control_ids, projected_controls
            ));
        }
        if case_ids != projected_cases {
            errors.push(format!(
                "{}: evaluated acceptance-case set {:?} is not the exact trace projection {:?}",
                document.label, case_ids, projected_cases
            ));
        }

        let mut evidenced_pairs = BTreeSet::new();
        for (evidence_id, binding) in &evidence_bindings {
            let Some(bundle) = evidence.get(evidence_id) else {
                errors.push(format!(
                    "{}: receipt references unknown evidence_instance_id {evidence_id}",
                    document.label
                ));
                continue;
            };
            if string_field(binding, "bundle_digest") != Some(bundle.digest.as_str()) {
                errors.push(format!(
                    "{}: evidence {evidence_id} bundle_digest does not match {}",
                    document.label, bundle.label
                ));
            }
            validate_evidence_binding_reference(document, binding, bundle, errors);
            let trace_id = string_field(&bundle.value, "trace_id").unwrap_or("");
            if !trace_ids.contains(trace_id) {
                errors.push(format!(
                    "{}: evidence {evidence_id} is outside the receipt trace set",
                    document.label
                ));
            }
            validate_bundle_receipt_context(document, bundle, errors);
            if let Some(trace) = traces.get(trace_id) {
                if let Some(pair) = validate_bound_bundle_instance(
                    document,
                    bundle,
                    trace,
                    &applicability_instances,
                    errors,
                ) {
                    if !evidenced_pairs.insert(pair.clone()) {
                        errors.push(format!(
                            "{}: multiple evidence bundles cover trace {} instance {}",
                            document.label, pair.0, pair.1
                        ));
                    }
                }
            }
            if claims_authoritative_closure {
                validate_authoritative_bundle(
                    document,
                    evidence_id,
                    bundle,
                    superseded_evidence,
                    now,
                    errors,
                );
                let bundle_rank = bundle
                    .value
                    .pointer("/provenance/evidence_tier/rank")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let receipt_rank = receipt
                    .pointer("/evidence_tier/rank")
                    .and_then(Value::as_u64)
                    .unwrap_or(u64::MAX);
                if bundle_rank < receipt_rank {
                    errors.push(format!(
                        "{}: evidence {evidence_id} tier rank {bundle_rank} is below receipt rank {receipt_rank}",
                        document.label
                    ));
                }
            }
        }

        let waived_pairs = validate_receipt_waivers(
            document,
            package_id,
            traces,
            controls,
            &trace_ids,
            &control_ids,
            &applicability_instances,
            now,
            claims_authoritative_closure,
            errors,
        );
        for trace_id in &trace_ids {
            let Some(trace) = traces.get(trace_id) else {
                continue;
            };
            for (instance_id, instance) in &applicability_instances {
                if trace_applies_to_instance(document, trace, instance, errors)
                    && !evidenced_pairs.contains(&(trace_id.clone(), instance_id.clone()))
                    && !waived_pairs.contains(&(trace_id.clone(), instance_id.clone()))
                {
                    errors.push(format!(
                        "{}: trace {trace_id} applicability instance {instance_id} has neither evidence nor an authorized waiver",
                        document.label
                    ));
                }
            }
        }

        let accepted_pass = string_field(receipt, "receipt_lifecycle") == Some("accepted")
            && string_field(receipt, "result") == Some("pass");
        if accepted_pass || claims_authoritative_closure {
            let expected: BTreeSet<String> = traces
                .iter()
                .filter(|(_, trace)| {
                    string_field(trace, "owning_work_package") == Some(package_id)
                        && string_field(trace, "trace_lifecycle") == Some("active")
                })
                .map(|(id, _)| id.clone())
                .collect();
            if trace_ids != expected {
                errors.push(format!(
                    "{}: accepted receipt omits or adds active package traces; expected {:?}, got {:?}",
                    document.label, expected, trace_ids
                ));
            }
        }

        let mut prerequisites = BTreeSet::new();
        let mut prerequisite_packages = BTreeSet::new();
        for prerequisite in array(receipt, "prerequisite_receipts") {
            let target_id = string_field(prerequisite, "receipt_id").unwrap_or("");
            prerequisites.insert(target_id.to_string());
            if let Some(target_package) = string_field(prerequisite, "package_id") {
                if !prerequisite_packages.insert(target_package.to_string()) {
                    errors.push(format!(
                        "{}: duplicate prerequisite package {target_package}",
                        document.label
                    ));
                }
            }
            let Some(target) = receipt_map.get(target_id) else {
                errors.push(format!(
                    "{}: prerequisite references unknown receipt {target_id}",
                    document.label
                ));
                continue;
            };
            validate_prerequisite_reference(document, prerequisite, target, errors);
            for key in [
                "document_version",
                "package_id",
                "acceptance_status",
                "production_accepted",
                "evidence_tier",
                "result",
                "receipt_lifecycle",
                "expires_at",
            ] {
                if prerequisite.get(key) != target.value.get(key) {
                    errors.push(format!(
                        "{}: prerequisite {target_id} has a mismatched {key}",
                        document.label
                    ));
                }
            }
            if string_field(prerequisite, "receipt_digest") != Some(target.digest.as_str()) {
                errors.push(format!(
                    "{}: prerequisite {target_id} receipt_digest does not match {}",
                    document.label, target.label
                ));
            }
            if claims_authoritative_closure {
                validate_authoritative_prerequisite(
                    document,
                    target_id,
                    target,
                    &superseded_receipts,
                    now,
                    errors,
                );
                let target_rank = target
                    .value
                    .pointer("/evidence_tier/rank")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let receipt_rank = receipt
                    .pointer("/evidence_tier/rank")
                    .and_then(Value::as_u64)
                    .unwrap_or(u64::MAX);
                if target_rank < receipt_rank {
                    errors.push(format!(
                        "{}: prerequisite {target_id} evidence tier rank {target_rank} is below receipt rank {receipt_rank}",
                        document.label
                    ));
                }
            }
        }
        if claims_authoritative_closure {
            let required = required_prerequisite_packages(package_id);
            if prerequisite_packages != required {
                errors.push(format!(
                    "{}: prerequisite package set {:?} does not match required set {:?}",
                    document.label, prerequisite_packages, required
                ));
            }
        }
        prerequisite_graph.insert(receipt_id.to_string(), prerequisites);

        if receipt_supersession
            .get(receipt_id)
            .is_some_and(|target| target == receipt_id)
        {
            errors.push(format!(
                "{}: receipt {receipt_id} cannot supersede itself",
                document.label
            ));
        }
    }

    detect_single_edge_cycles("receipt supersession", &receipt_supersession, errors);
    detect_multi_edge_cycles("prerequisite receipt", &prerequisite_graph, errors);
}

fn claims_authoritative_closure(receipt: &Value) -> bool {
    matches!(
        string_field(receipt, "acceptance_status"),
        Some("production_candidate" | "production_accepted")
    ) || receipt
        .get("production_accepted")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || (string_field(receipt, "receipt_lifecycle") == Some("accepted")
            && string_field(receipt, "result") == Some("pass"))
}

fn validate_receipt_timestamps(
    document: &LoadedDocument,
    now: DateTime<Utc>,
    authoritative: bool,
    errors: &mut Vec<String>,
) {
    let created = timestamp_field(document, "created_at", errors);
    let expires = timestamp_field(document, "expires_at", errors);
    if created
        .zip(expires)
        .is_some_and(|(left, right)| left >= right)
    {
        errors.push(format!(
            "{}: created_at must be before expires_at",
            document.label
        ));
    }
    if authoritative && expires.is_some_and(|expires| expires <= now) {
        errors.push(format!(
            "{}: authoritative receipt is expired",
            document.label
        ));
    }
    if authoritative && created.is_some_and(|created| created > now) {
        errors.push(format!(
            "{}: authoritative receipt has a future created_at",
            document.label
        ));
    }
}

fn validate_authoritative_bundle(
    receipt: &LoadedDocument,
    evidence_id: &str,
    bundle: &LoadedDocument,
    superseded_evidence: &BTreeSet<String>,
    now: DateTime<Utc>,
    errors: &mut Vec<String>,
) {
    for (field, expected) in [
        ("acceptance_status", "production_accepted"),
        ("evidence_lifecycle", "accepted"),
        ("normalized_result", "pass"),
    ] {
        if string_field(&bundle.value, field) != Some(expected) {
            errors.push(format!(
                "{}: evidence {evidence_id} must have {field}={expected}",
                receipt.label
            ));
        }
    }
    if bundle
        .value
        .get("production_accepted")
        .and_then(Value::as_bool)
        != Some(true)
    {
        errors.push(format!(
            "{}: evidence {evidence_id} is not production accepted",
            receipt.label
        ));
    }
    if superseded_evidence.contains(evidence_id) {
        errors.push(format!(
            "{}: evidence {evidence_id} has been superseded",
            receipt.label
        ));
    }
    let expires = timestamp_field(bundle, "expires_at", errors);
    if expires.is_some_and(|expires| expires <= now) {
        errors.push(format!(
            "{}: evidence {evidence_id} is expired",
            receipt.label
        ));
    }
    let accepted = optional_timestamp_field(bundle, "accepted_at", errors);
    if accepted.is_some_and(|accepted| accepted > now) {
        errors.push(format!(
            "{}: evidence {evidence_id} has a future accepted_at",
            receipt.label
        ));
    }
}

fn validate_authoritative_prerequisite(
    receipt: &LoadedDocument,
    target_id: &str,
    target: &LoadedDocument,
    superseded_receipts: &BTreeSet<String>,
    now: DateTime<Utc>,
    errors: &mut Vec<String>,
) {
    for (field, expected) in [
        ("acceptance_status", "production_accepted"),
        ("receipt_lifecycle", "accepted"),
        ("result", "pass"),
    ] {
        if string_field(&target.value, field) != Some(expected) {
            errors.push(format!(
                "{}: prerequisite {target_id} must have {field}={expected}",
                receipt.label
            ));
        }
    }
    if target
        .value
        .get("production_accepted")
        .and_then(Value::as_bool)
        != Some(true)
    {
        errors.push(format!(
            "{}: prerequisite {target_id} is not production accepted",
            receipt.label
        ));
    }
    if superseded_receipts.contains(target_id) {
        errors.push(format!(
            "{}: prerequisite {target_id} has been superseded",
            receipt.label
        ));
    }
    let expires = timestamp_field(target, "expires_at", errors);
    if expires.is_some_and(|expires| expires <= now) {
        errors.push(format!(
            "{}: prerequisite {target_id} is expired",
            receipt.label
        ));
    }
}

fn required_prerequisite_packages(package_id: &str) -> BTreeSet<String> {
    let packages: &[&str] = match package_id {
        "SB-0" => &[],
        "SB-1" | "SB-2" | "SB-4" | "SB-5" | "SB-6" | "SB-7" => &["SB-0"],
        "SB-3" => &["SB-0", "SB-1", "SB-2"],
        "SB-8" => &[
            "SB-0", "SB-1", "SB-2", "SB-3", "SB-4", "SB-5", "SB-6", "SB-7",
        ],
        "SB-9" => &[
            "SB-0", "SB-1", "SB-2", "SB-3", "SB-4", "SB-5", "SB-6", "SB-7", "SB-8",
        ],
        _ => &[],
    };
    packages
        .iter()
        .map(|package| (*package).to_string())
        .collect()
}

fn validate_ledger_binding(
    document: &LoadedDocument,
    ledger: &Value,
    ledger_digest: Option<&str>,
    errors: &mut Vec<String>,
) {
    let binding = document.value.get("ledger_binding").unwrap_or(&Value::Null);
    let context = format!("{}: ledger_binding", document.label);
    require_reference_string(binding, "artifact_kind", "control-trace", &context, errors);
    require_reference_string(
        binding,
        "artifact_locator",
        "catalog/security-contracts/v1/control-trace.implementation.json",
        &context,
        errors,
    );
    require_matching_reference_field(binding, ledger, "document_id", &context, errors);
    require_matching_reference_field(binding, ledger, "document_version", &context, errors);
    for key in ["ledger_id", "ledger_version"] {
        if binding.get(key) != ledger.get(key) {
            errors.push(format!(
                "{}: ledger_binding.{key} does not match the active ControlTrace ledger",
                document.label
            ));
        }
    }
    if binding.get("ledger_digest").and_then(Value::as_str) != ledger_digest {
        errors.push(format!(
            "{}: ledger_binding.ledger_digest does not match the active ControlTrace file",
            document.label
        ));
    }
}

fn validate_bundle_receipt_context(
    receipt: &LoadedDocument,
    bundle: &LoadedDocument,
    errors: &mut Vec<String>,
) {
    let closure = receipt.value.get("closure_context").unwrap_or(&Value::Null);
    if bundle.value.get("source_revision") != closure.get("source_revision") {
        errors.push(format!(
            "{}: evidence {} has the wrong source revision",
            receipt.label, bundle.label
        ));
    }
    if bundle.value.pointer("/artifact/digest") != closure.get("artifact_digest") {
        errors.push(format!(
            "{}: evidence {} has the wrong artifact digest",
            receipt.label, bundle.label
        ));
    }
    let bindings = bundle.value.get("bindings").unwrap_or(&Value::Null);
    for key in [
        "deployment_profile",
        "policy_versions",
        "configuration_versions",
        "provider_versions",
        "adapter_versions",
        "security_limit_profile",
    ] {
        if bindings.get(key) != closure.get(key) {
            errors.push(format!(
                "{}: evidence {} has a mismatched {key} binding",
                receipt.label, bundle.label
            ));
        }
    }
}

fn validate_receipt_waivers(
    document: &LoadedDocument,
    package_id: &str,
    traces: &BTreeMap<String, &Value>,
    controls: &BTreeMap<String, &Value>,
    evaluated_traces: &BTreeSet<String>,
    evaluated_controls: &BTreeSet<String>,
    applicability_instances: &BTreeMap<String, &Value>,
    now: DateTime<Utc>,
    authoritative: bool,
    errors: &mut Vec<String>,
) -> BTreeSet<(String, String)> {
    let mut waived = BTreeSet::new();
    let mut declared = BTreeSet::new();
    for waiver in array(&document.value, "waivers") {
        let errors_before = errors.len();
        let trace_id = string_field(waiver, "trace_id").unwrap_or("");
        let control_id = string_field(waiver, "control_id").unwrap_or("");
        let instance_id = waiver
            .pointer("/scope/instance_id")
            .and_then(Value::as_str)
            .unwrap_or("");
        let pair = (trace_id.to_string(), instance_id.to_string());
        if !declared.insert(pair.clone()) {
            errors.push(format!(
                "{}: duplicate waiver for trace {trace_id} applicability instance {instance_id}",
                document.label,
            ));
        }
        let Some(trace) = traces.get(trace_id) else {
            errors.push(format!(
                "{}: waiver references unknown trace {trace_id}",
                document.label
            ));
            continue;
        };
        if !evaluated_traces.contains(trace_id) {
            errors.push(format!(
                "{}: waived trace {trace_id} is absent from the evaluated trace set",
                document.label
            ));
        }
        if string_field(trace, "control_id") != Some(control_id) {
            errors.push(format!(
                "{}: waiver control {control_id} does not match trace {trace_id}",
                document.label
            ));
        }
        let Some(control) = controls.get(control_id) else {
            errors.push(format!(
                "{}: waiver references unknown control {control_id}",
                document.label
            ));
            continue;
        };
        if control.get("waivable").and_then(Value::as_bool) != Some(true) {
            errors.push(format!(
                "{}: control {control_id} is not waivable",
                document.label
            ));
        }
        if string_field(control, "owning_work_package") != Some(package_id) {
            errors.push(format!(
                "{}: waived control {control_id} is not owned by {package_id}",
                document.label
            ));
        }
        if !evaluated_controls.contains(control_id) {
            errors.push(format!(
                "{}: waived control {control_id} is absent from the evaluated control set",
                document.label
            ));
        }
        let compensating = string_field(waiver, "compensating_control_id").unwrap_or("");
        if compensating == control_id {
            errors.push(format!(
                "{}: control {control_id} cannot compensate for itself",
                document.label
            ));
        }
        if !controls.contains_key(compensating) {
            errors.push(format!(
                "{}: waiver references unknown compensating control {compensating}",
                document.label
            ));
        }

        let Some(instance) = applicability_instances.get(instance_id) else {
            errors.push(format!(
                "{}: waiver references unknown applicability instance {instance_id}",
                document.label
            ));
            continue;
        };
        let scope = waiver.get("scope").unwrap_or(&Value::Null);
        if scope != *instance {
            errors.push(format!(
                "{}: waiver scope does not exactly match applicability instance {instance_id}",
                document.label
            ));
        }
        if !trace_applies_to_instance(document, trace, instance, errors) {
            errors.push(format!(
                "{}: waiver targets non-applicable trace {trace_id} instance {instance_id}",
                document.label
            ));
        }

        let approved = waiver
            .pointer("/approval/approved_at")
            .and_then(Value::as_str)
            .and_then(|raw| match DateTime::parse_from_rfc3339(raw) {
                Ok(value) => Some(value.with_timezone(&Utc)),
                Err(error) => {
                    errors.push(format!(
                        "{}: waiver for trace {trace_id} has invalid approved_at: {error}",
                        document.label
                    ));
                    None
                }
            });
        let expires = string_field(waiver, "expires_at").and_then(|raw| {
            match DateTime::parse_from_rfc3339(raw) {
                Ok(value) => Some(value.with_timezone(&Utc)),
                Err(error) => {
                    errors.push(format!(
                        "{}: waiver for trace {trace_id} has invalid expires_at: {error}",
                        document.label
                    ));
                    None
                }
            }
        });
        if approved
            .zip(expires)
            .is_some_and(|(approved, expires)| approved >= expires)
        {
            errors.push(format!(
                "{}: waiver approval must precede expiry for trace {trace_id}",
                document.label
            ));
        }
        if authoritative && approved.is_some_and(|approved| approved > now) {
            errors.push(format!(
                "{}: waiver approval is future-dated for trace {trace_id}",
                document.label
            ));
        }
        if authoritative && expires.is_some_and(|expires| expires <= now) {
            errors.push(format!(
                "{}: waiver is expired for trace {trace_id}",
                document.label
            ));
        }
        if errors.len() == errors_before {
            waived.insert(pair);
        }
    }
    waived
}

fn detect_multi_edge_cycles(
    label: &str,
    edges: &BTreeMap<String, BTreeSet<String>>,
    errors: &mut Vec<String>,
) {
    let mut complete = BTreeSet::new();
    let mut reported = BTreeSet::new();
    for node in edges.keys() {
        let mut stack = Vec::new();
        detect_multi_edge_cycles_from(
            node,
            edges,
            &mut stack,
            &mut complete,
            &mut reported,
            label,
            errors,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn detect_multi_edge_cycles_from(
    node: &str,
    edges: &BTreeMap<String, BTreeSet<String>>,
    stack: &mut Vec<String>,
    complete: &mut BTreeSet<String>,
    reported: &mut BTreeSet<Vec<String>>,
    label: &str,
    errors: &mut Vec<String>,
) {
    if complete.contains(node) {
        return;
    }
    if let Some(position) = stack.iter().position(|candidate| candidate == node) {
        let mut cycle = stack[position..].to_vec();
        cycle.push(node.to_string());
        let canonical = canonical_cycle(&cycle);
        if reported.insert(canonical.clone()) {
            errors.push(format!("{label} cycle: {}", canonical.join(" -> ")));
        }
        return;
    }
    stack.push(node.to_string());
    if let Some(targets) = edges.get(node) {
        for target in targets {
            detect_multi_edge_cycles_from(target, edges, stack, complete, reported, label, errors);
        }
    }
    stack.pop();
    complete.insert(node.to_string());
}

fn owner_from(value: &Value, path: &str, errors: &mut Vec<String>) -> Owner {
    let package = string_field(value, "owning_work_package")
        .unwrap_or("")
        .to_string();
    let team = string_field(value, "owning_team").unwrap_or("").to_string();
    if !matches!(
        package.as_str(),
        "SB-0" | "SB-1" | "SB-2" | "SB-3" | "SB-4" | "SB-5" | "SB-6" | "SB-7" | "SB-8" | "SB-9"
    ) {
        errors.push(format!("{path}: invalid owning_work_package {package:?}"));
    }
    if team.trim().is_empty() {
        errors.push(format!("{path}: owning_team must be non-empty"));
    }
    Owner { package, team }
}

fn require_matching_owner(
    kind: &str,
    id: &str,
    expected: &Owner,
    actual: &Owner,
    path: &str,
    errors: &mut Vec<String>,
) {
    if expected.package != actual.package || expected.team != actual.team {
        errors.push(format!(
            "{path}: {kind} {id} owner is {}/{} but trace declares {}/{}",
            expected.package, expected.team, actual.package, actual.team
        ));
    }
}

fn validate_dimension_declarations(trace: &Value, path: &str, errors: &mut Vec<String>) {
    let Some(dimensions) = trace
        .get("evidence_instance_dimensions")
        .and_then(Value::as_object)
    else {
        return;
    };
    for scope in ["implementation", "deployment"] {
        let mut seen = BTreeSet::new();
        for dimension in dimensions
            .get(scope)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            if !seen.insert(dimension) {
                errors.push(format!(
                    "{path}: duplicate {scope} evidence dimension {dimension}"
                ));
            }
            if !dimension.starts_with(&format!("{scope}.")) {
                errors.push(format!(
                    "{path}: {scope} evidence dimension {dimension} has the wrong namespace"
                ));
            }
        }
    }
}

fn detect_single_edge_cycles(
    label: &str,
    edges: &BTreeMap<String, String>,
    errors: &mut Vec<String>,
) {
    let mut reported = BTreeSet::new();
    for start in edges.keys() {
        let mut positions = BTreeMap::new();
        let mut path = Vec::new();
        let mut current = start.as_str();
        loop {
            if let Some(position) = positions.get(current).copied() {
                let mut cycle = path[position..].to_vec();
                cycle.push(current.to_string());
                let canonical = canonical_cycle(&cycle);
                if reported.insert(canonical.clone()) {
                    errors.push(format!("{label} cycle: {}", canonical.join(" -> ")));
                }
                break;
            }
            positions.insert(current.to_string(), path.len());
            path.push(current.to_string());
            let Some(next) = edges.get(current) else {
                break;
            };
            current = next;
        }
    }
}

fn canonical_cycle(cycle: &[String]) -> Vec<String> {
    let core = &cycle[..cycle.len().saturating_sub(1)];
    if core.is_empty() {
        return cycle.to_vec();
    }
    let (position, _) = core
        .iter()
        .enumerate()
        .min_by(|(_, left), (_, right)| left.cmp(right))
        .expect("non-empty cycle");
    let mut result: Vec<String> = core[position..]
        .iter()
        .chain(core[..position].iter())
        .cloned()
        .collect();
    result.push(result[0].clone());
    result
}

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => {
            serde_json::to_string(value).expect("serializing a string cannot fail")
        }
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Value::Object(values) => {
            let ordered: BTreeMap<&str, &Value> = values
                .iter()
                .map(|(key, value)| (key.as_str(), value))
                .collect();
            let members = ordered
                .into_iter()
                .map(|(key, value)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(key).expect("serializing an object key cannot fail"),
                        canonical_json(value)
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{members}}}")
        }
    }
}

fn report_set_delta(
    label: &str,
    expected: &BTreeSet<String>,
    actual: &BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    for missing in expected.difference(actual) {
        errors.push(format!("missing {label} {missing}"));
    }
    for unknown in actual.difference(expected) {
        errors.push(format!("unknown {label} {unknown}"));
    }
}

fn array<'a>(value: &'a Value, field: &str) -> &'a [Value] {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn string_field<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn validate_cross_document_semantics(
    root: &Path,
    instances: &BTreeMap<&str, Value>,
    errors: &mut Vec<String>,
) {
    let Some(deployment) = instances.get("deployment-security-profile.implementation.json") else {
        return;
    };

    validate_bound_document_ref(
        deployment,
        "provider_registry_ref",
        "provider-registry",
        "catalog/security-contracts/v1/provider-registry.implementation.json",
        instances.get("provider-registry.implementation.json"),
        errors,
    );
    validate_bound_document_ref(
        deployment,
        "provider_lifecycle_snapshot_ref",
        "provider-registry",
        "catalog/security-contracts/v1/provider-registry.implementation.json",
        instances.get("provider-registry.implementation.json"),
        errors,
    );
    validate_bound_document_ref(
        deployment,
        "action_resource_registry_ref",
        "action-resource-registry",
        "catalog/security-contracts/v1/action-resource-registry.implementation.json",
        instances.get("action-resource-registry.implementation.json"),
        errors,
    );
    validate_bound_document_ref(
        deployment,
        "security_limit_profile_ref",
        "security-limit-profile",
        "catalog/security-contracts/v1/security-limit-profile.implementation.json",
        instances.get("security-limit-profile.implementation.json"),
        errors,
    );
    validate_bound_document_ref(
        deployment,
        "conformance_trust_root_registry_ref",
        "conformance-trust-root-registry",
        "catalog/security-contracts/v1/conformance-trust-root-registry.implementation.json",
        instances.get("conformance-trust-root-registry.implementation.json"),
        errors,
    );
    validate_bound_document_ref(
        deployment,
        "control_trace_ref",
        "control-trace",
        "catalog/security-contracts/v1/control-trace.implementation.json",
        instances.get("control-trace.implementation.json"),
        errors,
    );

    let deployment_id = string_field(deployment, "deployment_id").unwrap_or("");
    let profile = string_field(deployment, "security_profile").unwrap_or("");
    let applicability = deployment.get("applicability").unwrap_or(&Value::Null);
    require_array_contains(
        applicability,
        "deployment_ids",
        deployment_id,
        "deployment-security-profile.implementation.json:/applicability",
        errors,
    );
    require_array_contains(
        applicability,
        "security_profiles",
        profile,
        "deployment-security-profile.implementation.json:/applicability",
        errors,
    );
    let enabled = string_set(array(deployment, "enabled_features"));
    let applicable_enabled = string_set(array(applicability, "enabled_feature_ids"));
    if enabled != applicable_enabled {
        errors.push(format!(
            "deployment-security-profile.implementation.json: enabled_features {:?} do not exactly match applicability.enabled_feature_ids {:?}",
            enabled, applicable_enabled
        ));
    }
    validate_runtime_guard_control_ownership(deployment, errors);

    if let Some(provider) = instances.get("provider-registry.implementation.json") {
        validate_provider_registry(provider, errors);
    }
    if let Some(registry) = instances.get("action-resource-registry.implementation.json") {
        validate_action_resource_registry(root, registry, errors);
    }
    if let Some(profile) = instances.get("security-limit-profile.implementation.json") {
        validate_security_limit_profile(root, profile, errors);
    }
    if let Some(registry) = instances.get("conformance-trust-root-registry.implementation.json") {
        validate_conformance_trust_root_registry(
            root,
            registry,
            deployment.get("conformance_trust_root_registry_ref"),
            errors,
        );
        validate_trust_registry_applicability(deployment, registry, errors);
    }
}

fn validate_runtime_guard_control_ownership(deployment: &Value, errors: &mut Vec<String>) {
    let runtime_guards = deployment
        .pointer("/runtime_guard_evidence/guards")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let mut owner_by_control = BTreeMap::<String, String>::new();

    for (guard_index, guard) in runtime_guards.iter().enumerate() {
        let guard_id = string_field(guard, "guard_id")
            .map(str::to_string)
            .unwrap_or_else(|| format!("guard-index-{guard_index}"));
        if let Some(expected_kind) = guard
            .pointer("/expected_value/kind")
            .and_then(Value::as_str)
        {
            if expected_kind != guard_id {
                errors.push(format!(
                    "deployment-security-profile.implementation.json:/runtime_guard_evidence/guards/{guard_index}/expected_value/kind: {expected_kind} does not match guard_id {guard_id}"
                ));
            }
        }
        for (control_index, control) in array(guard, "control_ids").iter().enumerate() {
            let Some(control_id) = control.as_str() else {
                continue;
            };
            if let Some(previous_guard) =
                owner_by_control.insert(control_id.to_string(), guard_id.clone())
            {
                errors.push(format!(
                    "deployment-security-profile.implementation.json:/runtime_guard_evidence/guards/{guard_index}/control_ids/{control_index}: runtime guard control {control_id} is assigned to both {previous_guard} and {guard_id}; control IDs must be globally unique across runtime guards"
                ));
            }
        }
    }
}

fn validate_bound_document_ref(
    deployment: &Value,
    field: &str,
    expected_kind: &str,
    expected_locator: &str,
    target: Option<&Value>,
    errors: &mut Vec<String>,
) {
    let path = format!("deployment-security-profile.implementation.json:/{field}");
    let Some(reference) = deployment.get(field) else {
        return;
    };
    if string_field(reference, "artifact_kind") != Some(expected_kind) {
        errors.push(format!("{path}: artifact_kind must be {expected_kind}"));
    }
    if string_field(reference, "artifact_locator") != Some(expected_locator) {
        errors.push(format!(
            "{path}: artifact_locator must be the authoritative {expected_locator}"
        ));
    }
    let Some(target) = target else {
        return;
    };
    for key in ["document_id", "document_version"] {
        if reference.get(key) != target.get(key) {
            errors.push(format!(
                "{path}: {key} does not match the referenced implementation document"
            ));
        }
    }
}

#[derive(Clone, Debug)]
struct LoadedTrustRegistry {
    locator: String,
    value: Value,
    digest: String,
}

fn validate_conformance_trust_root_registry(
    root: &Path,
    registry: &Value,
    bound_head_reference: Option<&Value>,
    errors: &mut Vec<String>,
) {
    let lineage = load_conformance_trust_root_registry_lineage(root, registry, errors);
    if let (Some(reference), Some(head)) = (bound_head_reference, lineage.last()) {
        if string_field(reference, "content_digest") != Some(head.digest.as_str()) {
            errors.push(format!(
                "deployment-security-profile.implementation.json:/conformance_trust_root_registry_ref: content_digest does not match the exact raw bytes of {}; expected {}",
                head.locator, head.digest
            ));
        }
    }
    validate_conformance_trust_root_registry_lineage_at(&lineage, Utc::now(), errors);
}

fn validate_conformance_trust_root_registry_at(
    registry: &Value,
    now: DateTime<Utc>,
    errors: &mut Vec<String>,
) {
    let lineage = [LoadedTrustRegistry {
        locator: "conformance-trust-root-registry.implementation.json".to_string(),
        value: registry.clone(),
        digest: String::new(),
    }];
    validate_conformance_trust_root_registry_lineage_at(&lineage, now, errors);
}

fn load_conformance_trust_root_registry_lineage(
    root: &Path,
    head: &Value,
    errors: &mut Vec<String>,
) -> Vec<LoadedTrustRegistry> {
    let Some(head_path) = safe_trust_registry_path(
        root,
        TRUST_REGISTRY_HEAD_LOCATOR,
        TRUST_REGISTRY_HEAD_LOCATOR,
        errors,
    ) else {
        return Vec::new();
    };
    let Some(head_bytes) =
        read_bounded_trust_registry(&head_path, TRUST_REGISTRY_HEAD_LOCATOR, errors)
    else {
        return Vec::new();
    };
    let parsed_head = match parse_json_strict(&head_bytes) {
        Ok(value) => value,
        Err(error) => {
            errors.push(format!(
                "{TRUST_REGISTRY_HEAD_LOCATOR}: invalid strict JSON: {error}"
            ));
            return Vec::new();
        }
    };
    if &parsed_head != head {
        errors.push(format!(
            "{TRUST_REGISTRY_HEAD_LOCATOR}: parsed head differs from the validated implementation instance"
        ));
    }

    let schema_path = root.join(CONTRACT_DIR).join(TRUST_REGISTRY_SCHEMA_NAME);
    let schema = match fs::read(&schema_path) {
        Ok(bytes) => match parse_json_strict(&bytes) {
            Ok(schema) => Some(schema),
            Err(error) => {
                errors.push(format!(
                    "{}: cannot strict-parse lineage schema: {error}",
                    schema_path.display()
                ));
                None
            }
        },
        Err(error) => {
            errors.push(format!(
                "{}: cannot read lineage schema: {error}",
                schema_path.display()
            ));
            None
        }
    };
    let head_digest = raw_sha256_digest(&head_bytes);
    let mut newest_to_oldest = vec![LoadedTrustRegistry {
        locator: TRUST_REGISTRY_HEAD_LOCATOR.to_string(),
        value: parsed_head,
        digest: head_digest.clone(),
    }];
    let mut locator_digests =
        BTreeMap::from([(TRUST_REGISTRY_HEAD_LOCATOR.to_string(), head_digest.clone())]);
    let mut identity_digests = BTreeMap::new();
    if let (Some(id), Some(version)) = (
        string_field(&newest_to_oldest[0].value, "document_id"),
        newest_to_oldest[0]
            .value
            .get("document_version")
            .and_then(Value::as_u64),
    ) {
        identity_digests.insert((id.to_string(), version), head_digest);
    }

    loop {
        let current = newest_to_oldest
            .last()
            .expect("the trust-registry lineage starts with its head");
        let current_id = string_field(&current.value, "document_id").unwrap_or("");
        let current_version = current
            .value
            .get("document_version")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let predecessor = current.value.get("predecessor_registry_ref");

        if current_version == 1 {
            if predecessor.is_some_and(|reference| !reference.is_null()) {
                errors.push(format!(
                    "{}: version 1 must have a null predecessor_registry_ref",
                    current.locator
                ));
            }
            break;
        }
        if current_version == 0 {
            errors.push(format!(
                "{}: cannot traverse a registry with a non-positive document_version",
                current.locator
            ));
            break;
        }
        let Some(predecessor) = predecessor.filter(|reference| !reference.is_null()) else {
            errors.push(format!(
                "{}: version {current_version} has an incomplete predecessor lineage",
                current.locator
            ));
            break;
        };
        if newest_to_oldest.len() >= MAX_TRUST_REGISTRY_LINEAGE {
            errors.push(format!(
                "{}: trust-registry lineage exceeds {MAX_TRUST_REGISTRY_LINEAGE} documents",
                current.locator
            ));
            break;
        }

        let context = format!("{}:/predecessor_registry_ref", current.locator);
        if string_field(predecessor, "artifact_kind") != Some("conformance-trust-root-registry") {
            errors.push(format!(
                "{context}: artifact_kind must be conformance-trust-root-registry"
            ));
        }
        if string_field(predecessor, "document_id") != Some(current_id) {
            errors.push(format!(
                "{context}: predecessor must preserve document_id {current_id}"
            ));
        }
        if predecessor.get("document_version").and_then(Value::as_u64) != Some(current_version - 1)
        {
            errors.push(format!(
                "{context}: predecessor must be exact document_version {}",
                current_version - 1
            ));
        }
        let Some(locator) = string_field(predecessor, "artifact_locator") else {
            errors.push(format!("{context}: artifact_locator is required"));
            break;
        };
        let Some(expected_digest) = string_field(predecessor, "content_digest") else {
            errors.push(format!("{context}: content_digest is required"));
            break;
        };
        if !is_sha256_digest(expected_digest) {
            errors.push(format!(
                "{context}: content_digest must be sha256: plus 64 lowercase hexadecimal digits"
            ));
        }

        if let Some(previous_digest) = locator_digests.get(locator) {
            if previous_digest != expected_digest {
                errors.push(format!(
                    "{context}: locator {locator} is referenced with conflicting digests"
                ));
            } else {
                errors.push(format!(
                    "{context}: trust-registry lineage contains a locator cycle at {locator}"
                ));
            }
            break;
        }
        let referenced_identity = (
            string_field(predecessor, "document_id")
                .unwrap_or("")
                .to_string(),
            predecessor
                .get("document_version")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        );
        if let Some(previous_digest) = identity_digests.get(&referenced_identity) {
            if previous_digest != expected_digest {
                errors.push(format!(
                    "{context}: registry {}@{} is referenced with conflicting digests",
                    referenced_identity.0, referenced_identity.1
                ));
            } else {
                errors.push(format!(
                    "{context}: trust-registry lineage repeats {}@{}",
                    referenced_identity.0, referenced_identity.1
                ));
            }
            break;
        }

        let Some(path) = safe_trust_registry_path(root, locator, &context, errors) else {
            break;
        };
        let Some(bytes) = read_bounded_trust_registry(&path, locator, errors) else {
            break;
        };
        let actual_digest = raw_sha256_digest(&bytes);
        if actual_digest != expected_digest {
            errors.push(format!(
                "{context}: content_digest does not match exact raw bytes at {locator}; expected {actual_digest}"
            ));
            break;
        }
        let value = match parse_json_strict(&bytes) {
            Ok(value) => value,
            Err(error) => {
                errors.push(format!("{locator}: invalid strict JSON: {error}"));
                break;
            }
        };
        if let Some(schema) = schema.as_ref() {
            validate_instance(locator, TRUST_REGISTRY_SCHEMA_NAME, schema, &value, errors);
        }
        validate_declared_schema(locator, TRUST_REGISTRY_SCHEMA_NAME, &value, errors);
        if string_field(&value, "contract_kind") != Some("conformance-trust-root-registry") {
            errors.push(format!(
                "{context}: artifact_kind does not match contract_kind at {locator}"
            ));
        }
        if value.get("document_id") != predecessor.get("document_id") {
            errors.push(format!(
                "{context}: document_id does not match the referenced artifact {locator}"
            ));
        }
        if value.get("document_version") != predecessor.get("document_version") {
            errors.push(format!(
                "{context}: document_version does not match the referenced artifact {locator}"
            ));
        }

        let actual_identity = (
            string_field(&value, "document_id")
                .unwrap_or("")
                .to_string(),
            value
                .get("document_version")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        );
        if let Some(previous_digest) = identity_digests.get(&actual_identity) {
            if previous_digest != &actual_digest {
                errors.push(format!(
                    "{context}: loaded registry {}@{} conflicts with an earlier digest",
                    actual_identity.0, actual_identity.1
                ));
            } else {
                errors.push(format!(
                    "{context}: loaded registry repeats {}@{}",
                    actual_identity.0, actual_identity.1
                ));
            }
            break;
        }

        locator_digests.insert(locator.to_string(), actual_digest.clone());
        identity_digests.insert(actual_identity, actual_digest.clone());
        newest_to_oldest.push(LoadedTrustRegistry {
            locator: locator.to_string(),
            value,
            digest: actual_digest,
        });
    }

    newest_to_oldest.reverse();
    newest_to_oldest
}

fn read_bounded_trust_registry(
    path: &Path,
    label: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<u8>> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            errors.push(format!("{label}: cannot inspect trust registry: {error}"));
            return None;
        }
    };
    if metadata.len() > MAX_TRUST_REGISTRY_BYTES {
        errors.push(format!(
            "{label}: trust registry exceeds {MAX_TRUST_REGISTRY_BYTES} bytes"
        ));
        return None;
    }
    match fs::read(path) {
        Ok(bytes) => Some(bytes),
        Err(error) => {
            errors.push(format!("{label}: cannot read trust registry: {error}"));
            None
        }
    }
}

fn safe_trust_registry_path(
    root: &Path,
    locator: &str,
    context: &str,
    errors: &mut Vec<String>,
) -> Option<PathBuf> {
    let relative = Path::new(locator);
    if locator.is_empty()
        || locator.contains('\\')
        || relative
            .extension()
            .and_then(|extension| extension.to_str())
            != Some("json")
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        errors.push(format!(
            "{context}: trust-registry locator must be a normalized relative .json path: {locator:?}"
        ));
        return None;
    }

    let mut candidate = root.to_path_buf();
    let components = relative.components().collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(name) = component else {
            unreachable!("the path shape was checked above")
        };
        candidate.push(name);
        let metadata = match fs::symlink_metadata(&candidate) {
            Ok(metadata) => metadata,
            Err(error) => {
                errors.push(format!(
                    "{context}: trust-registry locator does not resolve to a file {locator}: {error}"
                ));
                return None;
            }
        };
        if metadata.file_type().is_symlink() {
            errors.push(format!(
                "{context}: trust-registry locator must not traverse a symlink: {locator}"
            ));
            return None;
        }
        let final_component = index + 1 == components.len();
        if (!final_component && !metadata.is_dir())
            || (final_component && !metadata.file_type().is_file())
        {
            errors.push(format!(
                "{context}: trust-registry locator is not a regular JSON file: {locator}"
            ));
            return None;
        }
    }

    let canonical_root = match fs::canonicalize(root) {
        Ok(path) => path,
        Err(error) => {
            errors.push(format!(
                "{context}: cannot canonicalize repository root: {error}"
            ));
            return None;
        }
    };
    let canonical_target = match fs::canonicalize(&candidate) {
        Ok(path) => path,
        Err(error) => {
            errors.push(format!("{context}: cannot canonicalize {locator}: {error}"));
            return None;
        }
    };
    if !canonical_target.starts_with(canonical_root) {
        errors.push(format!(
            "{context}: trust-registry locator escapes the repository: {locator}"
        ));
        return None;
    }
    Some(candidate)
}

fn raw_sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value.as_bytes()[7..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn validate_conformance_trust_root_registry_lineage_at(
    lineage: &[LoadedTrustRegistry],
    now: DateTime<Utc>,
    errors: &mut Vec<String>,
) {
    if lineage.is_empty() {
        errors.push("conformance trust-root registry lineage is empty".to_string());
        return;
    }
    if lineage.len() > MAX_TRUST_REGISTRY_LINEAGE {
        errors.push(format!(
            "conformance trust-root registry lineage exceeds {MAX_TRUST_REGISTRY_LINEAGE} documents"
        ));
    }

    for (index, registry) in lineage.iter().enumerate() {
        validate_conformance_trust_root_registry_document_at(
            &registry.value,
            &registry.locator,
            now,
            index + 1 == lineage.len(),
            errors,
        );
    }
    validate_trust_registry_lineage_transitions(lineage, errors);
}

fn validate_conformance_trust_root_registry_document_at(
    registry: &Value,
    label: &str,
    now: DateTime<Utc>,
    is_head: bool,
    errors: &mut Vec<String>,
) {
    require_exact_string(
        registry,
        "$schema",
        "https://ryuki.io/schemas/security-contracts/v1/conformance-trust-root-registry.schema.json",
        label,
        errors,
    );
    require_exact_string(registry, "schema_version", "1.0.0", label, errors);
    require_exact_string(
        registry,
        "contract_kind",
        "conformance-trust-root-registry",
        label,
        errors,
    );
    for field in ["document_version", "trust_policy_version"] {
        if registry.get(field).and_then(Value::as_u64).unwrap_or(0) == 0 {
            errors.push(format!("{label}: {field} must be a positive version"));
        }
    }
    enforce_array_bound(registry, "keys", MAX_TRUST_REGISTRY_KEYS, label, errors);
    enforce_array_bound(
        registry,
        "key_tombstones",
        MAX_TRUST_REGISTRY_TOMBSTONES,
        label,
        errors,
    );

    let acceptance = string_field(registry, "acceptance_status").unwrap_or("");
    let production = registry
        .get("production_accepted")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let lifecycle = registry.get("lifecycle").unwrap_or(&Value::Null);
    let lifecycle_state = string_field(lifecycle, "state").unwrap_or("");
    match acceptance {
        "implementation_only" if production => errors.push(format!(
            "{label}: implementation_only registry cannot be production accepted"
        )),
        "production_candidate" if production => errors.push(format!(
            "{label}: production_candidate registry cannot be production accepted"
        )),
        "production_accepted" if !production || lifecycle_state != "active" => errors.push(
            format!("{label}: production_accepted registry must be active and production accepted"),
        ),
        _ => {}
    }
    if lifecycle_state == "active" && !production {
        errors.push(format!(
            "{label}: active registry must be production accepted"
        ));
    }
    if let Some(effective_at) = parse_timestamp_value(
        lifecycle,
        "effective_at",
        &format!("{label}:/lifecycle"),
        errors,
    ) {
        if lifecycle_state == "active" && effective_at > now {
            errors.push(format!(
                "{label}:/lifecycle: active effective_at cannot be in the future"
            ));
        }
    }

    let canonicalization = string_set(array(registry, "canonicalization_profiles"));
    if canonicalization != BTreeSet::from(["ryuki-canonical-json-v1".to_string()]) {
        errors.push(format!(
            "{label}: canonicalization_profiles must contain only ryuki-canonical-json-v1"
        ));
    }
    let algorithms = string_set(array(registry, "signature_algorithms"));
    if algorithms != BTreeSet::from(["ed25519".to_string()]) {
        errors.push(format!(
            "{label}: signature_algorithms must contain only ed25519"
        ));
    }

    let applicability = registry.get("applicability").unwrap_or(&Value::Null);
    require_exact_string(
        applicability,
        "evaluation_scope",
        "deployment",
        &format!("{label}:/applicability"),
        errors,
    );
    for (field, maximum) in [
        ("security_profiles", MAX_TRUST_REGISTRY_PROFILES),
        ("deployment_ids", MAX_TRUST_REGISTRY_SCOPE_ITEMS),
        ("trust_domain_ids", MAX_TRUST_REGISTRY_SCOPE_ITEMS),
    ] {
        enforce_array_bound(
            applicability,
            field,
            maximum,
            &format!("{label}:/applicability"),
            errors,
        );
    }
    let registry_deployments = unique_string_array(
        applicability,
        "deployment_ids",
        &format!("{label}:/applicability"),
        errors,
    );
    let registry_domains = unique_string_array(
        applicability,
        "trust_domain_ids",
        &format!("{label}:/applicability"),
        errors,
    );
    unique_string_array(
        applicability,
        "security_profiles",
        &format!("{label}:/applicability"),
        errors,
    );

    let mut keys = BTreeMap::new();
    let mut key_material = BTreeSet::new();
    let mut live_fingerprints = BTreeSet::new();
    let mut successor_edges = BTreeMap::new();
    let tombstone_index = array(registry, "key_tombstones")
        .iter()
        .filter_map(|tombstone| {
            string_field(tombstone, "key_id").map(|key_id| (key_id.to_string(), tombstone))
        })
        .collect::<BTreeMap<_, _>>();
    for (index, key) in array(registry, "keys").iter().enumerate() {
        let context = format!("{label}:/keys/{index}");
        let key_id = string_field(key, "key_id").unwrap_or("");
        if keys.insert(key_id.to_string(), key).is_some() {
            errors.push(format!("{context}: duplicate key_id {key_id}"));
        }
        require_exact_string(key, "algorithm", "ed25519", &context, errors);
        match string_field(key, "public_key_base64")
            .ok_or_else(|| "public_key_base64 is missing".to_string())
            .and_then(decode_canonical_ed25519_public_key)
        {
            Ok(decoded) => {
                if decoded.iter().all(|byte| *byte == 0) {
                    errors.push(format!(
                        "{context}: Ed25519 public key cannot be all zeroes"
                    ));
                }
                let fingerprint = raw_sha256_digest(&decoded);
                live_fingerprints.insert(fingerprint.clone());
                if !key_material.insert(decoded) {
                    errors.push(format!("{context}: duplicate Ed25519 public-key material"));
                }
                if string_field(key, "public_key_fingerprint") != Some(fingerprint.as_str()) {
                    errors.push(format!(
                        "{context}: public_key_fingerprint must equal SHA-256 of the decoded raw 32-byte key; expected {fingerprint}"
                    ));
                }
            }
            Err(error) => errors.push(format!("{context}: {error}")),
        }

        for (field, allowed) in [
            ("deployment_ids", &registry_deployments),
            ("trust_domain_ids", &registry_domains),
        ] {
            enforce_array_bound(key, field, MAX_TRUST_REGISTRY_SCOPE_ITEMS, &context, errors);
            let values = unique_string_array(key, field, &context, errors);
            for value in values.difference(allowed) {
                errors.push(format!(
                    "{context}: {field} value {value} is outside registry applicability"
                ));
            }
        }
        for (field, maximum) in [
            ("allowed_purposes", MAX_TRUST_KEY_PURPOSES),
            ("allowed_evidence_tiers", MAX_TRUST_KEY_EVIDENCE_TIERS),
            ("allowed_package_ids", MAX_TRUST_KEY_PACKAGES),
        ] {
            enforce_array_bound(key, field, maximum, &context, errors);
            if unique_string_array(key, field, &context, errors).is_empty() {
                errors.push(format!("{context}: {field} must not be empty"));
            }
        }

        let valid_from = parse_timestamp_value(key, "valid_from", &context, errors);
        let valid_until = parse_timestamp_value(key, "valid_until", &context, errors);
        if valid_from
            .zip(valid_until)
            .is_some_and(|(start, end)| start >= end)
        {
            errors.push(format!("{context}: valid_from must be before valid_until"));
        }
        let key_lifecycle = string_field(key, "lifecycle").unwrap_or("");
        if !matches!(key_lifecycle, "active" | "overlap") {
            errors.push(format!(
                "{context}: live key lifecycle must be active or overlap"
            ));
        }
        if key.get("revoked_at").is_some() {
            errors.push(format!(
                "{context}: live key must not declare revoked_at; terminal state belongs in a tombstone"
            ));
        }
        if is_head
            && matches!(key_lifecycle, "active" | "overlap")
            && (valid_from.is_some_and(|start| start > now)
                || valid_until.is_some_and(|end| end <= now))
        {
            errors.push(format!(
                "{context}: {key_lifecycle} key is outside its validity window"
            ));
        }
        if let Some(target) = key.get("supersedes_key_id").and_then(Value::as_str) {
            if target == key_id {
                errors.push(format!("{context}: key cannot supersede itself"));
            }
            successor_edges.insert(key_id.to_string(), target.to_string());
        }
    }
    if acceptance == "production_accepted"
        && !keys
            .values()
            .any(|key| string_field(key, "lifecycle") == Some("active"))
    {
        errors.push(format!(
            "{label}: production_accepted registry requires at least one active key; overlap-only authority is forbidden"
        ));
    }
    let mut predecessor_successors = BTreeMap::<String, String>::new();
    for (source_id, target_id) in &successor_edges {
        let Some(source) = keys.get(source_id) else {
            continue;
        };
        if string_field(source, "lifecycle") != Some("active") {
            errors.push(format!(
                "{label}: live superseding key {source_id} must be active"
            ));
        }
        if let Some(existing_successor) =
            predecessor_successors.insert(target_id.clone(), source_id.clone())
        {
            errors.push(format!(
                "{label}: live predecessor {target_id} has multiple successors {existing_successor} and {source_id}"
            ));
        }
        let target = keys.get(target_id).copied();
        let tombstone_target = tombstone_index.get(target_id).copied();
        if target.is_none() && tombstone_target.is_none() {
            errors.push(format!(
                "{label}: key {source_id} supersedes unknown key {target_id}"
            ));
            continue;
        }
        if target.is_some_and(|target| string_field(target, "lifecycle") != Some("overlap")) {
            errors.push(format!(
                "{label}: live predecessor {target_id} of {source_id} must be overlap"
            ));
        }
        let target = target.or(tombstone_target).expect("one target exists");
        for field in ["signer_identity", "algorithm"] {
            if source.get(field) != target.get(field) {
                errors.push(format!(
                    "{label}: key {source_id} cannot supersede {target_id} with a different {field}"
                ));
            }
        }
        let source_start = string_field(source, "valid_from")
            .and_then(|timestamp| DateTime::parse_from_rfc3339(timestamp).ok())
            .map(|timestamp| timestamp.with_timezone(&Utc));
        let target_start = string_field(target, "valid_from")
            .or_else(|| string_field(target, "terminated_at"))
            .and_then(|timestamp| DateTime::parse_from_rfc3339(timestamp).ok())
            .map(|timestamp| timestamp.with_timezone(&Utc));
        if source_start
            .zip(target_start)
            .is_some_and(|(source_start, target_start)| source_start <= target_start)
        {
            errors.push(format!(
                "{label}: superseding key {source_id} must have a later valid_from than {target_id}"
            ));
        }
    }
    detect_single_edge_cycles("conformance key supersession", &successor_edges, errors);

    let mut tombstones = BTreeSet::new();
    let mut tombstone_fingerprints = BTreeSet::new();
    let trust_policy_version = registry
        .get("trust_policy_version")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    for (index, tombstone) in array(registry, "key_tombstones").iter().enumerate() {
        let context = format!("{label}:/key_tombstones/{index}");
        let key_id = string_field(tombstone, "key_id").unwrap_or("");
        if !tombstones.insert(key_id.to_string()) {
            errors.push(format!("{context}: duplicate tombstone key_id {key_id}"));
        }
        if keys.contains_key(key_id) {
            errors.push(format!(
                "{context}: tombstoned key_id {key_id} is reused by a key record"
            ));
        }
        require_exact_string(tombstone, "algorithm", "ed25519", &context, errors);
        let fingerprint = string_field(tombstone, "public_key_fingerprint").unwrap_or("");
        if !is_sha256_digest(fingerprint) {
            errors.push(format!(
                "{context}: public_key_fingerprint must be sha256: plus 64 lowercase hexadecimal digits"
            ));
        }
        if !tombstone_fingerprints.insert(fingerprint.to_string()) {
            errors.push(format!(
                "{context}: duplicate tombstone public_key_fingerprint {fingerprint}"
            ));
        }
        if live_fingerprints.contains(fingerprint) {
            errors.push(format!(
                "{context}: tombstoned public-key material is reused by a live key"
            ));
        }
        let terminal_state = string_field(tombstone, "terminal_state").unwrap_or("");
        if !matches!(terminal_state, "retired" | "revoked") {
            errors.push(format!(
                "{context}: terminal_state must be retired or revoked"
            ));
        }
        let terminated_at = parse_timestamp_value(tombstone, "terminated_at", &context, errors);
        if terminated_at.is_some_and(|timestamp| timestamp > now) {
            errors.push(format!(
                "{context}: tombstone terminated_at cannot be in the future"
            ));
        }
        let signatures_valid_before =
            optional_timestamp_value(tombstone, "signatures_valid_before", &context, errors);
        let tombstone_policy = tombstone
            .get("trust_policy_version")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let subsequent_revocation = tombstone.get("subsequent_revocation");
        match terminal_state {
            "retired" => {
                let Some(cutoff) = signatures_valid_before else {
                    errors.push(format!(
                        "{context}: retired tombstone requires signatures_valid_before"
                    ));
                    continue;
                };
                if terminated_at.is_some_and(|terminated| cutoff != terminated) {
                    errors.push(format!(
                        "{context}: retired signatures_valid_before must equal terminated_at"
                    ));
                }
            }
            "revoked" => {
                if signatures_valid_before.is_some() {
                    errors.push(format!(
                        "{context}: revoked tombstone must set signatures_valid_before to null"
                    ));
                }
                if subsequent_revocation.is_some_and(|value| !value.is_null()) {
                    errors.push(format!(
                        "{context}: directly revoked tombstone must set subsequent_revocation to null"
                    ));
                }
            }
            _ => {}
        }
        if let Some(subsequent_revocation) = subsequent_revocation.filter(|value| !value.is_null())
        {
            if terminal_state != "retired" {
                errors.push(format!(
                    "{context}: only a retired tombstone may add subsequent_revocation"
                ));
            }
            let revoked_at = parse_timestamp_value(
                subsequent_revocation,
                "revoked_at",
                &format!("{context}/subsequent_revocation"),
                errors,
            );
            if revoked_at.is_some_and(|timestamp| timestamp > now) {
                errors.push(format!(
                    "{context}/subsequent_revocation: revoked_at cannot be in the future"
                ));
            }
            if terminated_at
                .zip(revoked_at)
                .is_some_and(|(terminated_at, revoked_at)| revoked_at < terminated_at)
            {
                errors.push(format!(
                    "{context}/subsequent_revocation: revoked_at cannot predate terminated_at"
                ));
            }
            if registry_effective_at(registry)
                .zip(revoked_at)
                .is_some_and(|(effective_at, revoked_at)| revoked_at > effective_at)
            {
                errors.push(format!(
                    "{context}/subsequent_revocation: revoked_at cannot follow the introducing registry effective_at"
                ));
            }
            if !subsequent_revocation
                .get("reason")
                .is_some_and(Value::is_string)
            {
                errors.push(format!(
                    "{context}/subsequent_revocation: reason must be a string"
                ));
            }
            let revocation_policy = subsequent_revocation
                .get("trust_policy_version")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            if revocation_policy <= tombstone_policy || revocation_policy > trust_policy_version {
                errors.push(format!(
                    "{context}/subsequent_revocation: trust_policy_version must advance beyond {tombstone_policy} and be no newer than the registry"
                ));
            }
        }
        if tombstone_policy == 0 || tombstone_policy > trust_policy_version {
            errors.push(format!(
                "{context}: tombstone trust_policy_version must be nonzero and no newer than the registry"
            ));
        }
        if let Some(successor_id) = tombstone
            .get("superseded_by_key_id")
            .and_then(Value::as_str)
        {
            if successor_id == key_id {
                errors.push(format!("{context}: tombstone cannot supersede itself"));
            }
            let successor = keys
                .get(successor_id)
                .copied()
                .or_else(|| tombstone_index.get(successor_id).copied());
            let Some(successor) = successor else {
                errors.push(format!(
                    "{context}: superseded_by_key_id references unknown live or tombstoned key {successor_id}"
                ));
                continue;
            };
            for field in ["signer_identity", "algorithm"] {
                if tombstone.get(field) != successor.get(field) {
                    errors.push(format!(
                        "{context}: successor key {successor_id} has a different {field}"
                    ));
                }
            }
        }
    }
}

fn enforce_array_bound(
    value: &Value,
    field: &str,
    maximum: usize,
    context: &str,
    errors: &mut Vec<String>,
) {
    if array(value, field).len() > maximum {
        errors.push(format!(
            "{context}: {field} exceeds the maximum of {maximum} items"
        ));
    }
}

fn validate_trust_registry_lineage_transitions(
    lineage: &[LoadedTrustRegistry],
    errors: &mut Vec<String>,
) {
    let Some(genesis) = lineage.first() else {
        return;
    };
    if genesis
        .value
        .get("document_version")
        .and_then(Value::as_u64)
        != Some(1)
    {
        errors.push(format!(
            "{}: trust-registry lineage must terminate at document_version 1",
            genesis.locator
        ));
    }
    if genesis
        .value
        .get("predecessor_registry_ref")
        .is_some_and(|reference| !reference.is_null())
    {
        errors.push(format!(
            "{}: genesis predecessor_registry_ref must be null",
            genesis.locator
        ));
    }
    if !array(&genesis.value, "key_tombstones").is_empty() {
        errors.push(format!(
            "{}: genesis registry cannot contain tombstones without prior live-key history",
            genesis.locator
        ));
    }
    validate_new_key_activation_times(genesis, errors);

    let mut id_to_fingerprint = BTreeMap::<String, String>::new();
    let mut fingerprint_to_id = BTreeMap::<String, String>::new();
    let mut terminal_ids = BTreeSet::new();
    for registry in lineage {
        for key in array(&registry.value, "keys") {
            let key_id = string_field(key, "key_id").unwrap_or("");
            let fingerprint = string_field(key, "public_key_fingerprint").unwrap_or("");
            bind_historic_key_identity(
                key_id,
                fingerprint,
                &registry.locator,
                &mut id_to_fingerprint,
                &mut fingerprint_to_id,
                errors,
            );
            if terminal_ids.contains(key_id) {
                errors.push(format!(
                    "{}: tombstoned key_id {key_id} is resurrected as a live key",
                    registry.locator
                ));
            }
        }
        for tombstone in array(&registry.value, "key_tombstones") {
            let key_id = string_field(tombstone, "key_id").unwrap_or("");
            let fingerprint = string_field(tombstone, "public_key_fingerprint").unwrap_or("");
            bind_historic_key_identity(
                key_id,
                fingerprint,
                &registry.locator,
                &mut id_to_fingerprint,
                &mut fingerprint_to_id,
                errors,
            );
            terminal_ids.insert(key_id.to_string());
        }
    }

    for pair in lineage.windows(2) {
        let previous = &pair[0];
        let current = &pair[1];
        validate_trust_registry_edge(previous, current, errors);
    }
}

fn bind_historic_key_identity(
    key_id: &str,
    fingerprint: &str,
    context: &str,
    id_to_fingerprint: &mut BTreeMap<String, String>,
    fingerprint_to_id: &mut BTreeMap<String, String>,
    errors: &mut Vec<String>,
) {
    if let Some(previous) = id_to_fingerprint.get(key_id) {
        if previous != fingerprint {
            errors.push(format!(
                "{context}: historical key_id {key_id} changes public-key fingerprint from {previous} to {fingerprint}"
            ));
        }
    } else {
        id_to_fingerprint.insert(key_id.to_string(), fingerprint.to_string());
    }
    if let Some(previous) = fingerprint_to_id.get(fingerprint) {
        if previous != key_id {
            errors.push(format!(
                "{context}: historical public-key fingerprint {fingerprint} is relabeled from {previous} to {key_id}"
            ));
        }
    } else {
        fingerprint_to_id.insert(fingerprint.to_string(), key_id.to_string());
    }
}

fn validate_trust_registry_edge(
    previous: &LoadedTrustRegistry,
    current: &LoadedTrustRegistry,
    errors: &mut Vec<String>,
) {
    let previous_id = string_field(&previous.value, "document_id").unwrap_or("");
    let current_id = string_field(&current.value, "document_id").unwrap_or("");
    let previous_version = previous
        .value
        .get("document_version")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let current_version = current
        .value
        .get("document_version")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if current_id != previous_id {
        errors.push(format!(
            "{}: registry document_id changes from {previous_id} to {current_id}",
            current.locator
        ));
    }
    if current_version != previous_version.saturating_add(1) {
        errors.push(format!(
            "{}: document_version {current_version} must immediately follow {previous_version}",
            current.locator
        ));
    }

    let reference = current
        .value
        .get("predecessor_registry_ref")
        .unwrap_or(&Value::Null);
    for (field, expected) in [
        (
            "artifact_kind",
            Value::String("conformance-trust-root-registry".to_string()),
        ),
        ("document_id", Value::String(previous_id.to_string())),
        ("document_version", Value::from(previous_version)),
        ("content_digest", Value::String(previous.digest.clone())),
        ("artifact_locator", Value::String(previous.locator.clone())),
    ] {
        if reference.get(field) != Some(&expected) {
            errors.push(format!(
                "{}:/predecessor_registry_ref: {field} does not exactly bind {}",
                current.locator, previous.locator
            ));
        }
    }

    let previous_effective = registry_effective_at(&previous.value);
    let current_effective = registry_effective_at(&current.value);
    if previous_effective.zip(current_effective).is_some_and(
        |(previous_effective, current_effective)| current_effective <= previous_effective,
    ) {
        errors.push(format!(
            "{}: lifecycle.effective_at must strictly increase from {}",
            current.locator, previous.locator
        ));
    }
    validate_registry_lifecycle_transition(previous, current, errors);
    if trust_registry_scope_projection(&previous.value)
        != trust_registry_scope_projection(&current.value)
    {
        errors.push(format!(
            "{}: registry applicability must remain exact across the lineage",
            current.locator
        ));
    }

    let previous_policy = previous
        .value
        .get("trust_policy_version")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let current_policy = current
        .value
        .get("trust_policy_version")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if current_policy < previous_policy || current_policy > previous_policy.saturating_add(1) {
        errors.push(format!(
            "{}: trust_policy_version {current_policy} must be between {previous_policy} and {}",
            current.locator,
            previous_policy.saturating_add(1)
        ));
    }
    if registry_authority_changed(&previous.value, &current.value)
        && current_policy != previous_policy.saturating_add(1)
    {
        errors.push(format!(
            "{}: an authority change requires trust_policy_version {}",
            current.locator,
            previous_policy.saturating_add(1)
        ));
    }

    let previous_keys = trust_registry_records(&previous.value, "keys");
    let current_keys = trust_registry_records(&current.value, "keys");
    let previous_tombstones = trust_registry_records(&previous.value, "key_tombstones");
    let current_tombstones = trust_registry_records(&current.value, "key_tombstones");

    for (key_id, previous_tombstone) in &previous_tombstones {
        match current_tombstones.get(key_id) {
            Some(current_tombstone)
                if tombstone_is_valid_successor(previous_tombstone, current_tombstone) => {}
            Some(_) => errors.push(format!(
                "{}: tombstone {key_id} mutates outside the one-way subsequent-revocation overlay",
                current.locator
            )),
            None => errors.push(format!(
                "{}: predecessor tombstone {key_id} is dropped",
                current.locator
            )),
        }
        if current_keys.contains_key(key_id) {
            errors.push(format!(
                "{}: predecessor tombstone {key_id} is resurrected",
                current.locator
            ));
        }
    }

    for (key_id, previous_key) in &previous_keys {
        if let Some(current_key) = current_keys.get(key_id) {
            if !live_key_is_immutable(previous_key, current_key) {
                errors.push(format!(
                    "{}: recurring live key {key_id} changes an immutable authority field",
                    current.locator
                ));
            }
            validate_live_key_lifecycle_transition(
                key_id,
                previous_key,
                current_key,
                &current.locator,
                errors,
            );
            continue;
        }
        let Some(tombstone) = current_tombstones.get(key_id) else {
            errors.push(format!(
                "{}: predecessor live key {key_id} disappears without an immediate tombstone",
                current.locator
            ));
            continue;
        };
        for field in [
            "key_id",
            "signer_identity",
            "algorithm",
            "public_key_fingerprint",
        ] {
            if tombstone.get(field) != previous_key.get(field) {
                errors.push(format!(
                    "{}: tombstone {key_id} does not preserve predecessor {field}",
                    current.locator
                ));
            }
        }
        let terminated_at = string_field(tombstone, "terminated_at")
            .and_then(|timestamp| DateTime::parse_from_rfc3339(timestamp).ok())
            .map(|timestamp| timestamp.with_timezone(&Utc));
        let valid_from = string_field(previous_key, "valid_from")
            .and_then(|timestamp| DateTime::parse_from_rfc3339(timestamp).ok())
            .map(|timestamp| timestamp.with_timezone(&Utc));
        let valid_until = string_field(previous_key, "valid_until")
            .and_then(|timestamp| DateTime::parse_from_rfc3339(timestamp).ok())
            .map(|timestamp| timestamp.with_timezone(&Utc));
        if terminated_at.zip(valid_from.zip(valid_until)).is_some_and(
            |(terminated_at, (valid_from, valid_until))| {
                terminated_at < valid_from || terminated_at > valid_until
            },
        ) {
            errors.push(format!(
                "{}: tombstone {key_id} terminated_at must fall within the predecessor key validity window",
                current.locator
            ));
        }
    }

    for (key_id, tombstone) in &current_tombstones {
        if previous_tombstones.contains_key(key_id) {
            continue;
        }
        let Some(previous_key) = previous_keys.get(key_id) else {
            errors.push(format!(
                "{}: newly introduced tombstone {key_id} has no immediately preceding live key",
                current.locator
            ));
            continue;
        };
        for field in [
            "key_id",
            "signer_identity",
            "algorithm",
            "public_key_fingerprint",
        ] {
            if tombstone.get(field) != previous_key.get(field) {
                errors.push(format!(
                    "{}: newly introduced tombstone {key_id} changes predecessor {field}",
                    current.locator
                ));
            }
        }
    }

    let current_effective_at = registry_effective_at(&current.value);
    for (key_id, current_key) in &current_keys {
        if previous_keys.contains_key(key_id) {
            continue;
        }
        if previous_tombstones.contains_key(key_id) {
            errors.push(format!(
                "{}: tombstoned key_id {key_id} cannot become live again",
                current.locator
            ));
        }
        let valid_from = string_field(current_key, "valid_from")
            .and_then(|timestamp| DateTime::parse_from_rfc3339(timestamp).ok())
            .map(|timestamp| timestamp.with_timezone(&Utc));
        if valid_from
            .zip(current_effective_at)
            .is_some_and(|(valid_from, effective_at)| valid_from < effective_at)
        {
            errors.push(format!(
                "{}: newly introduced key {key_id} valid_from cannot predate registry effective_at",
                current.locator
            ));
        }
    }
}

fn validate_new_key_activation_times(registry: &LoadedTrustRegistry, errors: &mut Vec<String>) {
    let effective_at = registry_effective_at(&registry.value);
    let previous_ids = registry
        .value
        .get("predecessor_registry_ref")
        .is_some_and(|value| !value.is_null());
    for (index, key) in array(&registry.value, "keys").iter().enumerate() {
        // For a non-genesis document, recurring keys are filtered by the edge
        // validator below. This local check intentionally covers genesis; the
        // edge validator calls the same comparison only for newly introduced
        // keys after identifying its predecessor.
        if previous_ids {
            continue;
        }
        let valid_from = string_field(key, "valid_from")
            .and_then(|timestamp| DateTime::parse_from_rfc3339(timestamp).ok())
            .map(|timestamp| timestamp.with_timezone(&Utc));
        if valid_from
            .zip(effective_at)
            .is_some_and(|(valid_from, effective_at)| valid_from < effective_at)
        {
            errors.push(format!(
                "{}:/keys/{index}: newly introduced key valid_from cannot predate registry effective_at",
                registry.locator
            ));
        }
    }
}

fn validate_registry_lifecycle_transition(
    previous: &LoadedTrustRegistry,
    current: &LoadedTrustRegistry,
    errors: &mut Vec<String>,
) {
    let previous_state = previous
        .value
        .get("lifecycle")
        .and_then(|value| string_field(value, "state"))
        .unwrap_or("");
    let current_state = current
        .value
        .get("lifecycle")
        .and_then(|value| string_field(value, "state"))
        .unwrap_or("");
    let valid = matches!(
        (previous_state, current_state),
        ("implementation_only", "implementation_only" | "candidate")
            | ("candidate", "candidate" | "active")
            | ("active", "active" | "deprecated" | "retired")
            | ("deprecated", "deprecated" | "retired")
            | ("retired", "retired")
    );
    if !valid {
        errors.push(format!(
            "{}: registry lifecycle cannot transition from {previous_state} to {current_state}",
            current.locator
        ));
    }
}

fn registry_effective_at(registry: &Value) -> Option<DateTime<Utc>> {
    registry
        .get("lifecycle")
        .and_then(|lifecycle| string_field(lifecycle, "effective_at"))
        .and_then(|timestamp| DateTime::parse_from_rfc3339(timestamp).ok())
        .map(|timestamp| timestamp.with_timezone(&Utc))
}

fn trust_registry_records(registry: &Value, field: &str) -> BTreeMap<String, Value> {
    array(registry, field)
        .iter()
        .filter_map(|record| {
            string_field(record, "key_id").map(|key_id| (key_id.to_string(), record.clone()))
        })
        .collect()
}

fn live_key_is_immutable(previous: &Value, current: &Value) -> bool {
    let mut previous = previous.clone();
    let mut current = current.clone();
    if let Some(object) = previous.as_object_mut() {
        object.remove("lifecycle");
    }
    if let Some(object) = current.as_object_mut() {
        object.remove("lifecycle");
    }
    previous == current
}

fn validate_live_key_lifecycle_transition(
    key_id: &str,
    previous: &Value,
    current: &Value,
    context: &str,
    errors: &mut Vec<String>,
) {
    let previous_lifecycle = string_field(previous, "lifecycle").unwrap_or("");
    let current_lifecycle = string_field(current, "lifecycle").unwrap_or("");
    if !matches!(
        (previous_lifecycle, current_lifecycle),
        ("active", "active" | "overlap") | ("overlap", "overlap")
    ) {
        errors.push(format!(
            "{context}: live key {key_id} lifecycle cannot transition from {previous_lifecycle} to {current_lifecycle}"
        ));
    }
}

fn tombstone_is_valid_successor(previous: &Value, current: &Value) -> bool {
    if previous == current {
        return true;
    }
    if string_field(previous, "terminal_state") != Some("retired")
        || string_field(current, "terminal_state") != Some("retired")
        || !previous
            .get("subsequent_revocation")
            .is_some_and(Value::is_null)
        || !current
            .get("subsequent_revocation")
            .is_some_and(Value::is_object)
    {
        return false;
    }
    let terminated_at = string_field(current, "terminated_at")
        .and_then(|timestamp| DateTime::parse_from_rfc3339(timestamp).ok())
        .map(|timestamp| timestamp.with_timezone(&Utc));
    let subsequent_revocation = current
        .get("subsequent_revocation")
        .expect("the overlay object was checked above");
    let revoked_at = string_field(subsequent_revocation, "revoked_at")
        .and_then(|timestamp| DateTime::parse_from_rfc3339(timestamp).ok())
        .map(|timestamp| timestamp.with_timezone(&Utc));
    if terminated_at
        .zip(revoked_at)
        .is_some_and(|(terminated_at, revoked_at)| revoked_at < terminated_at)
    {
        return false;
    }
    let mut previous = previous.clone();
    let mut current = current.clone();
    for value in [&mut previous, &mut current] {
        if let Some(object) = value.as_object_mut() {
            object.remove("subsequent_revocation");
        }
    }
    previous == current
}

fn registry_authority_changed(previous: &Value, current: &Value) -> bool {
    trust_registry_scope_projection(previous) != trust_registry_scope_projection(current)
        || string_set(array(previous, "canonicalization_profiles"))
            != string_set(array(current, "canonicalization_profiles"))
        || string_set(array(previous, "signature_algorithms"))
            != string_set(array(current, "signature_algorithms"))
        || trust_registry_records(previous, "keys") != trust_registry_records(current, "keys")
        || trust_registry_records(previous, "key_tombstones")
            != trust_registry_records(current, "key_tombstones")
}

fn trust_registry_scope_projection(
    registry: &Value,
) -> (String, BTreeSet<String>, BTreeSet<String>, BTreeSet<String>) {
    let applicability = registry.get("applicability").unwrap_or(&Value::Null);
    (
        string_field(applicability, "evaluation_scope")
            .unwrap_or("")
            .to_string(),
        string_set(array(applicability, "security_profiles")),
        string_set(array(applicability, "deployment_ids")),
        string_set(array(applicability, "trust_domain_ids")),
    )
}

fn validate_trust_registry_applicability(
    deployment: &Value,
    registry: &Value,
    errors: &mut Vec<String>,
) {
    let context = "conformance-trust-root-registry.implementation.json:/applicability";
    let applicability = registry.get("applicability").unwrap_or(&Value::Null);
    let deployment_applicability = deployment.get("applicability").unwrap_or(&Value::Null);
    for field in ["security_profiles", "deployment_ids"] {
        let expected = string_set(array(deployment_applicability, field));
        let actual = string_set(array(applicability, field));
        if actual != expected {
            errors.push(format!(
                "{context}: {field} {:?} does not exactly match deployment profile {:?}",
                actual, expected
            ));
        }
    }
    let expected_domains = string_set(array(
        deployment.get("trust_topology").unwrap_or(&Value::Null),
        "trust_domain_ids",
    ));
    let actual_domains = string_set(array(applicability, "trust_domain_ids"));
    if actual_domains != expected_domains {
        errors.push(format!(
            "{context}: trust_domain_ids {:?} do not exactly match deployment trust topology {:?}",
            actual_domains, expected_domains
        ));
    }
}

fn parse_timestamp_value(
    value: &Value,
    field: &str,
    context: &str,
    errors: &mut Vec<String>,
) -> Option<DateTime<Utc>> {
    let Some(raw) = string_field(value, field) else {
        errors.push(format!("{context}: {field} must be a timestamp"));
        return None;
    };
    match DateTime::parse_from_rfc3339(raw) {
        Ok(timestamp) => Some(timestamp.with_timezone(&Utc)),
        Err(error) => {
            errors.push(format!("{context}: invalid {field}: {error}"));
            None
        }
    }
}

fn optional_timestamp_value(
    value: &Value,
    field: &str,
    context: &str,
    errors: &mut Vec<String>,
) -> Option<DateTime<Utc>> {
    if value.get(field).is_none_or(Value::is_null) {
        None
    } else {
        parse_timestamp_value(value, field, context, errors)
    }
}

fn decode_canonical_ed25519_public_key(encoded: &str) -> Result<Vec<u8>, String> {
    let bytes = encoded.as_bytes();
    if bytes.len() != 44 || bytes[43] != b'=' || bytes[..43].contains(&b'=') {
        return Err(
            "public_key_base64 must be canonical padded standard base64 for 32 bytes".to_string(),
        );
    }
    let mut decoded = Vec::with_capacity(32);
    for (index, chunk) in bytes.chunks_exact(4).enumerate() {
        let a = standard_base64_value(chunk[0])?;
        let b = standard_base64_value(chunk[1])?;
        let c = standard_base64_value(chunk[2])?;
        let final_chunk = index == 10;
        let d = if final_chunk {
            if chunk[3] != b'=' || c & 0b11 != 0 {
                return Err("public_key_base64 has non-canonical padding bits".to_string());
            }
            0
        } else {
            standard_base64_value(chunk[3])?
        };
        decoded.push((a << 2) | (b >> 4));
        decoded.push((b << 4) | (c >> 2));
        if !final_chunk {
            decoded.push((c << 6) | d);
        }
    }
    if decoded.len() != 32 {
        return Err("public_key_base64 must decode to exactly 32 bytes".to_string());
    }
    Ok(decoded)
}

fn standard_base64_value(byte: u8) -> Result<u8, String> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err("public_key_base64 contains a non-standard base64 character".to_string()),
    }
}

fn validate_provider_registry(registry: &Value, errors: &mut Vec<String>) {
    let mut configuration_keys = BTreeSet::<(String, u64)>::new();
    let mut provider_kinds = BTreeMap::new();
    for (index, configuration) in array(registry, "configurations").iter().enumerate() {
        let path = format!("provider-registry.implementation.json:/configurations/{index}");
        let provider_id = string_field(configuration, "provider_id").unwrap_or("");
        let version = configuration
            .get("config_version")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let key = (provider_id.to_string(), version);
        if !configuration_keys.insert(key) {
            errors.push(format!(
                "{path}: duplicate provider configuration {provider_id}@{version}"
            ));
        }
        if let Some(previous) = provider_kinds.insert(
            provider_id.to_string(),
            string_field(configuration, "kind")
                .unwrap_or("")
                .to_string(),
        ) {
            if previous != string_field(configuration, "kind").unwrap_or("") {
                errors.push(format!(
                    "{path}: provider_id {provider_id} changes kind from {previous}"
                ));
            }
        }
        let descriptor = configuration
            .get("capability_descriptor")
            .unwrap_or(&Value::Null);
        let advertised = array(descriptor, "advertised_capabilities");
        if advertised.is_empty()
            || advertised
                .windows(2)
                .any(|pair| pair[0].as_str().unwrap_or("") >= pair[1].as_str().unwrap_or(""))
        {
            errors.push(format!(
                "{path}: capability_descriptor.advertised_capabilities must be non-empty and strictly sorted"
            ));
        }
        validate_provider_payload_digest(configuration, &path, errors);
    }

    let mut lifecycle_keys = BTreeSet::new();
    let mut lifecycle_histories = BTreeMap::<(String, u64), Vec<(u64, &Value)>>::new();
    for (index, lifecycle) in array(registry, "provider_lifecycle").iter().enumerate() {
        let path = format!("provider-registry.implementation.json:/provider_lifecycle/{index}");
        let provider_id = string_field(lifecycle, "provider_id").unwrap_or("");
        let config_version = lifecycle
            .get("config_version")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let record_version = lifecycle
            .get("lifecycle_record_version")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let configuration_key = format!("{provider_id}@{config_version}");
        let lifecycle_key = format!("{configuration_key}#{record_version}");
        let unique_record = lifecycle_keys.insert(lifecycle_key.clone());
        if !unique_record {
            errors.push(format!(
                "{path}: duplicate provider lifecycle record {lifecycle_key}"
            ));
        }
        if !configuration_keys.contains(&(provider_id.to_string(), config_version)) {
            errors.push(format!(
                "{path}: lifecycle record references unknown provider configuration {configuration_key}"
            ));
        }
        let _ = parse_timestamp_value(lifecycle, "effective_at", &path, errors);
        if unique_record {
            lifecycle_histories
                .entry((provider_id.to_string(), config_version))
                .or_default()
                .push((record_version, lifecycle));
        }
    }

    for (provider_id, config_version) in &configuration_keys {
        if !lifecycle_histories.contains_key(&(provider_id.clone(), *config_version)) {
            errors.push(format!(
                "provider-registry.implementation.json:/configurations: provider configuration {provider_id}@{config_version} has no lifecycle history"
            ));
        }
    }

    let mut active_configurations = BTreeMap::<String, Vec<u64>>::new();
    for ((provider_id, config_version), history) in &mut lifecycle_histories {
        history.sort_by_key(|(record_version, _)| *record_version);
        let context = format!("provider lifecycle {provider_id}@{config_version}");
        for (index, (record_version, record)) in history.iter().enumerate() {
            if index == 0 {
                if *record_version != 1
                    || record.get("supersedes_lifecycle_record_version").is_some()
                {
                    errors.push(format!("{context} must start at version 1"));
                }
                if string_field(record, "state") != Some("configured") {
                    errors.push(format!("{context} must begin configured"));
                }
                continue;
            }

            let (previous_version, previous_record) = history[index - 1];
            if *record_version != previous_version.saturating_add(1)
                || record
                    .get("supersedes_lifecycle_record_version")
                    .and_then(Value::as_u64)
                    != Some(previous_version)
            {
                errors.push(format!("{context} has a broken supersession chain"));
            }

            let previous_path = format!(
                "provider-registry.implementation.json:/provider_lifecycle/{provider_id}@{config_version}#{previous_version}"
            );
            let current_path = format!(
                "provider-registry.implementation.json:/provider_lifecycle/{provider_id}@{config_version}#{record_version}"
            );
            let previous_effective =
                parse_timestamp_value(previous_record, "effective_at", &previous_path, errors);
            let current_effective =
                parse_timestamp_value(record, "effective_at", &current_path, errors);
            if previous_effective
                .zip(current_effective)
                .is_some_and(|(previous, current)| current <= previous)
            {
                errors.push(format!(
                    "{current_path}: effective_at must strictly increase from lifecycle record {previous_version}"
                ));
            }

            validate_provider_lifecycle_transition(
                string_field(previous_record, "state").unwrap_or(""),
                string_field(record, "state").unwrap_or(""),
                &current_path,
                errors,
            );
        }

        if history
            .last()
            .and_then(|(_, record)| string_field(record, "state"))
            == Some("active")
        {
            active_configurations
                .entry(provider_id.clone())
                .or_default()
                .push(*config_version);
        }
    }
    for (provider_id, versions) in active_configurations {
        if versions.len() > 1 {
            errors.push(format!(
                "provider-registry.implementation.json:/provider_lifecycle: provider {provider_id} has multiple active configuration versions {versions:?}"
            ));
        }
    }

    let configured_ids: BTreeSet<String> = configuration_keys
        .iter()
        .map(|(provider_id, _)| provider_id.clone())
        .collect();
    let mut tombstone_ids = BTreeSet::new();
    for (index, tombstone) in array(registry, "provider_id_tombstones").iter().enumerate() {
        let provider_id = string_field(tombstone, "provider_id").unwrap_or("");
        if !tombstone_ids.insert(provider_id.to_string()) {
            errors.push(format!(
                "provider-registry.implementation.json:/provider_id_tombstones/{index}: duplicate tombstone {provider_id}"
            ));
        }
        if configured_ids.contains(provider_id) {
            errors.push(format!(
                "provider-registry.implementation.json:/provider_id_tombstones/{index}: tombstoned provider_id {provider_id} is still configured"
            ));
        }
    }
}

fn validate_provider_lifecycle_transition(
    previous: &str,
    next: &str,
    path: &str,
    errors: &mut Vec<String>,
) {
    let allowed = matches!(
        (previous, next),
        ("configured", "validated")
            | ("configured", "quarantined")
            | ("validated", "active")
            | ("validated", "quarantined")
            | ("active", "draining")
            | ("active", "quarantined")
            | ("draining", "removed")
            | ("draining", "quarantined")
            | ("quarantined", "removed")
    );
    if !allowed {
        errors.push(format!(
            "{path}: invalid provider lifecycle transition {previous}->{next}"
        ));
    }
}

fn validate_provider_payload_digest(configuration: &Value, path: &str, errors: &mut Vec<String>) {
    let contract = configuration
        .get("payload_digest_contract")
        .unwrap_or(&Value::Null);
    let excluded = array(contract, "excluded_json_pointers");
    let contract_matches = string_field(contract, "algorithm") == Some("sha-256")
        && string_field(contract, "canonicalization") == Some("ryuki-canonical-json-v1")
        && string_field(contract, "digest_encoding") == Some("sha256-prefix-lowercase-hex")
        && excluded.len() == 1
        && excluded[0].as_str() == Some("/payload_digest");
    if !contract_matches {
        errors.push(format!(
            "{path}: payload_digest_contract must use the closed ryuki-canonical-json-v1 SHA-256 contract and exclude only /payload_digest"
        ));
        return;
    }

    let mut payload = configuration.clone();
    if let Some(object) = payload.as_object_mut() {
        object.remove("payload_digest");
    }
    let canonical = canonical_json(&payload);
    let expected = format!("sha256:{:x}", Sha256::digest(canonical.as_bytes()));
    if string_field(configuration, "payload_digest") != Some(expected.as_str()) {
        errors.push(format!(
            "{path}: payload_digest does not match the canonical provider configuration; expected {expected}"
        ));
    }
}

fn validate_action_resource_registry(root: &Path, registry: &Value, errors: &mut Vec<String>) {
    let actors = unique_string_array(
        registry,
        "actor_kinds",
        "action-resource-registry.implementation.json",
        errors,
    );

    let mut resources = BTreeMap::new();
    for (index, resource) in array(registry, "resources").iter().enumerate() {
        let path = format!("action-resource-registry.implementation.json:/resources/{index}");
        let kind = string_field(resource, "resource_kind").unwrap_or("");
        if resources.insert(kind.to_string(), resource).is_some() {
            errors.push(format!("{path}: duplicate resource_kind {kind}"));
        }
    }
    let mut resolvers = BTreeMap::new();
    for (index, resolver) in array(registry, "resolvers").iter().enumerate() {
        let path = format!("action-resource-registry.implementation.json:/resolvers/{index}");
        let id = string_field(resolver, "resolver_id").unwrap_or("");
        if resolvers.insert(id.to_string(), resolver).is_some() {
            errors.push(format!("{path}: duplicate resolver_id {id}"));
        }
        let resource_kind = string_field(resolver, "resource_kind").unwrap_or("");
        if !resources.contains_key(resource_kind) {
            errors.push(format!(
                "{path}: resolver {id} references unknown resource_kind {resource_kind}"
            ));
        }
    }
    for (kind, resource) in &resources {
        let resolver_id = string_field(resource, "resolver_id").unwrap_or("");
        let Some(resolver) = resolvers.get(resolver_id) else {
            errors.push(format!(
                "action-resource-registry.implementation.json: resource {kind} references unknown resolver {resolver_id}"
            ));
            continue;
        };
        if string_field(resolver, "resource_kind") != Some(kind.as_str()) {
            errors.push(format!(
                "action-resource-registry.implementation.json: resource {kind} and resolver {resolver_id} disagree on resource_kind"
            ));
        }
        if resource.get("resolver_version") != resolver.get("resolver_version") {
            errors.push(format!(
                "action-resource-registry.implementation.json: resource {kind} and resolver {resolver_id} disagree on resolver_version"
            ));
        }
    }

    let mut actions = BTreeMap::new();
    for (index, action) in array(registry, "actions").iter().enumerate() {
        let path = format!("action-resource-registry.implementation.json:/actions/{index}");
        let action_id = string_field(action, "action_id").unwrap_or("");
        if actions.insert(action_id.to_string(), action).is_some() {
            errors.push(format!("{path}: duplicate action_id {action_id}"));
        }
        let resource_kind = string_field(action, "resource_kind").unwrap_or("");
        if !resources.contains_key(resource_kind) {
            errors.push(format!(
                "{path}: action {action_id} references unknown resource_kind {resource_kind}"
            ));
        }
        for actor in array(action, "permitted_actor_kinds")
            .iter()
            .filter_map(Value::as_str)
        {
            if !actors.contains(actor) {
                errors.push(format!(
                    "{path}: action {action_id} references unknown actor kind {actor}"
                ));
            }
        }
    }

    let mut mapping_ids = BTreeSet::new();
    for (collection, mapping) in [("route_mappings", "route"), ("worker_mappings", "worker")] {
        for (index, entry) in array(registry, collection).iter().enumerate() {
            let path =
                format!("action-resource-registry.implementation.json:/{collection}/{index}");
            let mapping_id = string_field(entry, "mapping_id").unwrap_or("");
            if !mapping_ids.insert(mapping_id.to_string()) {
                errors.push(format!("{path}: duplicate mapping_id {mapping_id}"));
            }
            let action_id = string_field(entry, "action_id").unwrap_or("");
            let resource_kind = string_field(entry, "resource_kind").unwrap_or("");
            let resolver_id = string_field(entry, "resolver_id").unwrap_or("");
            let Some(action) = actions.get(action_id) else {
                errors.push(format!(
                    "{path}: {mapping} mapping references unknown action {action_id}"
                ));
                continue;
            };
            if string_field(action, "resource_kind") != Some(resource_kind) {
                errors.push(format!(
                    "{path}: mapping resource {resource_kind} disagrees with action {action_id}"
                ));
            }
            let Some(resource) = resources.get(resource_kind) else {
                errors.push(format!(
                    "{path}: {mapping} mapping references unknown resource {resource_kind}"
                ));
                continue;
            };
            if string_field(resource, "resolver_id") != Some(resolver_id) {
                errors.push(format!(
                    "{path}: mapping resolver {resolver_id} disagrees with resource {resource_kind}"
                ));
            }
            if let Some(source) = string_field(entry, "source_file") {
                validate_source_path(root, source, None, &path, errors);
            }
        }
    }

    let closure = registry.get("inventory_closure").unwrap_or(&Value::Null);
    for (index, source) in array(closure, "inventory_sources")
        .iter()
        .filter_map(Value::as_str)
        .enumerate()
    {
        validate_source_path(
            root,
            source,
            None,
            &format!(
                "action-resource-registry.implementation.json:/inventory_closure/inventory_sources/{index}"
            ),
            errors,
        );
    }
}

fn validate_security_limit_profile(root: &Path, profile: &Value, errors: &mut Vec<String>) {
    let mut limit_ids = BTreeSet::new();
    for (index, limit) in array(profile, "limits").iter().enumerate() {
        let path = format!("security-limit-profile.implementation.json:/limits/{index}");
        let limit_id = string_field(limit, "limit_id").unwrap_or("");
        if !limit_ids.insert(limit_id.to_string()) {
            errors.push(format!("{path}: duplicate limit_id {limit_id}"));
        }
        let selected = limit.get("selected_value").and_then(Value::as_f64);
        let hard_bounds = limit.get("hard_bounds").unwrap_or(&Value::Null);
        if let (Some(selected), Some(minimum)) =
            (selected, hard_bounds.get("minimum").and_then(Value::as_f64))
        {
            let inclusive = hard_bounds
                .get("minimum_inclusive")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            if selected < minimum || (!inclusive && selected == minimum) {
                errors.push(format!(
                    "{path}: selected_value {selected} is below the hard minimum {minimum}"
                ));
            }
        }
        if let (Some(selected), Some(maximum)) =
            (selected, hard_bounds.get("maximum").and_then(Value::as_f64))
        {
            let inclusive = hard_bounds
                .get("maximum_inclusive")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            if selected > maximum || (!inclusive && selected == maximum) {
                errors.push(format!(
                    "{path}: selected_value {selected} exceeds the hard maximum {maximum}"
                ));
            }
        }
        if let Some(binding) = limit.get("source_binding") {
            if let Some(source_file) = string_field(binding, "source_file") {
                validate_source_path(
                    root,
                    source_file,
                    string_field(binding, "source_symbol"),
                    &format!("{path}/source_binding"),
                    errors,
                );
            }
        }
    }
}

fn require_array_contains(
    value: &Value,
    field: &str,
    expected: &str,
    path: &str,
    errors: &mut Vec<String>,
) {
    if !array(value, field)
        .iter()
        .any(|item| item.as_str() == Some(expected))
    {
        errors.push(format!("{path}/{field}: missing bound value {expected}"));
    }
}

fn string_set(values: &[Value]) -> BTreeSet<String> {
    values
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

fn unique_string_array(
    value: &Value,
    field: &str,
    path: &str,
    errors: &mut Vec<String>,
) -> BTreeSet<String> {
    let mut result = BTreeSet::new();
    for (index, item) in array(value, field).iter().enumerate() {
        if let Some(item) = item.as_str() {
            if !result.insert(item.to_string()) {
                errors.push(format!("{path}:/{field}/{index}: duplicate value {item}"));
            }
        }
    }
    result
}

fn validate_recursive_content_references(
    root: &Path,
    file_name: &str,
    value: &Value,
    pointer: &str,
    errors: &mut Vec<String>,
) {
    match value {
        Value::Object(object) => {
            if let Some(locator) = object.get("artifact_locator").and_then(Value::as_str) {
                let context = format!("{file_name}:{}", display_json_pointer(pointer));
                validate_content_reference(root, object, locator, &context, errors);
            }
            for (key, child) in object {
                let child_pointer = format!("{pointer}/{}", escape_json_pointer(key));
                validate_recursive_content_references(
                    root,
                    file_name,
                    child,
                    &child_pointer,
                    errors,
                );
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                let child_pointer = format!("{pointer}/{index}");
                validate_recursive_content_references(
                    root,
                    file_name,
                    child,
                    &child_pointer,
                    errors,
                );
            }
        }
        _ => {}
    }
}

fn validate_content_reference(
    root: &Path,
    reference: &Map<String, Value>,
    locator: &str,
    context: &str,
    errors: &mut Vec<String>,
) {
    let Some(target) = safe_repository_path(root, locator, context, errors) else {
        return;
    };
    let bytes = match fs::read(&target) {
        Ok(bytes) => bytes,
        Err(error) => {
            errors.push(format!(
                "{context}: cannot read artifact_locator {locator}: {error}"
            ));
            return;
        }
    };
    let actual_digest = format!("sha256:{:x}", Sha256::digest(&bytes));
    let digest_field = [
        "content_digest",
        "reference_digest",
        "bundle_digest",
        "receipt_digest",
        "ledger_digest",
    ]
    .into_iter()
    .find(|field| reference.contains_key(*field));
    let Some(digest_field) = digest_field else {
        errors.push(format!(
            "{context}: artifact_locator requires a supported content digest field"
        ));
        return;
    };
    if reference.get(digest_field).and_then(Value::as_str) != Some(actual_digest.as_str()) {
        errors.push(format!(
            "{context}: {digest_field} does not match {locator}; expected {actual_digest}"
        ));
    }

    if target.extension().and_then(|extension| extension.to_str()) == Some("json") {
        if let Ok(document) = serde_json::from_slice::<Value>(&bytes) {
            for key in [
                "document_id",
                "document_version",
                "bundle_id",
                "receipt_id",
                "ledger_id",
            ] {
                if reference.get(key).is_some()
                    && document.get(key).is_some()
                    && reference.get(key) != document.get(key)
                {
                    errors.push(format!(
                        "{context}: {key} does not match artifact_locator {locator}"
                    ));
                }
            }
            if let (Some(reference_kind), Some(document_kind)) = (
                reference.get("artifact_kind"),
                document.get("contract_kind"),
            ) {
                if reference_kind != document_kind {
                    errors.push(format!(
                        "{context}: artifact_kind does not match artifact_locator {locator}"
                    ));
                }
            }
        }
    }
}

fn validate_source_path(
    root: &Path,
    source: &str,
    symbol: Option<&str>,
    context: &str,
    errors: &mut Vec<String>,
) {
    let Some(path) = safe_repository_path(root, source, context, errors) else {
        return;
    };
    if let Some(symbol) = symbol {
        match fs::read_to_string(&path) {
            Ok(contents) if contents.contains(symbol) => {}
            Ok(_) => errors.push(format!(
                "{context}: source_symbol {symbol} is absent from {source}"
            )),
            Err(error) => errors.push(format!(
                "{context}: cannot read source_file {source}: {error}"
            )),
        }
    }
}

fn safe_repository_path(
    root: &Path,
    locator: &str,
    context: &str,
    errors: &mut Vec<String>,
) -> Option<PathBuf> {
    let relative = Path::new(locator);
    if locator.is_empty()
        || locator.contains('\\')
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        errors.push(format!(
            "{context}: repository locator must be a normalized relative path: {locator:?}"
        ));
        return None;
    }
    let joined = root.join(relative);
    let metadata = match fs::symlink_metadata(&joined) {
        Ok(metadata) => metadata,
        Err(error) => {
            errors.push(format!(
                "{context}: repository locator does not resolve to a file {locator}: {error}"
            ));
            return None;
        }
    };
    if !metadata.file_type().is_file() {
        errors.push(format!(
            "{context}: repository locator is not a regular file: {locator}"
        ));
        return None;
    }
    let canonical_root = match fs::canonicalize(root) {
        Ok(path) => path,
        Err(error) => {
            errors.push(format!(
                "{context}: cannot canonicalize repository root: {error}"
            ));
            return None;
        }
    };
    let canonical_target = match fs::canonicalize(&joined) {
        Ok(path) => path,
        Err(error) => {
            errors.push(format!("{context}: cannot canonicalize {locator}: {error}"));
            return None;
        }
    };
    if !canonical_target.starts_with(&canonical_root) {
        errors.push(format!(
            "{context}: repository locator escapes the repository: {locator}"
        ));
        return None;
    }
    Some(joined)
}

fn escape_json_pointer(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn validate_implementation_only_honesty(
    instances: &BTreeMap<&str, Value>,
    bundles: &[LoadedDocument],
    receipts: &[LoadedDocument],
    errors: &mut Vec<String>,
) {
    if let Some(ledger) = instances.get("control-trace.implementation.json") {
        require_exact_string(
            ledger,
            "acceptance_status",
            "implementation_only",
            "control-trace.implementation.json",
            errors,
        );
        require_exact_bool(
            ledger,
            "production_accepted",
            false,
            "control-trace.implementation.json",
            errors,
        );
    }
    if let Some(deployment) = instances.get("deployment-security-profile.implementation.json") {
        let lifecycle = deployment.get("lifecycle").unwrap_or(&Value::Null);
        require_exact_string(
            lifecycle,
            "state",
            "implementation_only",
            "deployment-security-profile.implementation.json:/lifecycle",
            errors,
        );
        if string_field(deployment, "security_profile") == Some("production") {
            errors.push(
                "deployment-security-profile.implementation.json: repository fixture cannot claim the production profile without accepted operator receipts".to_string(),
            );
        }
    }
    for file_name in [
        "action-resource-registry.implementation.json",
        "provider-registry.implementation.json",
        "security-limit-profile.implementation.json",
    ] {
        let Some(document) = instances.get(file_name) else {
            continue;
        };
        let lifecycle = document.get("lifecycle").unwrap_or(&Value::Null);
        require_exact_string(
            lifecycle,
            "state",
            "implementation_only",
            &format!("{file_name}:/lifecycle"),
            errors,
        );
        if document.get("production_accepted").and_then(Value::as_bool) == Some(true) {
            errors.push(format!(
                "{file_name}: implementation-only document cannot claim production acceptance"
            ));
        }
        if document.get("accepted_receipt_id").is_some() {
            errors.push(format!(
                "{file_name}: implementation-only document cannot cite an accepted receipt"
            ));
        }
    }
    if let Some(registry) = instances.get("conformance-trust-root-registry.implementation.json") {
        require_exact_string(
            registry,
            "acceptance_status",
            "implementation_only",
            "conformance-trust-root-registry.implementation.json",
            errors,
        );
        require_exact_bool(
            registry,
            "production_accepted",
            false,
            "conformance-trust-root-registry.implementation.json",
            errors,
        );
        require_exact_string(
            registry.get("lifecycle").unwrap_or(&Value::Null),
            "state",
            "implementation_only",
            "conformance-trust-root-registry.implementation.json:/lifecycle",
            errors,
        );
        for (index, key) in array(registry, "keys").iter().enumerate() {
            if matches!(string_field(key, "lifecycle"), Some("active" | "overlap")) {
                errors.push(format!(
                    "conformance-trust-root-registry.implementation.json:/keys/{index}: repository implementation fixture cannot carry active signing authority"
                ));
            }
        }
    }
    for document in bundles {
        require_exact_string(
            &document.value,
            "acceptance_status",
            "implementation_only",
            &document.label,
            errors,
        );
        require_exact_bool(
            &document.value,
            "production_accepted",
            false,
            &document.label,
            errors,
        );
    }
    for document in receipts {
        require_exact_string(
            &document.value,
            "acceptance_status",
            "implementation_only",
            &document.label,
            errors,
        );
        require_exact_bool(
            &document.value,
            "production_accepted",
            false,
            &document.label,
            errors,
        );
    }
}

fn require_exact_string(
    value: &Value,
    field: &str,
    expected: &str,
    path: &str,
    errors: &mut Vec<String>,
) {
    if string_field(value, field) != Some(expected) {
        errors.push(format!("{path}: {field} must be {expected}"));
    }
}

fn require_exact_bool(
    value: &Value,
    field: &str,
    expected: bool,
    path: &str,
    errors: &mut Vec<String>,
) {
    if value.get(field).and_then(Value::as_bool) != Some(expected) {
        errors.push(format!("{path}: {field} must be {expected}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ryuki_core::conformance_applicability::{
        recompute_applicability_instance_id, recompute_applicability_inventory_binding,
        ApplicabilityControlTraceBinding, ApplicabilityInstance, ApplicabilityScope,
        ApplicabilitySubject,
    };
    use serde_json::json;

    fn root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn load(relative: &str) -> Value {
        serde_json::from_slice(&fs::read(root().join(relative)).expect("read fixture"))
            .expect("parse fixture")
    }

    fn refresh_provider_payload_digest(configuration: &mut Value) {
        let mut payload = configuration.clone();
        payload
            .as_object_mut()
            .expect("provider configuration object")
            .remove("payload_digest");
        configuration["payload_digest"] = json!(format!(
            "sha256:{:x}",
            Sha256::digest(canonical_json(&payload).as_bytes())
        ));
    }

    fn provider_lifecycle_record(
        genesis: &Value,
        config_version: u64,
        lifecycle_record_version: u64,
        state: &str,
        effective_at: &str,
        supersedes: Option<u64>,
    ) -> Value {
        let mut record = genesis.clone();
        record["config_version"] = json!(config_version);
        record["lifecycle_record_version"] = json!(lifecycle_record_version);
        record["state"] = json!(state);
        record["effective_at"] = json!(effective_at);
        if let Some(supersedes) = supersedes {
            record["supersedes_lifecycle_record_version"] = json!(supersedes);
            record["transition_receipt_ref"] = json!({
                "document_id": format!(
                    "provider-transition:{}-{config_version}-{lifecycle_record_version}",
                    string_field(genesis, "provider_id").unwrap_or("provider:unknown")
                ),
                "document_version": 1,
                "content_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "artifact_locator": format!(
                    "catalog/security-contracts/v1/provider-transitions/{config_version}-{lifecycle_record_version}.json"
                )
            });
        } else if let Some(object) = record.as_object_mut() {
            object.remove("supersedes_lifecycle_record_version");
            object.remove("transition_receipt_ref");
        }
        record
    }

    fn ledger() -> Value {
        load("catalog/security-contracts/v1/control-trace.implementation.json")
    }

    fn runtime_guard_expected_value(index: usize, deployment_id: &str) -> Value {
        let digest = |character: char| format!("sha256:{}", character.to_string().repeat(64));
        let provider = |provider_id: &str| {
            json!({
                "provider_id": provider_id,
                "configuration_version": 1,
                "configuration_payload_digest": digest('1'),
                "lifecycle_record_version": 1,
                "lifecycle_state": "active",
                "capability_descriptor_id": "capability-descriptor:validator-fixture",
                "capability_descriptor_version": 1,
                "adapter_kind": "fixture.provider",
                "adapter_version": "1.0.0"
            })
        };
        match index {
            0 => json!({
                "kind": "durable-postgresql",
                "database_provider": "cloudnativepg",
                "server_major_version": 18,
                "database_identity_digest": digest('2'),
                "storage_binding_digest": digest('3'),
                "migration_inventory_digest": digest('4'),
                "application_role": "ryuki_application",
                "migration_role": "ryuki_migrator"
            }),
            1 => json!({
                "kind": "approved-secret-provider",
                "providers": [provider("provider:validator-secrets")],
                "required_capability_ids": ["secret-read", "secret-renew"]
            }),
            2 => json!({
                "kind": "https-public-urls",
                "public_origin_set_digest": digest('5'),
                "ingress_binding_digest": digest('6'),
                "attestation_profile_id": "ingress-attestation-profile:validator",
                "attestation_profile_version": 1,
                "attestation_profile_digest": digest('7')
            }),
            3 => json!({
                "kind": "secure-cookies",
                "policies": [{
                    "policy_id": "cookie-policy:api-session",
                    "cookie_name": "__Host-ryuki_session",
                    "secure": true,
                    "http_only": true,
                    "path": "/",
                    "domain": null,
                    "same_site": "lax",
                    "policy_digest": digest('8')
                }],
                "policy_inventory_digest": digest('9')
            }),
            4 => json!({
                "kind": "non-development-authenticator",
                "authenticator_inventory_digest": "sha256:34f00f95d64f1aacf021b9e89eb642b3d0ff04f611592ff00097866c51f7fd7f",
                "authenticators": [{
                    "provider": provider("provider:validator-oidc"),
                    "authenticator_kind": "oidc",
                    "runtime_binding_digest": digest('a')
                }]
            }),
            5 => json!({
                "kind": "external-signing-key-material",
                "signing_inventory_digest": digest('b'),
                "purposes": [{
                    "purpose_id": "signing-purpose:control-plane-grants",
                    "algorithm": "ed25519",
                    "custody_kind": "kms",
                    "key_identity_digest": digest('c')
                }, {
                    "purpose_id": "signing-purpose:session-credentials",
                    "algorithm": "hmac-sha256",
                    "custody_kind": "hsm",
                    "key_identity_digest": digest('d')
                }]
            }),
            6 => json!({
                "kind": "mock-dependencies-disabled",
                "dependency_inventory_digest": digest('e'),
                "required_component_ids": [
                    "runtime-component:database",
                    "runtime-component:secret-provider"
                ]
            }),
            7 => json!({
                "kind": "first-owner-path-closed",
                "deployment_id": deployment_id,
                "state_contract_version": 1,
                "authority_namespace_digest": digest('f'),
                "closure_record_digest": digest('1')
            }),
            _ => unreachable!("there are exactly eight runtime guards"),
        }
    }

    fn production_deployment_profile_fixture() -> Value {
        let mut profile =
            load("catalog/security-contracts/v1/deployment-security-profile.implementation.json");
        profile["security_profile"] = json!("production");
        profile["applicability"]["security_profiles"] = json!(["production"]);
        profile["production_acceptance_receipt_ref"] = json!({
            "artifact_kind": "package-exit-receipt",
            "document_id": "package-exit-receipt:production-root",
            "document_version": 1,
            "content_digest": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "artifact_locator": "catalog/security-contracts/v1/package-exit-receipts/production-root.json"
        });
        let guard_ids = [
            "durable-postgresql",
            "approved-secret-provider",
            "https-public-urls",
            "secure-cookies",
            "non-development-authenticator",
            "external-signing-key-material",
            "mock-dependencies-disabled",
            "first-owner-path-closed",
        ];
        profile["runtime_guard_evidence"] = json!({
            "mode": "receipt_bound",
            "guards": guard_ids.iter().enumerate().map(|(index, guard_id)| json!({
                "guard_id": guard_id,
                "control_ids": ["SB-OPS-01"],
                "receipt_ref": {
                    "artifact_kind": "package-exit-receipt",
                    "document_id": format!("package-exit-receipt:production-guard-{index}"),
                    "document_version": 1,
                    "content_digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                    "artifact_locator": format!("catalog/security-contracts/v1/package-exit-receipts/production-guard-{index}.json")
                },
                "expected_value": runtime_guard_expected_value(index, "deployment:repository-conformance-fixture")
            })).collect::<Vec<_>>(),
            "runtime_cross_check_required": true
        });
        profile
    }

    fn production_build_manifest_fixture() -> Value {
        let control_trace = ApplicabilityControlTraceBinding {
            document_id: "control-trace:ryuki-security-boundary-v1".into(),
            document_version: 1,
            content_digest:
                "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".into(),
        };
        let mut component_instance = ApplicabilityInstance {
            applicability_instance_id: String::new(),
            trace_id: "TRACE-SB-EXT-01-AC-017".into(),
            owning_work_package: "SB-4".into(),
            scope: ApplicabilityScope::Implementation,
            subject: ApplicabilitySubject::Component {
                component_id: "component:ryuki-api".into(),
                component_version: "1.0.0".into(),
            },
            dimensions: Vec::new(),
        };
        component_instance.applicability_instance_id =
            recompute_applicability_instance_id(&control_trace, &component_instance)
                .expect("component applicability identity");
        let mut adapter_instance = ApplicabilityInstance {
            applicability_instance_id: String::new(),
            trace_id: "TRACE-SB-EXT-01-AC-017".into(),
            owning_work_package: "SB-4".into(),
            scope: ApplicabilityScope::Implementation,
            subject: ApplicabilitySubject::AdapterCapability {
                adapter_kind: "mock-adapter".into(),
                adapter_version: "1.0.0".into(),
                capability_id: "resource-read".into(),
            },
            dimensions: Vec::new(),
        };
        adapter_instance.applicability_instance_id =
            recompute_applicability_instance_id(&control_trace, &adapter_instance)
                .expect("adapter applicability identity");
        let instances = vec![component_instance, adapter_instance];
        let inventory = recompute_applicability_inventory_binding(&control_trace, &instances)
            .expect("implementation applicability inventory");

        json!({
            "$schema": "https://ryuki.io/schemas/security-contracts/v1/production-build-manifest.schema.json",
            "schema_version": "2.0.0",
            "contract_kind": "production-build-manifest",
            "document_id": "production-build-manifest:ryuki-api-linux-amd64",
            "document_version": 1,
            "component": {
                "component_id": "component:ryuki-api",
                "component_version": "1.0.0",
                "executable_name": "ryuki-api",
                "target": {
                    "architecture": "x86_64",
                    "operating_system": "linux",
                    "family": "unix",
                    "pointer_width_bits": 64,
                    "endian": "little"
                }
            },
            "source": {
                "revision_algorithm": "git_sha1",
                "revision": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            },
            "runtime_executable": {
                "content_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "byte_length": 1234567
            },
            "oci_subject": {
                "subject_kind": "oci_image_manifest",
                "repository": "ghcr.io/ryuki-platform/ryuki-api",
                "content_digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            },
            "control_trace_ref": {
                "artifact_kind": "control-trace",
                "document_id": "control-trace:ryuki-security-boundary-v1",
                "document_version": 1,
                "content_digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                "artifact_locator": "catalog/security-contracts/v1/control-trace.implementation.json"
            },
            "shipped_adapters": [{
                "adapter_kind": "mock-adapter",
                "adapter_version": "1.0.0",
                "production_eligible": false,
                "capability_ids": ["resource-read"],
                "mandatory_baseline": {
                    "document_id": "baseline:mock-adapter",
                    "document_version": 1,
                    "content_digest": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                    "artifact_locator": "catalog/security-contracts/v1/adapter-baselines/mock-adapter.json",
                    "required_trace_ids": ["TRACE-SB-EXT-01-AC-017"]
                }
            }],
            "selector_dispositions": [{
                "selector_domain": "integration_adapter",
                "selector": "mock-adapter",
                "disposition": "implemented",
                "adapter_kind": "mock-adapter"
            }],
            "implementation_applicability": inventory,
            "implementation_applicability_instances": instances
        })
    }

    fn add_production_migration_overlay(profile: &mut Value) {
        profile["migration_overlay"] = json!({
            "overlay_id": "migration-overlay:production-test",
            "overlay_version": 1,
            "security_profile": "production",
            "authority_source": "legacy_auth_mode",
            "legacy_selector_present": true,
            "provider_registry_present": true,
            "retirement_deadline": "2026-08-01T00:00:00Z",
            "conflict_telemetry_name": "security.migration.conflict",
            "grants_authority": false,
            "live_execution_allowed": false,
            "zero_consumer_receipt_ref": {
                "artifact_kind": "package-exit-receipt",
                "document_id": "package-exit-receipt:zero-consumer",
                "document_version": 1,
                "content_digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "artifact_locator": "catalog/security-contracts/v1/package-exit-receipts/zero-consumer.json"
            }
        });
    }

    fn semantic_errors(ledger: &Value) -> Vec<String> {
        let mut errors = Vec::new();
        validate_ledger_semantics(ledger, &mut errors);
        errors.sort();
        errors
    }

    fn trust_checkpoint_envelope_fixture() -> Value {
        json!({
            "schema_version": "2.0.0",
            "contract_kind": "conformance-trust-reconciliation-response",
            "canonicalization": "ryuki-canonical-json-v1",
            "signature_algorithm": "ed25519",
            "authority": {
                "authority_id": "conformance-trust-checkpoint-authority:test",
                "key_id": "conformance-trust-checkpoint-key:test-primary",
                "public_key_fingerprint": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            },
            "request_nonce": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
            "request_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "namespace": {
                "deployment_id": "deployment:test",
                "trust_domain_id": "trust-domain:test",
                "registry_id": "conformance-trust-root-registry:test"
            },
            "candidate_head": {
                "registry_version": 2,
                "content_digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "artifact_locator": "catalog/security-contracts/v1/trust-registry-v2.json"
            },
            "current_head": {
                "registry_version": 2,
                "content_digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "artifact_locator": "catalog/security-contracts/v1/trust-registry-v2.json"
            },
            "candidate_production_root": {
                "artifact_kind": "package-exit-receipt",
                "document_id": "package-exit-receipt:sb-9-production-root",
                "document_version": 3,
                "content_digest": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                "artifact_locator": "catalog/security-contracts/v1/package-exit-receipts/sb-9-production-root.json"
            },
            "current_production_root": {
                "receipt_ref": {
                    "artifact_kind": "package-exit-receipt",
                    "document_id": "package-exit-receipt:sb-9-production-root",
                    "document_version": 3,
                    "content_digest": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                    "artifact_locator": "catalog/security-contracts/v1/package-exit-receipts/sb-9-production-root.json"
                },
                "acceptance_record_id": "conformance-acceptance:sb-9-production-root"
            },
            "validated_lineage_digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "state": "external_strongly_consistent",
            "outcome": "matched",
            "reconciliation": {
                "candidate_matches_current": true,
                "candidate_production_root_matches_current": true,
                "restored_state_reconciled": true,
                "no_auto_advance": true
            },
            "checkpoint": {
                "sequence": 12,
                "authority_epoch": 3,
                "authority_revision": 7,
                "observed_at": {
                    "not_before": "2026-07-17T09:00:00Z",
                    "not_after": "2026-07-17T09:00:01Z"
                },
                "valid_until": "2026-07-17T09:05:00Z"
            },
            "acceptance_records": [{
                "acceptance_record_id": "conformance-acceptance:sb-9-production-root",
                "document": {
                    "contract_kind": "package-exit-receipt",
                    "document_id": "package-exit-receipt:sb-9-production-root",
                    "document_version": 3,
                    "complete_document_digest": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                    "signature_digest": "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                    "signed_subject_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                },
                "signer": {
                    "key_id": "conformance-key:test-primary",
                    "public_key_fingerprint": "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                },
                "registry": {
                    "registry_id": "conformance-trust-root-registry:test",
                    "registry_version": 2,
                    "registry_digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                    "artifact_locator": "catalog/security-contracts/v1/trust-registry-v2.json",
                    "head_sequence": 9,
                    "head_authority_revision": 7
                },
                "deployment_id": "deployment:test",
                "trust_domain_id": "trust-domain:test",
                "work_package_id": "SB-9",
                "purpose": "package_exit_receipt",
                "evidence_tier": "operator_environment",
                "authority_sequence": 11,
                "authority_epoch": 3,
                "accepted_at": {
                    "not_before": "2026-07-17T08:59:58Z",
                    "not_after": "2026-07-17T08:59:59Z"
                },
                "lifecycle": "accepted"
            }],
            "signature_base64": format!("{}==", "A".repeat(86))
        })
    }

    #[test]
    fn repository_security_contracts_pass_the_real_gate() {
        let errors = validate_repository(&root()).expect("repository validation should run");
        assert!(errors.is_empty(), "{}", errors.join("\n"));
    }

    #[test]
    fn production_build_manifest_schema_accepts_complete_closed_instance() {
        let schema = load("catalog/security-contracts/v1/production-build-manifest.schema.json");
        let manifest = production_build_manifest_fixture();
        let mut errors = Vec::new();

        validate_instance(
            "test:production-build-manifest",
            "production-build-manifest.schema.json",
            &schema,
            &manifest,
            &mut errors,
        );
        validate_production_build_manifest_semantics(
            "test:production-build-manifest",
            &manifest,
            &mut errors,
        );

        assert!(errors.is_empty(), "{}", errors.join("\n"));
    }

    #[test]
    fn production_build_manifest_schema_rejects_unknown_fields_and_invalid_identity() {
        let schema = load("catalog/security-contracts/v1/production-build-manifest.schema.json");
        let fixture = production_build_manifest_fixture();

        let mut unknown_field = fixture.clone();
        unknown_field["runtime_executable"]["self_attested"] = json!(true);
        let mut errors = Vec::new();
        validate_instance(
            "test:production-build-manifest-unknown-field",
            "production-build-manifest.schema.json",
            &schema,
            &unknown_field,
            &mut errors,
        );
        assert!(
            errors.iter().any(|error| {
                error.contains("at /runtime_executable") && error.contains("additionalProperties")
            }),
            "missing closed-object error: {}",
            errors.join("\n")
        );

        let mut zero_digest = fixture.clone();
        zero_digest["runtime_executable"]["content_digest"] = json!(ZERO_SHA256_DIGEST);
        errors.clear();
        validate_instance(
            "test:production-build-manifest-zero-digest",
            "production-build-manifest.schema.json",
            &schema,
            &zero_digest,
            &mut errors,
        );
        assert!(
            errors
                .iter()
                .any(|error| { error.contains("at /runtime_executable/content_digest") }),
            "missing nonzero digest error: {}",
            errors.join("\n")
        );

        let mut bad_revision = fixture;
        bad_revision["source"]["revision"] = json!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        errors.clear();
        validate_instance(
            "test:production-build-manifest-bad-revision",
            "production-build-manifest.schema.json",
            &schema,
            &bad_revision,
            &mut errors,
        );
        validate_production_build_manifest_semantics(
            "test:production-build-manifest-bad-revision",
            &bad_revision,
            &mut errors,
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains("source revision does not match revision_algorithm")),
            "missing revision binding error: {}",
            errors.join("\n")
        );
    }

    #[test]
    fn production_build_manifest_rejects_duplicate_and_unsorted_inventory() {
        let schema = load("catalog/security-contracts/v1/production-build-manifest.schema.json");
        let fixture = production_build_manifest_fixture();

        let mut duplicate = fixture.clone();
        duplicate["shipped_adapters"][0]["capability_ids"] =
            json!(["resource-read", "resource-read"]);
        let mut errors = Vec::new();
        validate_instance(
            "test:production-build-manifest-duplicate-inventory",
            "production-build-manifest.schema.json",
            &schema,
            &duplicate,
            &mut errors,
        );
        validate_production_build_manifest_semantics(
            "test:production-build-manifest-duplicate-inventory",
            &duplicate,
            &mut errors,
        );
        assert!(
            errors.iter().any(|error| {
                (error.contains("/shipped_adapters/0/capability_ids")
                    && error.contains("uniqueItems"))
                    || error.contains(
                        "shipped adapter mock-adapter capability_ids must be nonempty, unique, sorted, and bounded",
                    )
            }),
            "missing duplicate inventory error: {}",
            errors.join("\n")
        );

        let mut unsorted = fixture;
        unsorted["shipped_adapters"][0]["capability_ids"] =
            json!(["resource-write", "resource-read"]);
        errors.clear();
        validate_production_build_manifest_semantics(
            "test:production-build-manifest-unsorted-inventory",
            &unsorted,
            &mut errors,
        );
        assert!(
            errors.iter().any(|error| error.contains(
                "shipped adapter mock-adapter capability_ids must be nonempty, unique, sorted, and bounded"
            )),
            "missing canonical-order error: {}",
            errors.join("\n")
        );
    }

    #[test]
    fn production_build_manifest_rejects_cross_field_inventory_gaps() {
        let fixture = production_build_manifest_fixture();

        let mut missing_component = fixture.clone();
        missing_component["implementation_applicability_instances"]
            .as_array_mut()
            .expect("implementation applicability inventory")
            .remove(0);
        let mut errors = Vec::new();
        validate_production_build_manifest_semantics(
            "test:production-build-manifest-missing-component",
            &missing_component,
            &mut errors,
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains("omit the exact component subject")),
            "missing component closure error: {}",
            errors.join("\n")
        );

        let mut unshipped_selector = fixture.clone();
        unshipped_selector["selector_dispositions"][0]["adapter_kind"] = json!("catalog-adapter");
        errors.clear();
        validate_production_build_manifest_semantics(
            "test:production-build-manifest-unshipped-selector",
            &unshipped_selector,
            &mut errors,
        );
        assert!(
            errors.iter().any(|error| {
                error.contains("implemented selector")
                    && error.contains("references unshipped adapter")
            }),
            "missing selector closure error: {}",
            errors.join("\n")
        );

        let mut unknown_subject = fixture.clone();
        unknown_subject["implementation_applicability_instances"][1]["subject"]["capability_id"] =
            json!("resource-delete");
        errors.clear();
        validate_production_build_manifest_semantics(
            "test:production-build-manifest-unknown-subject",
            &unknown_subject,
            &mut errors,
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains("references unknown capability")),
            "missing subject closure error: {}",
            errors.join("\n")
        );

        let mut missing_baseline_trace = fixture;
        missing_baseline_trace["shipped_adapters"][0]["mandatory_baseline"]["required_trace_ids"] =
            json!(["TRACE-SB-EXT-02-AC-017"]);
        errors.clear();
        validate_production_build_manifest_semantics(
            "test:production-build-manifest-missing-baseline-trace",
            &missing_baseline_trace,
            &mut errors,
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains("omits mandatory baseline trace")),
            "missing baseline closure error: {}",
            errors.join("\n")
        );
    }

    #[test]
    fn production_build_manifest_rejects_stale_applicability_binding_after_row_changes() {
        let fixture = production_build_manifest_fixture();

        let mut omitted = fixture.clone();
        omitted["implementation_applicability_instances"]
            .as_array_mut()
            .expect("implementation applicability inventory")
            .pop();
        let mut errors = Vec::new();
        validate_production_build_manifest_semantics(
            "test:production-build-manifest-omitted-row",
            &omitted,
            &mut errors,
        );
        assert!(
            errors.iter().any(|error| error.contains(
                "implementation_applicability binding does not exactly match its instances"
            )),
            "missing omission binding error: {}",
            errors.join("\n")
        );

        let mut added = fixture.clone();
        let control_trace = ApplicabilityControlTraceBinding {
            document_id: "control-trace:ryuki-security-boundary-v1".into(),
            document_version: 1,
            content_digest:
                "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".into(),
        };
        let mut extra: ApplicabilityInstance =
            serde_json::from_value(added["implementation_applicability_instances"][0].clone())
                .expect("decode canonical applicability row");
        extra.trace_id = "TRACE-SB-EXT-02-AC-017".into();
        extra.applicability_instance_id =
            recompute_applicability_instance_id(&control_trace, &extra)
                .expect("extra applicability identity");
        added["implementation_applicability_instances"]
            .as_array_mut()
            .expect("implementation applicability inventory")
            .push(serde_json::to_value(extra).expect("encode extra applicability row"));
        errors.clear();
        validate_production_build_manifest_semantics(
            "test:production-build-manifest-added-row",
            &added,
            &mut errors,
        );
        assert!(
            errors.iter().any(|error| error.contains(
                "implementation_applicability binding does not exactly match its instances"
            )),
            "missing addition binding error: {}",
            errors.join("\n")
        );

        let mut mutated = fixture;
        mutated["implementation_applicability_instances"][1]["subject"]["capability_id"] =
            json!("resource-write");
        errors.clear();
        validate_production_build_manifest_semantics(
            "test:production-build-manifest-mutated-row",
            &mutated,
            &mut errors,
        );
        assert!(
            errors.iter().any(|error| {
                error.contains("applicability_instance_id does not match the canonical identity")
                    || error.contains(
                        "implementation_applicability binding does not exactly match its instances",
                    )
            }),
            "missing mutation identity error: {}",
            errors.join("\n")
        );
    }

    #[test]
    fn trust_checkpoint_envelope_schema_accepts_exact_closed_response() {
        let schema =
            load("catalog/security-contracts/v1/conformance-trust-checkpoint-envelope.schema.json");
        let mut errors = Vec::new();

        validate_instance(
            "test:trust-checkpoint-envelope",
            "conformance-trust-checkpoint-envelope.schema.json",
            &schema,
            &trust_checkpoint_envelope_fixture(),
            &mut errors,
        );

        assert!(errors.is_empty(), "{}", errors.join("\n"));
    }

    #[test]
    fn trust_checkpoint_production_root_schema_rejects_incomplete_or_unsafe_bindings() {
        let schema =
            load("catalog/security-contracts/v1/conformance-trust-checkpoint-envelope.schema.json");
        let fixture = trust_checkpoint_envelope_fixture();
        let mut cases = Vec::new();

        let mut old_wire_version = fixture.clone();
        old_wire_version["schema_version"] = json!("1.0.0");
        cases.push(("rootless v1 wire version", old_wire_version));

        for top_level in ["candidate_production_root", "current_production_root"] {
            let mut missing = fixture.clone();
            missing
                .as_object_mut()
                .expect("checkpoint fixture object")
                .remove(top_level);
            cases.push(("missing mandatory production root", missing));
        }

        for field in [
            "artifact_kind",
            "document_id",
            "document_version",
            "content_digest",
            "artifact_locator",
        ] {
            let mut incomplete = fixture.clone();
            incomplete["candidate_production_root"]
                .as_object_mut()
                .expect("candidate production root")
                .remove(field);
            cases.push(("incomplete five-field candidate root", incomplete));
        }

        let mut unknown_candidate_field = fixture.clone();
        unknown_candidate_field["candidate_production_root"]["authority_hint"] =
            json!("self-declared");
        cases.push(("unknown candidate root field", unknown_candidate_field));

        let mut wrong_kind = fixture.clone();
        wrong_kind["candidate_production_root"]["artifact_kind"] = json!("conformance-bundle");
        cases.push(("wrong candidate root kind", wrong_kind));

        let mut wrong_identity = fixture.clone();
        wrong_identity["candidate_production_root"]["document_id"] = json!("bundle:not-sb-9");
        cases.push(("wrong candidate root identity", wrong_identity));

        let mut zero_digest = fixture.clone();
        zero_digest["candidate_production_root"]["content_digest"] =
            json!("sha256:0000000000000000000000000000000000000000000000000000000000000000");
        cases.push(("zero candidate root digest", zero_digest));

        let mut unsafe_locator = fixture.clone();
        unsafe_locator["candidate_production_root"]["artifact_locator"] =
            json!("../sb-9-production-root.json");
        cases.push(("unsafe candidate root locator", unsafe_locator));

        let mut unknown_current_field = fixture.clone();
        unknown_current_field["current_production_root"]["selection_hint"] = json!(7);
        cases.push(("unknown current root field", unknown_current_field));

        let mut incomplete_current_ref = fixture.clone();
        incomplete_current_ref["current_production_root"]["receipt_ref"]
            .as_object_mut()
            .expect("current production root receipt ref")
            .remove("artifact_locator");
        cases.push((
            "incomplete current root receipt ref",
            incomplete_current_ref,
        ));

        let mut missing_acceptance = fixture.clone();
        missing_acceptance["current_production_root"]
            .as_object_mut()
            .expect("current production root")
            .remove("acceptance_record_id");
        cases.push(("missing current root acceptance event", missing_acceptance));

        let mut invalid_acceptance = fixture.clone();
        invalid_acceptance["current_production_root"]["acceptance_record_id"] =
            json!("package-exit-receipt:not-an-acceptance");
        cases.push(("invalid current root acceptance event", invalid_acceptance));

        let mut empty_acceptance_lookup = fixture.clone();
        empty_acceptance_lookup["acceptance_records"] = json!([]);
        cases.push(("missing SB-9 acceptance record", empty_acceptance_lookup));

        let mut non_root_acceptance = fixture.clone();
        non_root_acceptance["acceptance_records"][0]["work_package_id"] = json!("SB-8");
        cases.push(("non-SB-9 acceptance record", non_root_acceptance));

        let mut missing_reconciliation_flag = fixture.clone();
        missing_reconciliation_flag["reconciliation"]
            .as_object_mut()
            .expect("reconciliation")
            .remove("candidate_production_root_matches_current");
        cases.push((
            "missing production root reconciliation flag",
            missing_reconciliation_flag,
        ));

        let mut false_reconciliation_flag = fixture;
        false_reconciliation_flag["reconciliation"]["candidate_production_root_matches_current"] =
            json!(false);
        cases.push((
            "false production root reconciliation flag",
            false_reconciliation_flag,
        ));

        for (label, candidate) in cases {
            let mut errors = Vec::new();
            validate_instance(
                label,
                "conformance-trust-checkpoint-envelope.schema.json",
                &schema,
                &candidate,
                &mut errors,
            );
            assert!(!errors.is_empty(), "{label} must fail schema validation");
        }
    }

    #[test]
    fn trust_checkpoint_accepted_document_id_enforces_160_byte_limit() {
        let schema =
            load("catalog/security-contracts/v1/conformance-trust-checkpoint-envelope.schema.json");
        let mut at_limit = trust_checkpoint_envelope_fixture();
        at_limit["acceptance_records"][0]["document"]["document_id"] =
            Value::String("a".repeat(160));
        let mut errors = Vec::new();
        validate_instance(
            "test:checkpoint-document-id-at-limit",
            "conformance-trust-checkpoint-envelope.schema.json",
            &schema,
            &at_limit,
            &mut errors,
        );
        assert!(errors.is_empty(), "{}", errors.join("\n"));

        let mut over_limit = at_limit;
        over_limit["acceptance_records"][0]["document"]["document_id"] =
            Value::String("a".repeat(161));
        validate_instance(
            "test:checkpoint-document-id-over-limit",
            "conformance-trust-checkpoint-envelope.schema.json",
            &schema,
            &over_limit,
            &mut errors,
        );
        assert!(errors.iter().any(|error| {
            error.contains("at /acceptance_records/0/document/document_id")
                && error.contains("/maxLength")
        }));
    }

    #[test]
    fn closure_document_versions_enforce_exact_json_integer_limit() {
        for schema_name in [
            "conformance-bundle.schema.json",
            "package-exit-receipt.schema.json",
        ] {
            let schema = load(&format!("catalog/security-contracts/v1/{schema_name}"));
            let version_schema = schema
                .pointer("/properties/document_version")
                .expect("top-level document_version schema");
            let mut errors = Vec::new();
            validate_instance(
                "test:document-version-at-limit",
                schema_name,
                version_schema,
                &json!(9_007_199_254_740_991_u64),
                &mut errors,
            );
            assert!(errors.is_empty(), "{schema_name}: {}", errors.join("\n"));

            validate_instance(
                "test:document-version-over-limit",
                schema_name,
                version_schema,
                &json!(9_007_199_254_740_992_u64),
                &mut errors,
            );
            assert!(
                errors.iter().any(|error| error.contains("via /maximum")),
                "{schema_name}: {}",
                errors.join("\n")
            );
        }
    }

    #[test]
    fn trust_checkpoint_envelope_schema_rejects_ambiguous_or_unbounded_input() {
        let schema =
            load("catalog/security-contracts/v1/conformance-trust-checkpoint-envelope.schema.json");
        let fixture = trust_checkpoint_envelope_fixture();
        let mut cases = Vec::new();

        let mut unknown_root = fixture.clone();
        unknown_root["public_key_base64"] = json!("self-declared-key");
        cases.push(("unknown root field", unknown_root));

        let mut unknown_nested = fixture.clone();
        unknown_nested["acceptance_records"][0]["document"]["untrusted_status"] = json!("accepted");
        cases.push(("unknown nested field", unknown_nested));

        let mut bad_namespace = fixture.clone();
        bad_namespace["namespace"]["deployment_id"] = json!("test");
        cases.push(("non-canonical namespace", bad_namespace));

        let mut traversal = fixture.clone();
        traversal["current_head"]["artifact_locator"] = json!("../registry.json");
        cases.push(("unsafe head locator", traversal));

        let mut generic_outcome = fixture.clone();
        generic_outcome["outcome"] = json!("ok");
        cases.push(("generic outcome", generic_outcome));

        let mut oversized_counter = fixture.clone();
        oversized_counter["checkpoint"]["sequence"] = json!(9_007_199_254_740_992_u64);
        cases.push((
            "counter above canonical JSON exact-integer range",
            oversized_counter,
        ));

        let mut zero_digest = fixture.clone();
        zero_digest["request_digest"] =
            json!("sha256:0000000000000000000000000000000000000000000000000000000000000000");
        cases.push(("zero request digest", zero_digest));

        let mut invalid_signature = fixture.clone();
        invalid_signature["signature_base64"] = json!("not-base64");
        cases.push(("invalid signature encoding", invalid_signature));

        let mut nonce_pad_bits = fixture.clone();
        nonce_pad_bits["request_nonce"] = json!(format!("{}B=", "A".repeat(42)));
        cases.push(("non-canonical nonce pad bits", nonce_pad_bits));

        let mut signature_pad_bits = fixture.clone();
        signature_pad_bits["signature_base64"] = json!(format!("{}B==", "A".repeat(85)));
        cases.push(("non-canonical signature pad bits", signature_pad_bits));

        let mut zero_nonce = fixture.clone();
        zero_nonce["request_nonce"] = json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        cases.push(("all-zero request nonce", zero_nonce));

        let template = fixture["acceptance_records"][0].clone();
        let mut bounded_acceptances = fixture.clone();
        bounded_acceptances["acceptance_records"] = Value::Array(
            (0..4096)
                .map(|index| {
                    let mut record = template.clone();
                    record["acceptance_record_id"] =
                        json!(format!("conformance-acceptance:test-{index:04}"));
                    record
                })
                .collect(),
        );
        let mut bounded_errors = Vec::new();
        validate_instance(
            "test:bounded-complete-acceptance-lookup",
            "conformance-trust-checkpoint-envelope.schema.json",
            &schema,
            &bounded_acceptances,
            &mut bounded_errors,
        );
        assert!(bounded_errors.is_empty(), "{}", bounded_errors.join("\n"));

        let mut oversized_acceptances = fixture.clone();
        oversized_acceptances["acceptance_records"] = Value::Array(
            (0..4097)
                .map(|index| {
                    let mut record = template.clone();
                    record["acceptance_record_id"] =
                        json!(format!("conformance-acceptance:oversized-{index:04}"));
                    record
                })
                .collect(),
        );
        let mut oversized_errors = Vec::new();
        validate_instance(
            "test:oversized-otherwise-valid-acceptance-lookup",
            "conformance-trust-checkpoint-envelope.schema.json",
            &schema,
            &oversized_acceptances,
            &mut oversized_errors,
        );
        assert!(
            oversized_errors.iter().any(|error| {
                error.contains("at /acceptance_records")
                    && error.contains("/properties/acceptance_records/maxItems")
            }),
            "missing maxItems error: {}",
            oversized_errors.join("\n")
        );
        assert_eq!(oversized_errors.len(), 1, "{}", oversized_errors.join("\n"));

        let mut missing_nonce = fixture.clone();
        missing_nonce
            .as_object_mut()
            .expect("checkpoint fixture object")
            .remove("request_nonce");
        cases.push(("missing request nonce", missing_nonce));

        let mut missing_revision = fixture;
        missing_revision["checkpoint"]
            .as_object_mut()
            .expect("checkpoint object")
            .remove("authority_revision");
        cases.push(("missing authority revision", missing_revision));

        for (label, candidate) in cases {
            let mut errors = Vec::new();
            validate_instance(
                label,
                "conformance-trust-checkpoint-envelope.schema.json",
                &schema,
                &candidate,
                &mut errors,
            );
            assert!(!errors.is_empty(), "{label} must fail schema validation");
        }
    }

    #[test]
    fn deployment_profile_binds_exact_trust_registry_head_digest() {
        let mut deployment =
            load("catalog/security-contracts/v1/deployment-security-profile.implementation.json");
        deployment["conformance_trust_root_registry_ref"]["content_digest"] =
            json!("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        let registry = load(
            "catalog/security-contracts/v1/conformance-trust-root-registry.implementation.json",
        );
        let instances = BTreeMap::from([
            (
                "deployment-security-profile.implementation.json",
                deployment,
            ),
            (
                "conformance-trust-root-registry.implementation.json",
                registry,
            ),
        ]);
        let mut errors = Vec::new();

        validate_cross_document_semantics(&root(), &instances, &mut errors);

        assert!(errors.iter().any(|error| {
            error.contains("conformance_trust_root_registry_ref")
                && error.contains("content_digest does not match the exact raw bytes")
        }));
    }

    #[test]
    fn deployment_profile_requires_root_acceptance_only_for_production() {
        let schema = load("catalog/security-contracts/v1/deployment-security-profile.schema.json");
        let fixture =
            load("catalog/security-contracts/v1/deployment-security-profile.implementation.json");

        let mut production_without_acceptance = production_deployment_profile_fixture();
        let mut errors = Vec::new();
        validate_instance(
            "test:otherwise-valid-production-root",
            "deployment-security-profile.schema.json",
            &schema,
            &production_without_acceptance,
            &mut errors,
        );
        assert!(errors.is_empty(), "{}", errors.join("\n"));

        production_without_acceptance["production_acceptance_receipt_ref"] = Value::Null;
        validate_instance(
            "test:production-without-root-acceptance",
            "deployment-security-profile.schema.json",
            &schema,
            &production_without_acceptance,
            &mut errors,
        );
        assert!(
            errors.iter().any(|error| {
                error.contains("at /production_acceptance_receipt_ref") && error.contains("object")
            }),
            "missing targeted production root error: {}",
            errors.join("\n")
        );

        let mut nonproduction_with_acceptance = fixture;
        nonproduction_with_acceptance["production_acceptance_receipt_ref"] = json!({
            "artifact_kind": "package-exit-receipt",
            "document_id": "package-exit-receipt:forbidden-test-authority",
            "document_version": 1,
            "content_digest": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "artifact_locator": "receipts/forbidden-test-authority.json"
        });
        errors.clear();
        validate_instance(
            "test:nonproduction-with-root-acceptance",
            "deployment-security-profile.schema.json",
            &schema,
            &nonproduction_with_acceptance,
            &mut errors,
        );
        assert!(
            !errors.is_empty(),
            "non-production must not carry production acceptance authority"
        );
    }

    #[test]
    fn deployment_profile_requires_matching_non_downgradable_guard_expectations() {
        let schema = load("catalog/security-contracts/v1/deployment-security-profile.schema.json");
        let production = production_deployment_profile_fixture();
        let mut errors = Vec::new();
        validate_instance(
            "test:valid-typed-runtime-guard-expectations",
            "deployment-security-profile.schema.json",
            &schema,
            &production,
            &mut errors,
        );
        assert!(errors.is_empty(), "{}", errors.join("\n"));

        let mut missing = production.clone();
        missing["runtime_guard_evidence"]["guards"][0]
            .as_object_mut()
            .unwrap()
            .remove("expected_value");
        errors.clear();
        validate_instance(
            "test:runtime-guard-missing-expected-value",
            "deployment-security-profile.schema.json",
            &schema,
            &missing,
            &mut errors,
        );
        assert!(!errors.is_empty());

        let mut wrong_kind = production.clone();
        wrong_kind["runtime_guard_evidence"]["guards"][0]["expected_value"] =
            runtime_guard_expected_value(1, "deployment:repository-conformance-fixture");
        errors.clear();
        validate_instance(
            "test:runtime-guard-wrong-expected-kind",
            "deployment-security-profile.schema.json",
            &schema,
            &wrong_kind,
            &mut errors,
        );
        assert!(!errors.is_empty());

        let mut insecure_cookie = production;
        insecure_cookie["runtime_guard_evidence"]["guards"][3]["expected_value"]["policies"][0]
            ["secure"] = json!(false);
        errors.clear();
        validate_instance(
            "test:runtime-guard-insecure-cookie-expectation",
            "deployment-security-profile.schema.json",
            &schema,
            &insecure_cookie,
            &mut errors,
        );
        assert!(!errors.is_empty());

        let mut missing_runtime_binding = production_deployment_profile_fixture();
        missing_runtime_binding["runtime_guard_evidence"]["guards"][4]["expected_value"]
            ["authenticators"][0]
            .as_object_mut()
            .unwrap()
            .remove("runtime_binding_digest");
        errors.clear();
        validate_instance(
            "test:authenticator-missing-runtime-binding",
            "deployment-security-profile.schema.json",
            &schema,
            &missing_runtime_binding,
            &mut errors,
        );
        assert!(!errors.is_empty());

        let mut machine_only = production_deployment_profile_fixture();
        machine_only["runtime_guard_evidence"]["guards"][4]["expected_value"]["authenticators"]
            [0]["authenticator_kind"] = json!("workload");
        errors.clear();
        validate_instance(
            "test:authenticator-without-human-provider",
            "deployment-security-profile.schema.json",
            &schema,
            &machine_only,
            &mut errors,
        );
        assert!(!errors.is_empty());

        let mut legacy_mechanism = production_deployment_profile_fixture();
        let mut legacy_row = legacy_mechanism["runtime_guard_evidence"]["guards"][4]
            ["expected_value"]["authenticators"][0]
            .clone();
        legacy_row["provider"]["provider_id"] = json!("provider:validator-legacy-workload");
        legacy_row["authenticator_kind"] = json!("composite");
        legacy_mechanism["runtime_guard_evidence"]["guards"][4]["expected_value"]["authenticators"]
            .as_array_mut()
            .unwrap()
            .push(legacy_row);
        errors.clear();
        validate_instance(
            "test:legacy-authenticator-mechanism-label",
            "deployment-security-profile.schema.json",
            &schema,
            &legacy_mechanism,
            &mut errors,
        );
        assert!(!errors.is_empty());
    }

    #[test]
    fn deployment_profile_references_reject_zero_digests_and_json_pointer_locators() {
        let schema = load("catalog/security-contracts/v1/deployment-security-profile.schema.json");
        let production = production_deployment_profile_fixture();
        let mut errors = Vec::new();
        validate_instance(
            "test:valid-production-reference-baseline",
            "deployment-security-profile.schema.json",
            &schema,
            &production,
            &mut errors,
        );
        assert!(errors.is_empty(), "{}", errors.join("\n"));

        let mut production_with_overlay = production.clone();
        add_production_migration_overlay(&mut production_with_overlay);
        validate_instance(
            "test:valid-production-overlay-reference-baseline",
            "deployment-security-profile.schema.json",
            &schema,
            &production_with_overlay,
            &mut errors,
        );
        assert!(errors.is_empty(), "{}", errors.join("\n"));

        for field in [
            "conformance_trust_root_registry_ref",
            "control_trace_ref",
            "provider_registry_ref",
            "provider_lifecycle_snapshot_ref",
            "action_resource_registry_ref",
            "security_limit_profile_ref",
            "control_plane_topology_ref",
            "egress_policy_ref",
            "retention_policy_ref",
        ] {
            for (member, invalid) in [
                ("content_digest", json!(ZERO_SHA256_DIGEST)),
                ("artifact_locator", json!(format!("json-pointer:#/{field}"))),
            ] {
                let mut candidate = production.clone();
                candidate[field][member] = invalid;
                let mut errors = Vec::new();
                validate_instance(
                    &format!("test:{field}-{member}"),
                    "deployment-security-profile.schema.json",
                    &schema,
                    &candidate,
                    &mut errors,
                );
                let expected_path = format!("/{field}/{member}");
                assert!(
                    errors
                        .iter()
                        .any(|error| error.contains(&format!("at {expected_path}"))),
                    "{field}.{member} missing {expected_path}: {}",
                    errors.join("\n")
                );
            }
        }

        let mut cases = Vec::new();
        let mut candidate = production.clone();
        candidate["production_acceptance_receipt_ref"]["content_digest"] =
            json!(ZERO_SHA256_DIGEST);
        cases.push((
            "root receipt zero digest",
            candidate,
            "/production_acceptance_receipt_ref/content_digest",
        ));
        let mut candidate = production.clone();
        candidate["production_acceptance_receipt_ref"]["artifact_locator"] =
            json!("json-pointer:#/production_acceptance_receipt_ref");
        cases.push((
            "root receipt JSON Pointer locator",
            candidate,
            "/production_acceptance_receipt_ref/artifact_locator",
        ));
        let mut candidate = production.clone();
        candidate["runtime_guard_evidence"]["guards"][0]["receipt_ref"]["content_digest"] =
            json!(ZERO_SHA256_DIGEST);
        cases.push((
            "guard receipt zero digest",
            candidate,
            "/runtime_guard_evidence/guards/0/receipt_ref/content_digest",
        ));
        let mut candidate = production.clone();
        candidate["runtime_guard_evidence"]["guards"][0]["receipt_ref"]["artifact_locator"] =
            json!("json-pointer:#/runtime_guard_evidence/guards/0/receipt_ref");
        cases.push((
            "guard receipt JSON Pointer locator",
            candidate,
            "/runtime_guard_evidence/guards/0/receipt_ref/artifact_locator",
        ));
        let mut candidate = production_with_overlay.clone();
        candidate["migration_overlay"]["zero_consumer_receipt_ref"]["content_digest"] =
            json!(ZERO_SHA256_DIGEST);
        cases.push((
            "migration receipt zero digest",
            candidate,
            "/migration_overlay/zero_consumer_receipt_ref/content_digest",
        ));
        let mut candidate = production_with_overlay;
        candidate["migration_overlay"]["zero_consumer_receipt_ref"]["artifact_locator"] =
            json!("json-pointer:#/migration_overlay/zero_consumer_receipt_ref");
        cases.push((
            "migration receipt JSON Pointer locator",
            candidate,
            "/migration_overlay/zero_consumer_receipt_ref/artifact_locator",
        ));

        for (label, candidate, expected_path) in cases {
            let mut errors = Vec::new();
            validate_instance(
                label,
                "deployment-security-profile.schema.json",
                &schema,
                &candidate,
                &mut errors,
            );
            assert!(
                errors
                    .iter()
                    .any(|error| error.contains(&format!("at {expected_path}"))),
                "{label} missing {expected_path}: {}",
                errors.join("\n")
            );
        }
    }

    #[test]
    fn repository_gate_never_accepts_self_declared_closure_authority() {
        let forged = LoadedDocument {
            label: "forged:self-consistent".into(),
            digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .into(),
            value: json!({}),
        };
        let mut errors = Vec::new();
        reject_untrusted_closure_documents(&[forged], &[], &mut errors);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("trusted production-closure verification is not implemented"));
    }

    #[test]
    fn closure_policy_and_configuration_sets_are_exact_profile_projections() {
        let (policies, configurations) =
            load_deployment_profile_version_bindings(&root()).expect("checked-in profile bindings");
        let mut context = json!({
            "policy_versions": policies,
            "configuration_versions": configurations,
        });
        let expected = load_deployment_profile_version_bindings(&root()).unwrap();
        let mut errors = Vec::new();
        validate_profile_version_bindings(Some(&context), Some(&expected), "test", &mut errors);
        assert!(errors.is_empty(), "{}", errors.join("\n"));

        context["policy_versions"].as_array_mut().unwrap().pop();
        validate_profile_version_bindings(Some(&context), Some(&expected), "test", &mut errors);
        assert!(errors
            .iter()
            .any(|error| error.contains("policy artifact set")));
    }

    #[test]
    fn receipt_digest_projections_are_exact_sorted_nonzero_and_bounded() {
        let (_, _, receipt) = authoritative_candidate_fixture();
        let mut errors = Vec::new();
        validate_receipt_digest_projections(&receipt, &mut errors);
        assert!(errors.is_empty(), "{}", errors.join("\n"));

        let mut invalid = receipt;
        invalid.value["input_digests"]
            .as_array_mut()
            .expect("input digests")
            .reverse();
        invalid.value["output_digests"] = json!([ZERO_SHA256_DIGEST]);
        let mut errors = Vec::new();
        validate_receipt_digest_projections(&invalid, &mut errors);
        assert!(errors
            .iter()
            .any(|error| error.contains("strictly bytewise sorted")));
        assert!(errors
            .iter()
            .any(|error| error.contains("nonzero lowercase SHA-256")));
        assert!(errors
            .iter()
            .any(|error| error.contains("exact evaluated evidence-bundle")));

        invalid.value["input_digests"] = Value::Array(vec![
            json!(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            );
            MAX_RECEIPT_DIGESTS + 1
        ]);
        errors.clear();
        validate_receipt_digest_projections(&invalid, &mut errors);
        assert!(errors
            .iter()
            .any(|error| error.contains("1 through 4096 digests")));
    }

    #[test]
    fn receipt_package_constraints_bind_tier_and_complete_sb9_retirement() {
        let (_, _, mut receipt) = authoritative_candidate_fixture();
        let evidence_ids = BTreeSet::from(["evidence:authoritative".to_string()]);
        receipt.value["package_id"] = json!("SB-8");
        receipt.value["retirement_closure"] = json!({});
        let mut errors = Vec::new();
        validate_receipt_package_constraints(&receipt, &evidence_ids, &mut errors);
        assert!(errors
            .iter()
            .any(|error| error.contains("at least operator_environment")));
        assert!(errors
            .iter()
            .any(|error| error.contains("must have retirement_closure=null")));

        receipt.value["package_id"] = json!("SB-9");
        receipt.value["evidence_tier"] = json!({"name": "operator_environment", "rank": 2});
        receipt.value["retirement_closure"] = json!({
            "zero_consumer_evidence_instance_ids": ["evidence:authoritative"],
            "zero_live_authority_evidence_instance_ids": ["evidence:authoritative"],
            "retired_bypass_evidence_instance_ids": ["evidence:wrong"]
        });
        errors.clear();
        validate_receipt_package_constraints(&receipt, &evidence_ids, &mut errors);
        assert!(errors
            .iter()
            .any(|error| error.contains("exact current SB-9 receipt evidence set")));
    }

    #[test]
    fn runtime_guard_control_ids_are_globally_unique() {
        let deployment = json!({
            "runtime_guard_evidence": {"guards": [
                {"guard_id": "durable-postgresql", "control_ids": ["SB-OPS-01"]},
                {"guard_id": "approved-secret-provider", "control_ids": ["SB-OPS-01"]}
            ]}
        });
        let mut errors = Vec::new();
        validate_runtime_guard_control_ownership(&deployment, &mut errors);
        assert!(errors
            .iter()
            .any(|error| error.contains("globally unique across runtime guards")));
    }

    #[test]
    fn duplicate_json_keys_are_rejected_recursively() {
        let error = parse_json_strict(br#"{"outer":{"id":1,"id":2}}"#)
            .expect_err("duplicate key must fail");
        assert!(error
            .to_string()
            .contains("duplicate JSON object key \"id\""));
    }

    #[test]
    fn ac_048_rejects_inventory_omission_and_unknown_control() {
        let mut ledger = ledger();
        ledger["controls"]
            .as_array_mut()
            .expect("controls")
            .remove(0);
        ledger["controls"]
            .as_array_mut()
            .expect("controls")
            .push(json!({
                "control_id": "SB-FAKE-99",
                "title": "Not a normative control",
                "owning_work_package": "SB-0",
                "owning_team": "test",
                "waivable": false
            }));

        let errors = semantic_errors(&ledger);
        assert!(errors
            .iter()
            .any(|error| error == "missing canonical control SB-BOUND-01"));
        assert!(errors
            .iter()
            .any(|error| error == "unknown canonical control SB-FAKE-99"));
    }

    #[test]
    fn ac_048_rejects_orphan_and_duplicate_static_mapping_tuple() {
        let mut ledger = ledger();
        let mut duplicate = ledger["traces"][0].clone();
        duplicate["trace_id"] = json!("TRACE-DUPLICATE-STATIC-TUPLE");
        ledger["traces"]
            .as_array_mut()
            .expect("traces")
            .push(duplicate);
        ledger["traces"][1]["control_id"] = json!("SB-UNKNOWN-99");

        let errors = semantic_errors(&ledger);
        assert!(errors
            .iter()
            .any(|error| error.contains("duplicate static mapping tuple")));
        assert!(errors
            .iter()
            .any(|error| error.contains("references unknown control SB-UNKNOWN-99")));
    }

    #[test]
    fn ac_048_rejects_conflicting_owner_and_circular_trace_supersession() {
        let mut ledger = ledger();
        let first = ledger["traces"][0]["trace_id"]
            .as_str()
            .expect("trace id")
            .to_string();
        let second = ledger["traces"][1]["trace_id"]
            .as_str()
            .expect("trace id")
            .to_string();
        ledger["traces"][0]["owning_team"] = json!("conflicting-owner");
        ledger["traces"][0]["supersedes_trace_id"] = json!(second);
        ledger["traces"][1]["supersedes_trace_id"] = json!(first);

        let errors = semantic_errors(&ledger);
        assert!(errors.iter().any(
            |error| error.contains("but trace declares") && error.contains("conflicting-owner")
        ));
        assert!(errors
            .iter()
            .any(|error| error.starts_with("trace supersession cycle:")));
    }

    #[test]
    fn ac_048_rejects_duplicate_evidence_id_and_applicability_mismatch() {
        let ledger = ledger();
        let trace = &ledger["traces"][0];
        let first = bundle_for_trace("bundle:first", "evidence:duplicate", trace, false);
        let second = bundle_for_trace("bundle:second", "evidence:duplicate", trace, true);
        let mut errors = Vec::new();
        validate_closure_semantics(&root(), &ledger, &[first, second], &[], &mut errors);
        errors.sort();

        assert!(errors
            .iter()
            .any(|error| error.contains("duplicate evidence_instance_id evidence:duplicate")));
        assert!(errors
            .iter()
            .any(|error| error.contains("applicability mismatch")));
    }

    #[test]
    fn ac_048_rejects_recursive_receipt_cycle() {
        let ledger = ledger();
        let trace = &ledger["traces"][0];
        let bundle = bundle_for_trace("bundle:one", "evidence:one", trace, false);
        let package = trace["owning_work_package"].as_str().expect("package");
        let first_id = "package-exit-receipt:first";
        let second_id = "package-exit-receipt:second";
        let first_digest =
            "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        let second_digest =
            "sha256:2222222222222222222222222222222222222222222222222222222222222222";
        let first = receipt_for_trace(
            first_id,
            first_digest,
            package,
            trace,
            "evidence:one",
            Some((second_id, second_digest)),
            &ledger,
        );
        let second = receipt_for_trace(
            second_id,
            second_digest,
            package,
            trace,
            "evidence:one",
            Some((first_id, first_digest)),
            &ledger,
        );

        let mut errors = Vec::new();
        validate_closure_semantics(&root(), &ledger, &[bundle], &[first, second], &mut errors);
        errors.sort();
        assert!(errors
            .iter()
            .any(|error| error.starts_with("prerequisite receipt cycle:")));
    }

    #[test]
    fn ac_048_rejects_evidence_digest_substitution() {
        let ledger = ledger();
        let trace = &ledger["traces"][0];
        let bundle = bundle_for_trace("bundle:one", "evidence:one", trace, false);
        let package = trace["owning_work_package"].as_str().expect("package");
        let mut receipt = receipt_for_trace(
            "package-exit-receipt:digest-substitution",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            package,
            trace,
            "evidence:one",
            None,
            &ledger,
        );
        receipt.value["evaluated_sets"]["evidence_bindings"][0]["bundle_digest"] =
            json!("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

        let mut errors = Vec::new();
        validate_closure_semantics(&root(), &ledger, &[bundle], &[receipt], &mut errors);
        assert!(errors
            .iter()
            .any(|error| error.contains("bundle_digest does not match")));
    }

    #[test]
    fn ac_048_rejects_wrong_closure_reference_kind_identity_version_and_locator() {
        for (field, wrong, expected_error) in [
            (
                "artifact_kind",
                json!("package-exit-receipt"),
                "artifact_kind must exactly reference conformance-bundle",
            ),
            (
                "bundle_id",
                json!("bundle:wrong"),
                "bundle_id does not match the referenced closure document",
            ),
            (
                "document_version",
                json!(99),
                "document_version does not match the referenced closure document",
            ),
            (
                "artifact_locator",
                json!("catalog/security-contracts/v1/conformance-bundles/wrong.json"),
                "artifact_locator must exactly reference test:authoritative-bundle",
            ),
        ] {
            let (ledger, bundle, mut receipt) = authoritative_candidate_fixture();
            receipt.value["evaluated_sets"]["evidence_bindings"][0][field] = wrong;
            let mut errors = Vec::new();
            validate_closure_semantics_at(
                &root(),
                &ledger,
                &[bundle],
                &[receipt],
                closure_test_now(),
                &mut errors,
            );
            assert!(
                errors.iter().any(|error| error.contains(expected_error)),
                "missing {expected_error}: {}",
                errors.join("\n")
            );
        }
    }

    #[test]
    fn ac_048_rejects_noncanonical_ledger_locator() {
        let (ledger, bundle, mut receipt) = authoritative_candidate_fixture();
        receipt.value["ledger_binding"]["artifact_locator"] =
            json!("catalog/security-contracts/v1/./control-trace.implementation.json");
        let mut errors = Vec::new();
        validate_closure_semantics_at(
            &root(),
            &ledger,
            &[bundle],
            &[receipt],
            closure_test_now(),
            &mut errors,
        );
        assert!(errors.iter().any(|error| {
            error.contains("artifact_locator must exactly reference catalog/security-contracts/v1/control-trace.implementation.json")
        }));
    }

    #[test]
    fn ac_048_rejects_failed_and_expired_authoritative_evidence() {
        let ledger = ledger();
        let trace = &ledger["traces"][0];
        let mut bundle = bundle_for_trace("bundle:stale", "evidence:stale", trace, false);
        make_bundle_production_accepted(&mut bundle);
        bundle.value["normalized_result"] = json!("fail");
        bundle.value["expires_at"] = json!("2026-06-30T00:00:00Z");
        let package = trace["owning_work_package"].as_str().expect("package");
        let mut receipt = receipt_for_trace(
            "package-exit-receipt:stale",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            package,
            trace,
            "evidence:stale",
            None,
            &ledger,
        );
        make_receipt_candidate(&mut receipt);

        let mut errors = Vec::new();
        validate_closure_semantics_at(
            &root(),
            &ledger,
            &[bundle],
            &[receipt],
            closure_test_now(),
            &mut errors,
        );
        assert!(errors
            .iter()
            .any(|error| error.contains("normalized_result=pass")));
        assert!(errors
            .iter()
            .any(|error| error.contains("evidence evidence:stale is expired")));
    }

    #[test]
    fn ac_048_rejects_superseded_authoritative_evidence() {
        let ledger = ledger();
        let trace = &ledger["traces"][0];
        let mut old = bundle_for_trace("bundle:old", "evidence:old", trace, false);
        old.label = format!("{CONFORMANCE_BUNDLE_LOCATOR_PREFIX}bundle-old.json");
        make_bundle_production_accepted(&mut old);
        let mut replacement = bundle_for_trace("bundle:new", "evidence:new", trace, false);
        replacement.value["document_version"] = json!(2);
        replacement.value["supersedes_evidence_instance_id"] = json!("evidence:old");
        replacement.value["supersedes_evidence_ref"] = json!({
            "artifact_kind": "conformance-bundle",
            "bundle_id": old.value["bundle_id"].clone(),
            "document_version": old.value["document_version"].clone(),
            "artifact_locator": old.label.clone(),
            "evidence_instance_id": old.value["evidence_instance_id"].clone(),
            "bundle_digest": old.digest.clone()
        });
        let package = trace["owning_work_package"].as_str().expect("package");
        let mut receipt = receipt_for_trace(
            "package-exit-receipt:superseded",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            package,
            trace,
            "evidence:old",
            None,
            &ledger,
        );
        make_receipt_candidate(&mut receipt);
        receipt.value["evaluated_sets"]["evidence_bindings"][0]["artifact_locator"] =
            json!(old.label.clone());

        let mut errors = Vec::new();
        validate_closure_semantics_at(
            &root(),
            &ledger,
            &[old, replacement],
            &[receipt],
            closure_test_now(),
            &mut errors,
        );
        assert!(errors
            .iter()
            .any(|error| error.contains("evidence evidence:old has been superseded")));
    }

    #[test]
    fn ac_048_rejects_cross_instance_or_non_monotonic_evidence_supersession() {
        let (ledger, mut old, mut receipt) = authoritative_candidate_fixture();
        old.label = format!("{CONFORMANCE_BUNDLE_LOCATOR_PREFIX}authoritative-bundle.json");
        receipt.value["evaluated_sets"]["evidence_bindings"][0]["artifact_locator"] =
            json!(old.label.clone());
        let mut invalid = old.clone();
        invalid.label = "test:invalid-successor".to_string();
        invalid.value["bundle_id"] = json!("bundle:invalid-successor");
        invalid.value["evidence_instance_id"] = json!("evidence:invalid-successor");
        invalid.value["applicability_instance_id"] = json!("applicability:other");
        invalid.value["supersedes_evidence_instance_id"] = json!("evidence:authoritative");
        invalid.value["supersedes_evidence_ref"] = json!({
            "artifact_kind": "conformance-bundle",
            "bundle_id": old.value["bundle_id"].clone(),
            "document_version": old.value["document_version"].clone(),
            "artifact_locator": old.label.clone(),
            "evidence_instance_id": old.value["evidence_instance_id"].clone(),
            "bundle_digest": old.digest.clone()
        });
        let mut errors = Vec::new();
        validate_closure_semantics_at(
            &root(),
            &ledger,
            &[old, invalid],
            &[receipt],
            closure_test_now(),
            &mut errors,
        );
        assert!(errors.iter().any(|error| {
            error.contains("different applicability_instance_id")
                || error.contains("document_version 1 must exceed 1")
        }));
        assert!(!errors
            .iter()
            .any(|error| error.contains("evidence evidence:authoritative has been superseded")));
    }

    #[test]
    fn ac_048_rejects_missing_normative_prerequisite_package() {
        let ledger = ledger();
        let trace = ledger["traces"]
            .as_array()
            .expect("traces")
            .iter()
            .find(|trace| trace["owning_work_package"] == "SB-1")
            .expect("SB-1 trace");
        let mut bundle = bundle_for_trace("bundle:sb1", "evidence:sb1", trace, false);
        make_bundle_production_accepted(&mut bundle);
        let mut receipt = receipt_for_trace(
            "package-exit-receipt:sb1-without-sb0",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "SB-1",
            trace,
            "evidence:sb1",
            None,
            &ledger,
        );
        make_receipt_candidate(&mut receipt);

        let mut errors = Vec::new();
        validate_closure_semantics_at(
            &root(),
            &ledger,
            &[bundle],
            &[receipt],
            closure_test_now(),
            &mut errors,
        );
        assert!(errors
            .iter()
            .any(|error| { error.contains("prerequisite package set") && error.contains("SB-0") }));
    }

    #[test]
    fn ac_048_authoritative_candidate_semantic_baseline_is_clean() {
        let (ledger, bundle, receipt) = authoritative_candidate_fixture();
        let mut errors = Vec::new();
        validate_closure_semantics_at(
            &root(),
            &ledger,
            &[bundle],
            &[receipt],
            closure_test_now(),
            &mut errors,
        );
        assert!(errors.is_empty(), "{}", errors.join("\n"));
    }

    #[test]
    fn ac_048_evaluates_closed_recursive_applicability_language() {
        let dimensions = BTreeMap::from([
            ("implementation.mode".to_string(), json!("production")),
            (
                "implementation.tags".to_string(),
                json!(["trusted", "pinned"]),
            ),
            ("implementation.replicas".to_string(), json!(3)),
        ]);
        let expression = json!({
            "operator": "all",
            "operands": [
                {"operator": "equals", "dimension": "implementation.mode", "value": "production"},
                {"operator": "not_equals", "dimension": "implementation.replicas", "value": 1},
                {"operator": "contains", "dimension": "implementation.tags", "value": "trusted"},
                {"operator": "in", "dimension": "implementation.replicas", "values": [2, 3, 4]},
                {"operator": "not_in", "dimension": "implementation.mode", "values": ["test", "development"]},
                {"operator": "not", "operand": {"operator": "never"}},
                {"operator": "any", "operands": [
                    {"operator": "never"},
                    {"operator": "always"}
                ]}
            ]
        });
        assert_eq!(evaluate_expression(&expression, &dimensions), Ok(true));
    }

    #[test]
    fn ac_048_treats_a_null_minimum_tier_as_out_of_scope() {
        let trace = json!({
            "trace_id": "TRACE-TEST-AC-001",
            "applicability_expression": {
                "implementation": {"operator": "always"},
                "deployment": {"operator": "always"}
            },
            "evidence_instance_dimensions": {
                "implementation": [],
                "deployment": []
            },
            "minimum_evidence_tier": {
                "implementation": null,
                "deployment": {"name": "repository_local", "rank": 1}
            }
        });
        let instance = json!({
            "implementation_dimensions": [],
            "deployment_dimensions": []
        });
        let bundle = LoadedDocument {
            label: "test:null-tier-bundle".to_string(),
            digest: ZERO_SHA256_DIGEST.to_string(),
            value: json!({
                "evaluated_applicability": {
                    "implementation": {"applicable": false, "dimensions": []},
                    "deployment": {"applicable": true, "dimensions": []}
                },
                "provenance": {
                    "evidence_tier": {"name": "repository_local", "rank": 1}
                }
            }),
        };
        let mut errors = Vec::new();

        assert_eq!(
            evaluate_trace_scope(&bundle, &trace, &instance, "implementation", &mut errors,),
            Some(false)
        );
        validate_bundle_applicability(&bundle, &trace, &mut errors);
        assert!(errors.is_empty(), "{}", errors.join("\n"));
    }

    #[test]
    fn ac_048_bounds_recursive_applicability_expressions() {
        let dimensions = BTreeMap::new();
        let too_many_operands = json!({
            "operator": "all",
            "operands": (0..=MAX_APPLICABILITY_EXPRESSION_OPERANDS)
                .map(|_| json!({"operator": "always"}))
                .collect::<Vec<_>>()
        });
        assert!(evaluate_expression(&too_many_operands, &dimensions)
            .unwrap_err()
            .contains("1 through 64 operands"));

        let mut too_deep = json!({"operator": "always"});
        for _ in 0..=MAX_APPLICABILITY_EXPRESSION_DEPTH {
            too_deep = json!({"operator": "not", "operand": too_deep});
        }
        assert!(evaluate_expression(&too_deep, &dimensions)
            .unwrap_err()
            .contains("maximum depth"));

        fn binary_expression(depth: usize) -> Value {
            if depth == 0 {
                json!({"operator": "always"})
            } else {
                json!({
                    "operator": "all",
                    "operands": [
                        binary_expression(depth - 1),
                        binary_expression(depth - 1)
                    ]
                })
            }
        }
        assert!(evaluate_expression(&binary_expression(12), &dimensions)
            .unwrap_err()
            .contains("maximum node count"));
    }

    #[test]
    fn ac_048_rejects_applicability_instance_undercount() {
        let (ledger, bundle, mut receipt) = authoritative_candidate_fixture();
        receipt.value["applicability_instances"]
            .as_array_mut()
            .expect("instances")
            .push(json!({
                "instance_id": "applicability:second",
                "implementation_dimensions": [],
                "deployment_dimensions": []
            }));
        let mut errors = Vec::new();
        validate_closure_semantics_at(
            &root(),
            &ledger,
            &[bundle],
            &[receipt],
            closure_test_now(),
            &mut errors,
        );
        assert!(errors.iter().any(|error| {
            error.contains("applicability instance applicability:second")
                && error.contains("neither evidence nor an authorized waiver")
        }));
    }

    #[test]
    fn ac_048_rejects_scope_mismatched_and_expired_waiver() {
        let (mut ledger, _bundle, mut receipt) = authoritative_candidate_fixture();
        ledger["controls"][0]["waivable"] = json!(true);
        ledger["controls"]
            .as_array_mut()
            .expect("controls")
            .push(json!({
                "control_id": "SB-TEST-02",
                "owning_work_package": "SB-0",
                "waivable": false
            }));
        receipt.value["evaluated_sets"]["evidence_bindings"] = json!([]);
        receipt.value["waivers"] = json!([{
            "trace_id": "TRACE-TEST-AC-001",
            "control_id": "SB-TEST-01",
            "compensating_control_id": "SB-TEST-02",
            "scope": {
                "instance_id": "applicability:fixture",
                "implementation_dimensions": [{
                    "name": "implementation.unexpected",
                    "value": "wrong"
                }],
                "deployment_dimensions": []
            },
            "approval": {"approved_at": "2026-06-01T00:00:00Z"},
            "expires_at": "2026-07-01T00:00:00Z"
        }]);
        let mut errors = Vec::new();
        validate_closure_semantics_at(
            &root(),
            &ledger,
            &[],
            &[receipt],
            closure_test_now(),
            &mut errors,
        );
        assert!(errors
            .iter()
            .any(|error| error.contains("waiver scope does not exactly match")));
        assert!(errors
            .iter()
            .any(|error| error.contains("waiver is expired")));
        assert!(errors
            .iter()
            .any(|error| error.contains("neither evidence nor an authorized waiver")));
    }

    #[test]
    fn ac_048_rejects_receipt_tier_inflation() {
        let (ledger, bundle, mut receipt) = authoritative_candidate_fixture();
        receipt.value["evidence_tier"] = json!({"name": "externally_attested", "rank": 3});
        let mut errors = Vec::new();
        validate_closure_semantics_at(
            &root(),
            &ledger,
            &[bundle],
            &[receipt],
            closure_test_now(),
            &mut errors,
        );
        assert!(errors
            .iter()
            .any(|error| error.contains("tier rank 1 is below receipt rank 3")));
    }

    #[test]
    fn ac_048_rejects_superseded_authoritative_receipt_directly() {
        let (ledger, bundle, mut old) = authoritative_candidate_fixture();
        old.label = format!("{PACKAGE_EXIT_RECEIPT_LOCATOR_PREFIX}authoritative-candidate.json");
        let mut replacement = old.clone();
        replacement.label = "test:replacement-receipt".to_string();
        replacement.digest =
            "sha256:2222222222222222222222222222222222222222222222222222222222222222".to_string();
        replacement.value["receipt_id"] = json!("package-exit-receipt:replacement");
        replacement.value["document_version"] = json!(2);
        replacement.value["supersedes_receipt_id"] =
            json!("package-exit-receipt:authoritative-candidate");
        replacement.value["supersedes_receipt_ref"] = json!({
            "artifact_kind": "package-exit-receipt",
            "receipt_id": old.value["receipt_id"].clone(),
            "document_version": old.value["document_version"].clone(),
            "artifact_locator": old.label.clone(),
            "package_id": old.value["package_id"].clone(),
            "receipt_digest": old.digest.clone()
        });
        let mut errors = Vec::new();
        validate_closure_semantics_at(
            &root(),
            &ledger,
            &[bundle],
            &[old, replacement],
            closure_test_now(),
            &mut errors,
        );
        assert!(errors.iter().any(|error| {
            error.contains("authoritative receipt package-exit-receipt:authoritative-candidate")
                && error.contains("superseded")
        }));
    }

    #[test]
    fn ac_048_rejects_supersession_forks_for_evidence_and_receipts() {
        let (ledger, mut bundle, mut receipt) = authoritative_candidate_fixture();
        bundle.label = format!("{CONFORMANCE_BUNDLE_LOCATOR_PREFIX}authoritative-bundle.json");
        receipt.value["evaluated_sets"]["evidence_bindings"][0]["artifact_locator"] =
            json!(bundle.label.clone());
        receipt.label =
            format!("{PACKAGE_EXIT_RECEIPT_LOCATOR_PREFIX}authoritative-candidate.json");

        let first_bundle = successor_bundle(
            &bundle,
            "bundle:fork-one",
            "evidence:fork-one",
            "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        );
        let second_bundle = successor_bundle(
            &bundle,
            "bundle:fork-two",
            "evidence:fork-two",
            "sha256:3333333333333333333333333333333333333333333333333333333333333333",
        );
        let first_receipt = successor_receipt(
            &receipt,
            "package-exit-receipt:fork-one",
            "sha256:4444444444444444444444444444444444444444444444444444444444444444",
        );
        let second_receipt = successor_receipt(
            &receipt,
            "package-exit-receipt:fork-two",
            "sha256:5555555555555555555555555555555555555555555555555555555555555555",
        );

        let mut errors = Vec::new();
        validate_closure_semantics_at(
            &root(),
            &ledger,
            &[bundle, first_bundle, second_bundle],
            &[receipt, first_receipt, second_receipt],
            closure_test_now(),
            &mut errors,
        );
        assert!(errors.iter().any(|error| {
            error.contains("evidence predecessor evidence:authoritative has multiple successors")
        }));
        assert!(errors.iter().any(|error| {
            error.contains(
                "receipt predecessor package-exit-receipt:authoritative-candidate has multiple successors",
            )
        }));
        assert!(!errors
            .iter()
            .any(|error| error.contains("evidence evidence:authoritative has been superseded")));
        assert!(!errors.iter().any(|error| {
            error.contains("authoritative receipt package-exit-receipt:authoritative-candidate")
                && error.contains("superseded")
        }));
    }

    #[test]
    fn ac_048_rejects_supersession_evidence_tier_downgrades() {
        let (ledger, mut bundle, mut receipt) = authoritative_candidate_fixture();
        bundle.label = format!("{CONFORMANCE_BUNDLE_LOCATOR_PREFIX}authoritative-bundle.json");
        bundle.value["provenance"]["evidence_tier"] =
            json!({"name": "externally_attested", "rank": 3});
        receipt.value["evaluated_sets"]["evidence_bindings"][0]["artifact_locator"] =
            json!(bundle.label.clone());
        receipt.value["evidence_tier"] = json!({"name": "externally_attested", "rank": 3});
        receipt.label =
            format!("{PACKAGE_EXIT_RECEIPT_LOCATOR_PREFIX}authoritative-candidate.json");

        let mut bundle_successor = successor_bundle(
            &bundle,
            "bundle:downgraded",
            "evidence:downgraded",
            "sha256:6666666666666666666666666666666666666666666666666666666666666666",
        );
        bundle_successor.value["provenance"]["evidence_tier"] =
            json!({"name": "repository_local", "rank": 1});
        let mut receipt_successor = successor_receipt(
            &receipt,
            "package-exit-receipt:downgraded",
            "sha256:7777777777777777777777777777777777777777777777777777777777777777",
        );
        receipt_successor.value["evidence_tier"] = json!({"name": "repository_local", "rank": 1});

        let mut errors = Vec::new();
        validate_closure_semantics_at(
            &root(),
            &ledger,
            &[bundle, bundle_successor],
            &[receipt, receipt_successor],
            closure_test_now(),
            &mut errors,
        );
        assert!(errors.iter().any(|error| {
            error.contains("superseding evidence evidence:downgraded tier rank 1")
                && error.contains("predecessor evidence:authoritative rank 3")
        }));
        assert!(errors.iter().any(|error| {
            error.contains("superseding receipt package-exit-receipt:downgraded tier rank 1")
                && error.contains("predecessor package-exit-receipt:authoritative-candidate rank 3")
        }));
        assert!(!errors
            .iter()
            .any(|error| error.contains("evidence evidence:authoritative has been superseded")));
        assert!(!errors.iter().any(|error| {
            error.contains("authoritative receipt package-exit-receipt:authoritative-candidate")
                && error.contains("superseded")
        }));
    }

    #[test]
    fn provider_registry_rejects_payload_tamper_and_digest_contract_downgrade() {
        let registry = load("catalog/security-contracts/v1/provider-registry.implementation.json");
        let mut tampered = registry.clone();
        tampered["configurations"][0]["display_name"] = json!("tampered-after-digest");
        let mut errors = Vec::new();
        validate_provider_registry(&tampered, &mut errors);
        assert!(errors
            .iter()
            .any(|error| error.contains("payload_digest does not match")));

        let mut downgraded = registry;
        downgraded["configurations"][0]["payload_digest_contract"]["algorithm"] = json!("sha-1");
        let mut errors = Vec::new();
        validate_provider_registry(&downgraded, &mut errors);
        assert!(errors
            .iter()
            .any(|error| error.contains("closed ryuki-canonical-json-v1 SHA-256 contract")));

        let mut unsorted =
            load("catalog/security-contracts/v1/provider-registry.implementation.json");
        unsorted["configurations"][0]["capability_descriptor"]["advertised_capabilities"] =
            json!(["static-human-fixture", "dry-run-only"]);
        let mut errors = Vec::new();
        validate_provider_registry(&unsorted, &mut errors);
        assert!(errors.iter().any(|error| {
            error.contains("advertised_capabilities must be non-empty and strictly sorted")
        }));
    }

    #[test]
    fn provider_registry_accepts_coherent_multi_record_lifecycle_history() {
        let mut registry =
            load("catalog/security-contracts/v1/provider-registry.implementation.json");
        let genesis = registry["provider_lifecycle"][0].clone();
        registry["provider_lifecycle"] = json!([
            provider_lifecycle_record(&genesis, 1, 1, "configured", "2026-07-16T00:00:00Z", None),
            provider_lifecycle_record(&genesis, 1, 2, "validated", "2026-07-16T00:01:00Z", Some(1),),
            provider_lifecycle_record(&genesis, 1, 3, "active", "2026-07-16T00:02:00Z", Some(2),),
        ]);

        let mut errors = Vec::new();
        validate_provider_registry(&registry, &mut errors);
        assert!(errors.is_empty(), "{errors:?}");
    }

    #[test]
    fn provider_registry_rejects_broken_or_non_monotonic_lifecycle_history() {
        let mut registry =
            load("catalog/security-contracts/v1/provider-registry.implementation.json");
        let genesis = registry["provider_lifecycle"][0].clone();
        registry["provider_lifecycle"] = json!([
            provider_lifecycle_record(&genesis, 1, 1, "configured", "2026-07-16T00:00:00Z", None),
            provider_lifecycle_record(&genesis, 1, 2, "validated", "2026-07-16T00:00:00Z", Some(7),),
        ]);

        let mut errors = Vec::new();
        validate_provider_registry(&registry, &mut errors);
        assert!(errors
            .iter()
            .any(|error| error.contains("broken supersession chain")));
        assert!(errors
            .iter()
            .any(|error| error.contains("effective_at must strictly increase")));
    }

    #[test]
    fn provider_registry_selects_only_latest_active_state_and_rejects_simultaneous_active_versions()
    {
        let mut registry =
            load("catalog/security-contracts/v1/provider-registry.implementation.json");
        let first_configuration = registry["configurations"][0].clone();
        let mut second_configuration = first_configuration.clone();
        second_configuration["config_version"] = json!(2);
        refresh_provider_payload_digest(&mut second_configuration);
        registry["configurations"] = json!([first_configuration, second_configuration]);

        let genesis = registry["provider_lifecycle"][0].clone();
        let first_draining =
            provider_lifecycle_record(&genesis, 1, 4, "draining", "2026-07-16T00:03:00Z", Some(3));
        registry["provider_lifecycle"] = json!([
            provider_lifecycle_record(&genesis, 1, 1, "configured", "2026-07-16T00:00:00Z", None),
            provider_lifecycle_record(&genesis, 1, 2, "validated", "2026-07-16T00:01:00Z", Some(1),),
            provider_lifecycle_record(&genesis, 1, 3, "active", "2026-07-16T00:02:00Z", Some(2),),
            first_draining.clone(),
            provider_lifecycle_record(&genesis, 2, 1, "configured", "2026-07-16T00:04:00Z", None),
            provider_lifecycle_record(&genesis, 2, 2, "validated", "2026-07-16T00:05:00Z", Some(1),),
            provider_lifecycle_record(&genesis, 2, 3, "active", "2026-07-16T00:06:00Z", Some(2),),
        ]);

        let mut errors = Vec::new();
        validate_provider_registry(&registry, &mut errors);
        assert!(errors.is_empty(), "{errors:?}");

        registry["provider_lifecycle"]
            .as_array_mut()
            .expect("provider lifecycle array")
            .retain(|record| record != &first_draining);
        let mut errors = Vec::new();
        validate_provider_registry(&registry, &mut errors);
        assert!(errors.iter().any(|error| {
            error.contains("provider provider:repository-static-dry-run")
                && error.contains("multiple active configuration versions")
        }));
    }

    #[test]
    fn deployment_profile_conformance_binding_cycle_normalizes_receipt_digests() {
        let profile =
            load("catalog/security-contracts/v1/deployment-security-profile.implementation.json");
        let binding = deployment_profile_binding(&profile).expect("deployment profile binding");
        assert_eq!(
            string_field(&binding, "digest_contract"),
            Some(DEPLOYMENT_PROFILE_BINDING_DIGEST_CONTRACT)
        );
        assert_eq!(binding.get("id"), profile.get("document_id"));
        let expected_version = profile["document_version"]
            .as_u64()
            .expect("document version")
            .to_string();
        assert_eq!(
            string_field(&binding, "version"),
            Some(expected_version.as_str())
        );
        assert_eq!(binding.get("deployment_id"), profile.get("deployment_id"));

        let mut unequal_versions = profile.clone();
        unequal_versions["document_version"] = json!(7);
        unequal_versions["deployment_profile_version"] = json!(99);
        let unequal_binding =
            deployment_profile_binding(&unequal_versions).expect("unequal profile versions");
        assert_eq!(string_field(&unequal_binding, "version"), Some("7"));

        let mut receipt_bound = profile.clone();
        receipt_bound["production_acceptance_receipt_ref"] = json!({
            "artifact_kind": "package-exit-receipt",
            "document_id": "package-exit-receipt:test-root",
            "document_version": 1,
            "content_digest": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "artifact_locator": "catalog/security-contracts/v1/package-exit-receipts/test-root.json"
        });
        let receipt_binding =
            deployment_profile_binding(&receipt_bound).expect("receipt-bound profile");
        assert_eq!(receipt_binding.get("digest"), binding.get("digest"));

        let mut changed_root_digest = receipt_bound.clone();
        changed_root_digest["production_acceptance_receipt_ref"]["content_digest"] =
            json!("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        let changed_root_binding =
            deployment_profile_binding(&changed_root_digest).expect("changed root digest");
        assert_eq!(changed_root_binding.get("digest"), binding.get("digest"));

        let guard = json!({
            "guard_id": "durable-postgresql",
            "control_ids": ["SB-OPS-01"],
            "receipt_ref": {
                "artifact_kind": "package-exit-receipt",
                "document_id": "package-exit-receipt:test-guard",
                "document_version": 1,
                "content_digest": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                "artifact_locator": "catalog/security-contracts/v1/package-exit-receipts/test-guard.json"
            },
            "expected_value": runtime_guard_expected_value(
                0,
                "deployment:repository-conformance-fixture"
            )
        });
        let mut guard_bound = profile.clone();
        guard_bound["runtime_guard_evidence"] = json!({
            "mode": "receipt_bound",
            "guards": [guard],
            "runtime_cross_check_required": true
        });
        let guard_binding = deployment_profile_binding(&guard_bound).expect("guard-bound profile");
        let mut changed_guard_digest = guard_bound.clone();
        changed_guard_digest["runtime_guard_evidence"]["guards"][0]["receipt_ref"]
            ["content_digest"] =
            json!("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        let changed_guard_binding =
            deployment_profile_binding(&changed_guard_digest).expect("changed guard digest");
        assert_eq!(
            changed_guard_binding.get("digest"),
            guard_binding.get("digest")
        );

        let mut security_relevant_changes = Vec::new();
        let mut changed = guard_bound.clone();
        changed["runtime_guard_evidence"]["guards"][0]["guard_id"] =
            json!("approved-secret-provider");
        security_relevant_changes.push(changed);
        let mut changed = guard_bound.clone();
        changed["runtime_guard_evidence"]["guards"][0]["control_ids"] = json!(["SB-OPS-02"]);
        security_relevant_changes.push(changed);
        let mut changed = guard_bound.clone();
        changed["runtime_guard_evidence"]["guards"][0]["expected_value"]
            ["storage_binding_digest"] =
            json!("sha256:abababababababababababababababababababababababababababababababab");
        security_relevant_changes.push(changed);
        let mut changed = guard_bound.clone();
        changed["runtime_guard_evidence"]["guards"][0]["receipt_ref"]["document_id"] =
            json!("package-exit-receipt:test-guard-other");
        security_relevant_changes.push(changed);
        let mut changed = guard_bound.clone();
        changed["runtime_guard_evidence"]["guards"][0]["receipt_ref"]["document_version"] =
            json!(2);
        security_relevant_changes.push(changed);
        let mut changed = guard_bound.clone();
        changed["runtime_guard_evidence"]["guards"][0]["receipt_ref"]["artifact_locator"] =
            json!("catalog/security-contracts/v1/package-exit-receipts/test-guard-other.json");
        security_relevant_changes.push(changed);
        for changed in security_relevant_changes {
            let changed_binding =
                deployment_profile_binding(&changed).expect("changed guard binding");
            assert_ne!(changed_binding.get("digest"), guard_binding.get("digest"));
        }

        let mut overlay_bound = profile.clone();
        overlay_bound["migration_overlay"] = json!({
            "overlay_id": "migration-overlay:test",
            "overlay_version": 1,
            "security_profile": "test",
            "authority_source": "legacy_auth_mode",
            "legacy_selector_present": true,
            "provider_registry_present": true,
            "retirement_deadline": "2026-08-01T00:00:00Z",
            "conflict_telemetry_name": "security.migration.conflict",
            "grants_authority": false,
            "live_execution_allowed": false,
            "zero_consumer_receipt_ref": {
                "artifact_kind": "package-exit-receipt",
                "document_id": "package-exit-receipt:zero-consumer",
                "document_version": 1,
                "content_digest": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                "artifact_locator": "catalog/security-contracts/v1/package-exit-receipts/zero-consumer.json"
            }
        });
        let overlay_binding =
            deployment_profile_binding(&overlay_bound).expect("overlay-bound profile");
        let mut changed_overlay_digest = overlay_bound.clone();
        changed_overlay_digest["migration_overlay"]["zero_consumer_receipt_ref"]
            ["content_digest"] =
            json!("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        let changed_overlay_digest_binding =
            deployment_profile_binding(&changed_overlay_digest).expect("changed overlay digest");
        assert_eq!(
            changed_overlay_digest_binding.get("digest"),
            overlay_binding.get("digest")
        );
        for (field, replacement) in [
            (
                "document_id",
                json!("package-exit-receipt:zero-consumer-other"),
            ),
            ("document_version", json!(2)),
            (
                "artifact_locator",
                json!(
                    "catalog/security-contracts/v1/package-exit-receipts/zero-consumer-other.json"
                ),
            ),
        ] {
            let mut changed = overlay_bound.clone();
            changed["migration_overlay"]["zero_consumer_receipt_ref"][field] = replacement;
            let changed_binding =
                deployment_profile_binding(&changed).expect("changed overlay binding");
            assert_ne!(changed_binding.get("digest"), overlay_binding.get("digest"));
        }

        let mut tampered = profile;
        tampered["policy_version"] = json!(999);
        let tampered_binding = deployment_profile_binding(&tampered).expect("tampered profile");
        assert_ne!(tampered_binding.get("digest"), binding.get("digest"));
    }

    #[test]
    fn trust_registry_rejects_duplicate_revoked_and_tombstoned_key_reuse() {
        let mut registry = trust_registry_fixture();
        let duplicate = registry["keys"][0].clone();
        registry["keys"]
            .as_array_mut()
            .expect("keys")
            .push(duplicate);
        registry["keys"][0]["lifecycle"] = json!("revoked");
        registry["keys"][0]["revoked_at"] = Value::Null;
        registry["key_tombstones"] = json!([{
            "key_id": "conformance-key:test-primary",
            "signer_identity": "signer:test",
            "algorithm": "ed25519",
            "public_key_fingerprint": "sha256:72cd6e8422c407fb6d098690f1130b7ded7ec2f7f5e1d30bd9d521f015363793",
            "terminal_state": "revoked",
            "terminated_at": "2026-07-15T00:00:00Z",
            "signatures_valid_before": null,
            "subsequent_revocation": null,
            "reason": "Test terminal revocation record",
            "superseded_by_key_id": null,
            "trust_policy_version": 1
        }]);

        let mut errors = Vec::new();
        validate_conformance_trust_root_registry_at(&registry, closure_test_now(), &mut errors);
        assert!(errors
            .iter()
            .any(|error| error.contains("duplicate key_id conformance-key:test-primary")));
        assert!(errors
            .iter()
            .any(|error| error.contains("live key lifecycle must be active or overlap")));
        assert!(errors.iter().any(|error| {
            error.contains("tombstoned key_id conformance-key:test-primary is reused")
        }));
    }

    #[test]
    fn trust_registry_rejects_invalid_key_window_and_scope_escape() {
        let mut registry = trust_registry_fixture();
        registry["keys"][0]["valid_from"] = json!("2026-07-18T00:00:00Z");
        registry["keys"][0]["valid_until"] = json!("2026-07-17T00:00:00Z");
        registry["keys"][0]["deployment_ids"] = json!(["deployment:outside"]);
        registry["keys"][0]["public_key_base64"] =
            json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        let mut errors = Vec::new();
        validate_conformance_trust_root_registry_at(&registry, closure_test_now(), &mut errors);
        assert!(errors
            .iter()
            .any(|error| error.contains("valid_from must be before valid_until")));
        assert!(errors
            .iter()
            .any(|error| error.contains("outside registry applicability")));
        assert!(errors
            .iter()
            .any(|error| error.contains("Ed25519 public key cannot be all zeroes")));
    }

    #[test]
    fn trust_registry_compares_supersession_times_as_instants() {
        let mut registry = trust_registry_fixture();
        let mut predecessor = registry["keys"][0].clone();
        predecessor["key_id"] = json!("conformance-key:test-predecessor");
        predecessor["public_key_base64"] = json!("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=");
        predecessor["public_key_fingerprint"] =
            json!("sha256:75877bb41d393b5fb8455ce60ecd8dda001d06316496b14dfa7f895656eeca4a");
        predecessor["valid_from"] = json!("2026-07-16T00:30:00+02:00");
        predecessor["lifecycle"] = json!("overlap");
        registry["keys"][0]["valid_from"] = json!("2026-07-15T23:00:00Z");
        registry["keys"][0]["supersedes_key_id"] = json!("conformance-key:test-predecessor");
        registry["keys"]
            .as_array_mut()
            .expect("keys")
            .push(predecessor);

        let mut errors = Vec::new();
        validate_conformance_trust_root_registry_at(&registry, closure_test_now(), &mut errors);
        assert!(
            !errors
                .iter()
                .any(|error| error.contains("must have a later valid_from")),
            "{}",
            errors.join("\n")
        );

        let mut registry = trust_registry_fixture();
        let mut predecessor = registry["keys"][0].clone();
        predecessor["key_id"] = json!("conformance-key:test-predecessor");
        predecessor["public_key_base64"] = json!("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=");
        predecessor["public_key_fingerprint"] =
            json!("sha256:75877bb41d393b5fb8455ce60ecd8dda001d06316496b14dfa7f895656eeca4a");
        predecessor["valid_from"] = json!("2026-07-16T00:00:00-10:00");
        predecessor["lifecycle"] = json!("overlap");
        registry["keys"][0]["valid_from"] = json!("2026-07-16T05:00:00+10:00");
        registry["keys"][0]["supersedes_key_id"] = json!("conformance-key:test-predecessor");
        registry["keys"]
            .as_array_mut()
            .expect("keys")
            .push(predecessor);

        let mut errors = Vec::new();
        validate_conformance_trust_root_registry_at(&registry, closure_test_now(), &mut errors);
        assert!(errors
            .iter()
            .any(|error| error.contains("must have a later valid_from")));
    }

    #[test]
    fn trust_registry_requires_single_active_successor_from_overlap() {
        let rotation = || {
            let mut registry = trust_registry_fixture();
            let mut predecessor = registry["keys"][0].clone();
            predecessor["key_id"] = json!("conformance-key:test-predecessor");
            predecessor["public_key_base64"] =
                json!("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=");
            predecessor["public_key_fingerprint"] =
                json!("sha256:75877bb41d393b5fb8455ce60ecd8dda001d06316496b14dfa7f895656eeca4a");
            predecessor["valid_from"] = json!("2026-07-15T00:00:00Z");
            predecessor["lifecycle"] = json!("overlap");
            registry["keys"][0]["valid_from"] = json!("2026-07-15T01:00:00Z");
            registry["keys"][0]["supersedes_key_id"] = json!("conformance-key:test-predecessor");
            registry["keys"]
                .as_array_mut()
                .expect("keys")
                .push(predecessor);
            registry
        };

        let mut non_active_successor = rotation();
        non_active_successor["keys"][0]["lifecycle"] = json!("overlap");
        let mut errors = Vec::new();
        validate_conformance_trust_root_registry_at(
            &non_active_successor,
            closure_test_now(),
            &mut errors,
        );
        assert!(errors.iter().any(|error| {
            error.contains("live superseding key conformance-key:test-primary must be active")
        }));

        let mut active_predecessor = rotation();
        active_predecessor["keys"][1]["lifecycle"] = json!("active");
        let mut errors = Vec::new();
        validate_conformance_trust_root_registry_at(
            &active_predecessor,
            closure_test_now(),
            &mut errors,
        );
        assert!(errors.iter().any(|error| {
            error.contains(
                "live predecessor conformance-key:test-predecessor of conformance-key:test-primary must be overlap",
            )
        }));

        let mut multiple_successors = rotation();
        let mut second_successor = multiple_successors["keys"][0].clone();
        second_successor["key_id"] = json!("conformance-key:test-tertiary");
        second_successor["public_key_base64"] =
            json!("AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=");
        second_successor["public_key_fingerprint"] = json!(raw_sha256_digest(&[3_u8; 32]));
        second_successor["valid_from"] = json!("2026-07-15T02:00:00Z");
        multiple_successors["keys"]
            .as_array_mut()
            .expect("keys")
            .push(second_successor);
        let mut errors = Vec::new();
        validate_conformance_trust_root_registry_at(
            &multiple_successors,
            closure_test_now(),
            &mut errors,
        );
        assert!(errors.iter().any(|error| {
            error.contains(
                "live predecessor conformance-key:test-predecessor has multiple successors",
            )
        }));
    }

    #[test]
    fn trust_registry_fingerprint_hashes_decoded_raw_key_bytes() {
        let encoded = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
        let decoded = decode_canonical_ed25519_public_key(encoded).expect("canonical key");
        assert_eq!(
            raw_sha256_digest(&decoded),
            "sha256:72cd6e8422c407fb6d098690f1130b7ded7ec2f7f5e1d30bd9d521f015363793"
        );
        assert_ne!(
            raw_sha256_digest(encoded.as_bytes()),
            raw_sha256_digest(&decoded)
        );
    }

    #[test]
    fn trust_registry_accepts_valid_bounded_rotation_lineage() {
        let lineage = valid_rotation_lineage();
        let mut errors = Vec::new();
        validate_conformance_trust_root_registry_lineage_at(
            &lineage,
            closure_test_now(),
            &mut errors,
        );
        assert!(errors.is_empty(), "{}", errors.join("\n"));
    }

    #[test]
    fn trust_registry_rejects_wrong_link_policy_and_effective_time() {
        let mut wrong_link = valid_rotation_lineage();
        wrong_link[1].value["predecessor_registry_ref"]["content_digest"] =
            json!("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        let mut errors = Vec::new();
        validate_conformance_trust_root_registry_lineage_at(
            &wrong_link,
            closure_test_now(),
            &mut errors,
        );
        assert!(errors
            .iter()
            .any(|error| error.contains("content_digest does not exactly bind")));

        let mut wrong_policy = valid_rotation_lineage();
        wrong_policy[1].value["trust_policy_version"] = json!(1);
        let mut errors = Vec::new();
        validate_conformance_trust_root_registry_lineage_at(
            &wrong_policy,
            closure_test_now(),
            &mut errors,
        );
        assert!(errors
            .iter()
            .any(|error| error.contains("authority change requires trust_policy_version 2")));

        let mut wrong_effective = valid_rotation_lineage();
        wrong_effective[1].value["lifecycle"]["effective_at"] = json!("2026-07-14T23:00:00-01:00");
        let mut errors = Vec::new();
        validate_conformance_trust_root_registry_lineage_at(
            &wrong_effective,
            closure_test_now(),
            &mut errors,
        );
        assert!(errors
            .iter()
            .any(|error| error.contains("effective_at must strictly increase")));
    }

    #[test]
    fn trust_registry_rejects_dropped_or_mutated_tombstones() {
        let mut dropped = valid_three_version_lineage();
        dropped[2].value["key_tombstones"] = json!([]);
        let mut errors = Vec::new();
        validate_conformance_trust_root_registry_lineage_at(
            &dropped,
            closure_test_now(),
            &mut errors,
        );
        assert!(errors
            .iter()
            .any(|error| error.contains("predecessor tombstone") && error.contains("dropped")));

        let mut mutated = valid_three_version_lineage();
        mutated[2].value["key_tombstones"][0]["reason"] =
            json!("Mutated terminal record that must be rejected");
        let mut errors = Vec::new();
        validate_conformance_trust_root_registry_lineage_at(
            &mutated,
            closure_test_now(),
            &mut errors,
        );
        assert!(errors.iter().any(|error| error.contains("mutates outside")));
    }

    #[test]
    fn trust_registry_rejects_key_disappearance_and_resurrection() {
        let mut disappeared = valid_three_version_lineage();
        disappeared[2].value["keys"] = json!([]);
        let mut errors = Vec::new();
        validate_conformance_trust_root_registry_lineage_at(
            &disappeared,
            closure_test_now(),
            &mut errors,
        );
        assert!(errors
            .iter()
            .any(|error| error.contains("disappears without an immediate tombstone")));

        let mut resurrected = valid_three_version_lineage();
        let retired_key = resurrected[0].value["keys"][0].clone();
        resurrected[2]
            .value
            .get_mut("keys")
            .and_then(Value::as_array_mut)
            .expect("keys")
            .push(retired_key);
        let mut errors = Vec::new();
        validate_conformance_trust_root_registry_lineage_at(
            &resurrected,
            closure_test_now(),
            &mut errors,
        );
        assert!(errors
            .iter()
            .any(|error| error.contains("resurrected as a live key")));
    }

    #[test]
    fn trust_registry_rejects_key_id_and_material_relabeling() {
        let mut changed_id_material = valid_three_version_lineage();
        changed_id_material[2].value["keys"][0]["public_key_base64"] =
            json!("AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=");
        changed_id_material[2].value["keys"][0]["public_key_fingerprint"] =
            json!("sha256:648aa5c579fb30f38af744d97d6ec840c7a91277a499a0d780f3e7314eca090b");
        let mut errors = Vec::new();
        validate_conformance_trust_root_registry_lineage_at(
            &changed_id_material,
            closure_test_now(),
            &mut errors,
        );
        assert!(errors
            .iter()
            .any(|error| error.contains("historical key_id") && error.contains("changes")));

        let mut relabeled_material = valid_three_version_lineage();
        let mut alias = relabeled_material[2].value["keys"][0].clone();
        alias["key_id"] = json!("conformance-key:test-alias");
        alias["supersedes_key_id"] = Value::Null;
        relabeled_material[2]
            .value
            .get_mut("keys")
            .and_then(Value::as_array_mut)
            .expect("keys")
            .push(alias);
        let mut errors = Vec::new();
        validate_conformance_trust_root_registry_lineage_at(
            &relabeled_material,
            closure_test_now(),
            &mut errors,
        );
        assert!(errors.iter().any(|error| {
            error.contains("historical public-key fingerprint") && error.contains("relabeled")
        }));
    }

    #[test]
    fn trust_registry_allows_one_way_subsequent_revocation_overlay() {
        let mut lineage = valid_three_version_lineage();
        lineage[2].value["trust_policy_version"] = json!(3);
        lineage[2].value["key_tombstones"][0]["subsequent_revocation"] = json!({
            "revoked_at": "2026-07-15T17:00:00Z",
            "reason": "Emergency revocation after later compromise",
            "trust_policy_version": 3
        });
        let mut errors = Vec::new();
        validate_conformance_trust_root_registry_lineage_at(
            &lineage,
            closure_test_now(),
            &mut errors,
        );
        assert!(errors.is_empty(), "{}", errors.join("\n"));

        let mut reversed = lineage;
        let mut fourth = next_unchanged_registry(&reversed[2], 4, "2026-07-15T20:00:00Z");
        fourth.value["key_tombstones"][0]["subsequent_revocation"] = Value::Null;
        reversed.push(fourth);
        let mut errors = Vec::new();
        validate_conformance_trust_root_registry_lineage_at(
            &reversed,
            closure_test_now(),
            &mut errors,
        );
        assert!(errors.iter().any(|error| error.contains("mutates outside")));
    }

    #[test]
    fn trust_registry_enforces_collection_and_lineage_bounds() {
        let mut registry = trust_registry_fixture();
        let key_template = registry["keys"][0].clone();
        registry["keys"] = Value::Array(
            (0..=MAX_TRUST_REGISTRY_KEYS)
                .map(|_| key_template.clone())
                .collect(),
        );
        registry["applicability"]["deployment_ids"] = Value::Array(
            (0..=MAX_TRUST_REGISTRY_SCOPE_ITEMS)
                .map(|index| json!(format!("deployment:test-{index}")))
                .collect(),
        );
        let mut errors = Vec::new();
        validate_conformance_trust_root_registry_at(&registry, closure_test_now(), &mut errors);
        assert!(errors
            .iter()
            .any(|error| error.contains("keys exceeds the maximum")));
        assert!(errors
            .iter()
            .any(|error| error.contains("deployment_ids exceeds the maximum of 256 items")));

        let mut scoped = trust_registry_fixture();
        scoped["applicability"]["security_profiles"] =
            Value::Array(vec![json!("test"); MAX_TRUST_REGISTRY_PROFILES + 1]);
        scoped["keys"][0]["allowed_purposes"] = Value::Array(vec![
            json!("conformance_bundle");
            MAX_TRUST_KEY_PURPOSES + 1
        ]);
        scoped["keys"][0]["allowed_evidence_tiers"] = Value::Array(vec![
            json!("repository_local");
            MAX_TRUST_KEY_EVIDENCE_TIERS
                + 1
        ]);
        scoped["keys"][0]["allowed_package_ids"] =
            Value::Array(vec![json!("SB-0"); MAX_TRUST_KEY_PACKAGES + 1]);
        let over_scope = (0..=MAX_TRUST_REGISTRY_SCOPE_ITEMS)
            .map(|index| json!(format!("deployment:test-{index}")))
            .collect::<Vec<_>>();
        scoped["applicability"]["deployment_ids"] = Value::Array(over_scope.clone());
        scoped["keys"][0]["deployment_ids"] = Value::Array(over_scope);
        let over_domains = (0..=MAX_TRUST_REGISTRY_SCOPE_ITEMS)
            .map(|index| json!(format!("trust-domain:test-{index}")))
            .collect::<Vec<_>>();
        scoped["applicability"]["trust_domain_ids"] = Value::Array(over_domains.clone());
        scoped["keys"][0]["trust_domain_ids"] = Value::Array(over_domains);
        let mut errors = Vec::new();
        validate_conformance_trust_root_registry_at(&scoped, closure_test_now(), &mut errors);
        for expected in [
            "security_profiles exceeds the maximum of 3 items",
            "allowed_purposes exceeds the maximum of 2 items",
            "allowed_evidence_tiers exceeds the maximum of 3 items",
            "allowed_package_ids exceeds the maximum of 10 items",
            "deployment_ids exceeds the maximum of 256 items",
            "trust_domain_ids exceeds the maximum of 256 items",
        ] {
            assert!(
                errors.iter().any(|error| error.contains(expected)),
                "missing {expected}: {}",
                errors.join("\n")
            );
        }

        let mut oversized_lineage = Vec::new();
        for version in 1..=MAX_TRUST_REGISTRY_LINEAGE + 1 {
            let mut value = trust_registry_fixture();
            value["document_version"] = json!(version);
            value["lifecycle"]["effective_at"] = json!(format!("2026-07-15T00:{version:02}:00Z"));
            oversized_lineage.push(LoadedTrustRegistry {
                locator: format!("test/registry-v{version}.json"),
                value,
                digest: format!("sha256:{version:064x}"),
            });
        }
        let mut errors = Vec::new();
        validate_conformance_trust_root_registry_lineage_at(
            &oversized_lineage,
            closure_test_now(),
            &mut errors,
        );
        assert!(errors
            .iter()
            .any(|error| error.contains("lineage exceeds 16 documents")));
    }

    #[test]
    fn trust_registry_collection_bounds_accept_exact_limit_and_reject_next_item() {
        for maximum in [
            MAX_TRUST_REGISTRY_KEYS,
            MAX_TRUST_REGISTRY_TOMBSTONES,
            MAX_TRUST_REGISTRY_SCOPE_ITEMS,
            MAX_TRUST_REGISTRY_PROFILES,
            MAX_TRUST_KEY_PURPOSES,
            MAX_TRUST_KEY_EVIDENCE_TIERS,
            MAX_TRUST_KEY_PACKAGES,
        ] {
            let at_limit = json!({"items": vec![Value::Null; maximum]});
            let mut errors = Vec::new();
            enforce_array_bound(&at_limit, "items", maximum, "test:bound", &mut errors);
            assert!(errors.is_empty(), "{}", errors.join("\n"));

            let over_limit = json!({"items": vec![Value::Null; maximum + 1]});
            let mut errors = Vec::new();
            enforce_array_bound(&over_limit, "items", maximum, "test:bound", &mut errors);
            assert_eq!(errors.len(), 1);
            assert!(errors[0].contains(&format!("maximum of {maximum} items")));
        }
    }

    #[test]
    fn trust_registry_lineage_errors_are_deterministic() {
        let mut lineage = valid_three_version_lineage();
        lineage[2].value["keys"] = json!([]);
        lineage[2].value["key_tombstones"][0]["reason"] = json!("Mutated deterministic error");
        let mut first = Vec::new();
        let mut second = Vec::new();
        validate_conformance_trust_root_registry_lineage_at(
            &lineage,
            closure_test_now(),
            &mut first,
        );
        validate_conformance_trust_root_registry_lineage_at(
            &lineage,
            closure_test_now(),
            &mut second,
        );
        first.sort();
        first.dedup();
        second.sort();
        second.dedup();
        assert_eq!(first, second);
    }

    #[test]
    fn trust_registry_rejects_overlap_reactivation_and_overlap_only_production() {
        let mut lineage = valid_three_version_lineage();
        lineage[1].value["keys"][0]["lifecycle"] = json!("overlap");
        lineage[2].value["keys"][0]["lifecycle"] = json!("active");
        lineage[2].value["trust_policy_version"] = json!(3);
        let mut errors = Vec::new();
        validate_conformance_trust_root_registry_lineage_at(
            &lineage,
            closure_test_now(),
            &mut errors,
        );
        assert!(errors
            .iter()
            .any(|error| error.contains("lifecycle cannot transition from overlap to active")));

        let mut registry = trust_registry_fixture();
        registry["acceptance_status"] = json!("production_accepted");
        registry["production_accepted"] = json!(true);
        registry["lifecycle"]["state"] = json!("active");
        registry["keys"][0]["lifecycle"] = json!("overlap");
        let mut errors = Vec::new();
        validate_conformance_trust_root_registry_at(&registry, closure_test_now(), &mut errors);
        assert!(errors
            .iter()
            .any(|error| error.contains("overlap-only authority is forbidden")));
    }

    #[test]
    fn credential_reference_digest_uses_its_schema_field() {
        let locator = "docs/architecture/platform-security-boundary.md";
        let bytes = fs::read(root().join(locator)).expect("source artifact");
        let reference = json!({
            "reference_digest": format!("sha256:{:x}", Sha256::digest(bytes)),
            "artifact_locator": locator
        });
        let mut errors = Vec::new();
        validate_content_reference(
            &root(),
            reference.as_object().expect("reference object"),
            locator,
            "credential-ref-test",
            &mut errors,
        );
        assert!(errors.is_empty(), "{}", errors.join("\n"));
    }

    #[test]
    fn conformance_errors_are_deterministic_and_sorted_at_the_gate() {
        let first = validate_repository(&root()).expect("first validation");
        let second = validate_repository(&root()).expect("second validation");
        assert_eq!(first, second);
        assert!(first.windows(2).all(|pair| pair[0] <= pair[1]));
    }

    fn closure_context_fixture() -> Value {
        let deployment_profile = load_deployment_profile_binding(&root())
            .expect("checked-in deployment profile binding");
        let (policy_versions, configuration_versions) =
            load_deployment_profile_version_bindings(&root())
                .expect("checked-in profile version bindings");
        json!({
            "source_revision": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "artifact_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "deployment_profile": deployment_profile,
            "policy_versions": policy_versions,
            "configuration_versions": configuration_versions,
            "provider_versions": [{"id": "provider:test", "version": "1", "digest": "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}],
            "adapter_versions": [{"id": "adapter:test", "version": "1", "digest": "sha256:6666666666666666666666666666666666666666666666666666666666666666"}],
            "security_limit_profile": {"id": "security-limit-profile:test", "version": "1", "digest": "sha256:7777777777777777777777777777777777777777777777777777777777777777"}
        })
    }

    fn refresh_receipt_digest_projections(receipt: &mut LoadedDocument) {
        receipt.value["input_digests"] = json!(receipt_input_digest_projection(&receipt.value));
        receipt.value["output_digests"] = json!(receipt_output_digest_projection(&receipt.value));
    }

    fn authoritative_candidate_fixture() -> (Value, LoadedDocument, LoadedDocument) {
        let ledger = json!({
            "document_id": "control-trace:test",
            "document_version": 1,
            "ledger_id": "control-trace:test",
            "ledger_version": "1.0.0",
            "controls": [{
                "control_id": "SB-TEST-01",
                "owning_work_package": "SB-0",
                "waivable": false
            }],
            "traces": [{
                "trace_id": "TRACE-TEST-AC-001",
                "control_id": "SB-TEST-01",
                "acceptance_case_id": "AC-001",
                "owning_work_package": "SB-0",
                "trace_lifecycle": "active",
                "applicability_expression": {
                    "implementation": {"operator": "always"},
                    "deployment": {"operator": "always"}
                },
                "evidence_instance_dimensions": {
                    "implementation": [],
                    "deployment": []
                },
                "minimum_evidence_tier": {
                    "implementation": {"name": "repository_local", "rank": 1},
                    "deployment": {"name": "repository_local", "rank": 1}
                }
            }]
        });
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let closure_context = closure_context_fixture();
        let bundle = LoadedDocument {
            label: "test:authoritative-bundle".to_string(),
            digest: digest.to_string(),
            value: json!({
                "document_version": 1,
                "bundle_id": "bundle:authoritative",
                "evidence_instance_id": "evidence:authoritative",
                "applicability_instance_id": "applicability:fixture",
                "acceptance_status": "production_accepted",
                "production_accepted": true,
                "trace_id": "TRACE-TEST-AC-001",
                "control_id": "SB-TEST-01",
                "acceptance_case_id": "AC-001",
                "source_revision": closure_context["source_revision"].clone(),
                "artifact": {"digest": closure_context["artifact_digest"].clone()},
                "bindings": {
                    "deployment_profile": closure_context["deployment_profile"].clone(),
                    "policy_versions": closure_context["policy_versions"].clone(),
                    "configuration_versions": closure_context["configuration_versions"].clone(),
                    "provider_versions": closure_context["provider_versions"].clone(),
                    "adapter_versions": closure_context["adapter_versions"].clone(),
                    "security_limit_profile": closure_context["security_limit_profile"].clone()
                },
                "evaluated_applicability": {
                    "implementation": {"applicable": true, "dimensions": []},
                    "deployment": {"applicable": true, "dimensions": []}
                },
                "normalized_result": "pass",
                "provenance": {
                    "evidence_tier": {"name": "repository_local", "rank": 1}
                },
                "evidence_lifecycle": "accepted",
                "produced_at": "2026-07-15T00:00:00Z",
                "verified_at": "2026-07-15T00:05:00Z",
                "accepted_at": "2026-07-15T00:10:00Z",
                "expires_at": "2026-07-17T00:00:00Z",
                "supersedes_evidence_instance_id": null,
                "supersedes_evidence_ref": null
            }),
        };
        let ledger_bytes = fs::read(
            root().join("catalog/security-contracts/v1/control-trace.implementation.json"),
        )
        .expect("ledger bytes");
        let mut receipt = LoadedDocument {
            label: "test:authoritative-receipt".to_string(),
            digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            value: json!({
                "document_version": 1,
                "receipt_id": "package-exit-receipt:authoritative-candidate",
                "acceptance_status": "production_candidate",
                "production_accepted": false,
                "package_id": "SB-0",
                "ledger_binding": {
                    "artifact_kind": "control-trace",
                    "document_id": "control-trace:test",
                    "document_version": 1,
                    "artifact_locator": "catalog/security-contracts/v1/control-trace.implementation.json",
                    "ledger_id": "control-trace:test",
                    "ledger_version": "1.0.0",
                    "ledger_digest": format!("sha256:{:x}", Sha256::digest(ledger_bytes))
                },
                "evaluated_sets": {
                    "trace_ids": ["TRACE-TEST-AC-001"],
                    "control_ids": ["SB-TEST-01"],
                    "acceptance_case_ids": ["AC-001"],
                    "evidence_bindings": [{
                        "evidence_instance_id": "evidence:authoritative",
                        "bundle_id": "bundle:authoritative",
                        "document_version": 1,
                        "artifact_kind": "conformance-bundle",
                        "artifact_locator": "test:authoritative-bundle",
                        "bundle_digest": digest
                    }]
                },
                "applicability_instances": [{
                    "instance_id": "applicability:fixture",
                    "implementation_dimensions": [],
                    "deployment_dimensions": []
                }],
                "closure_context": closure_context,
                "prerequisite_receipts": [],
                "input_digests": [],
                "output_digests": [],
                "evidence_tier": {"name": "repository_local", "rank": 1},
                "waivers": [],
                "retirement_closure": null,
                "result": "blocked",
                "receipt_lifecycle": "produced",
                "created_at": "2026-07-15T01:00:00Z",
                "expires_at": "2026-07-17T00:00:00Z",
                "supersedes_receipt_id": null,
                "supersedes_receipt_ref": null
            }),
        };
        refresh_receipt_digest_projections(&mut receipt);
        (ledger, bundle, receipt)
    }

    fn closure_test_now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-07-16T00:00:00Z")
            .expect("fixed timestamp")
            .with_timezone(&Utc)
    }

    fn trust_registry_fixture() -> Value {
        json!({
            "$schema": "https://ryuki.io/schemas/security-contracts/v1/conformance-trust-root-registry.schema.json",
            "schema_version": "1.0.0",
            "contract_kind": "conformance-trust-root-registry",
            "document_id": "conformance-trust-root-registry:test",
            "document_version": 1,
            "predecessor_registry_ref": null,
            "acceptance_status": "production_candidate",
            "production_accepted": false,
            "lifecycle": {
                "state": "candidate",
                "effective_at": "2026-07-15T00:00:00Z"
            },
            "applicability": {
                "evaluation_scope": "deployment",
                "security_profiles": ["test"],
                "deployment_ids": ["deployment:test"],
                "trust_domain_ids": ["trust-domain:test"]
            },
            "trust_policy_version": 1,
            "canonicalization_profiles": ["ryuki-canonical-json-v1"],
            "signature_algorithms": ["ed25519"],
            "keys": [{
                "key_id": "conformance-key:test-primary",
                "signer_identity": "signer:test",
                "algorithm": "ed25519",
                "public_key_base64": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
                "public_key_fingerprint": "sha256:72cd6e8422c407fb6d098690f1130b7ded7ec2f7f5e1d30bd9d521f015363793",
                "allowed_purposes": ["conformance_bundle", "package_exit_receipt"],
                "allowed_evidence_tiers": ["repository_local"],
                "allowed_package_ids": ["SB-0"],
                "deployment_ids": ["deployment:test"],
                "trust_domain_ids": ["trust-domain:test"],
                "valid_from": "2026-07-15T00:00:00Z",
                "valid_until": "2026-07-17T00:00:00Z",
                "lifecycle": "active",
                "supersedes_key_id": null
            }],
            "key_tombstones": []
        })
    }

    fn valid_rotation_lineage() -> Vec<LoadedTrustRegistry> {
        let root = LoadedTrustRegistry {
            locator: "test/registry-v1.json".to_string(),
            value: trust_registry_fixture(),
            digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
        };
        let mut rotated = root.value.clone();
        rotated["document_version"] = json!(2);
        rotated["predecessor_registry_ref"] = json!({
            "artifact_kind": "conformance-trust-root-registry",
            "document_id": "conformance-trust-root-registry:test",
            "document_version": 1,
            "content_digest": root.digest.clone(),
            "artifact_locator": root.locator.clone()
        });
        rotated["lifecycle"]["effective_at"] = json!("2026-07-15T12:00:00Z");
        rotated["trust_policy_version"] = json!(2);
        let mut successor = rotated["keys"][0].clone();
        successor["key_id"] = json!("conformance-key:test-secondary");
        successor["public_key_base64"] = json!("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=");
        successor["public_key_fingerprint"] =
            json!("sha256:75877bb41d393b5fb8455ce60ecd8dda001d06316496b14dfa7f895656eeca4a");
        successor["valid_from"] = json!("2026-07-15T12:00:01Z");
        successor["supersedes_key_id"] = json!("conformance-key:test-primary");
        rotated["keys"] = json!([successor]);
        rotated["key_tombstones"] = json!([{
            "key_id": "conformance-key:test-primary",
            "signer_identity": "signer:test",
            "algorithm": "ed25519",
            "public_key_fingerprint": "sha256:72cd6e8422c407fb6d098690f1130b7ded7ec2f7f5e1d30bd9d521f015363793",
            "terminal_state": "retired",
            "terminated_at": "2026-07-15T12:00:00Z",
            "signatures_valid_before": "2026-07-15T12:00:00Z",
            "subsequent_revocation": null,
            "reason": "Routine rotation of the primary test key",
            "superseded_by_key_id": "conformance-key:test-secondary",
            "trust_policy_version": 2
        }]);
        vec![
            root,
            LoadedTrustRegistry {
                locator: "test/registry-v2.json".to_string(),
                value: rotated,
                digest: "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                    .to_string(),
            },
        ]
    }

    fn valid_three_version_lineage() -> Vec<LoadedTrustRegistry> {
        let mut lineage = valid_rotation_lineage();
        let third = next_unchanged_registry(&lineage[1], 3, "2026-07-15T18:00:00Z");
        lineage.push(third);
        lineage
    }

    fn next_unchanged_registry(
        previous: &LoadedTrustRegistry,
        version: u64,
        effective_at: &str,
    ) -> LoadedTrustRegistry {
        let mut value = previous.value.clone();
        value["document_version"] = json!(version);
        value["predecessor_registry_ref"] = json!({
            "artifact_kind": "conformance-trust-root-registry",
            "document_id": previous.value["document_id"],
            "document_version": previous.value["document_version"],
            "content_digest": previous.digest.clone(),
            "artifact_locator": previous.locator.clone()
        });
        value["lifecycle"]["effective_at"] = json!(effective_at);
        LoadedTrustRegistry {
            locator: format!("test/registry-v{version}.json"),
            value,
            digest: format!("sha256:{version:064x}"),
        }
    }

    fn successor_bundle(
        predecessor: &LoadedDocument,
        bundle_id: &str,
        evidence_id: &str,
        digest: &str,
    ) -> LoadedDocument {
        let mut successor = predecessor.clone();
        successor.label = format!("test:{bundle_id}");
        successor.digest = digest.to_string();
        successor.value["bundle_id"] = json!(bundle_id);
        successor.value["evidence_instance_id"] = json!(evidence_id);
        successor.value["document_version"] = json!(
            predecessor
                .value
                .get("document_version")
                .and_then(Value::as_u64)
                .expect("predecessor document version")
                + 1
        );
        successor.value["supersedes_evidence_instance_id"] =
            predecessor.value["evidence_instance_id"].clone();
        successor.value["supersedes_evidence_ref"] = json!({
            "artifact_kind": "conformance-bundle",
            "bundle_id": predecessor.value["bundle_id"].clone(),
            "document_version": predecessor.value["document_version"].clone(),
            "artifact_locator": predecessor.label.clone(),
            "evidence_instance_id": predecessor.value["evidence_instance_id"].clone(),
            "bundle_digest": predecessor.digest.clone()
        });
        successor
    }

    fn successor_receipt(
        predecessor: &LoadedDocument,
        receipt_id: &str,
        digest: &str,
    ) -> LoadedDocument {
        let mut successor = predecessor.clone();
        successor.label = format!("test:{receipt_id}");
        successor.digest = digest.to_string();
        successor.value["receipt_id"] = json!(receipt_id);
        successor.value["document_version"] = json!(
            predecessor
                .value
                .get("document_version")
                .and_then(Value::as_u64)
                .expect("predecessor document version")
                + 1
        );
        successor.value["supersedes_receipt_id"] = predecessor.value["receipt_id"].clone();
        successor.value["supersedes_receipt_ref"] = json!({
            "artifact_kind": "package-exit-receipt",
            "receipt_id": predecessor.value["receipt_id"].clone(),
            "document_version": predecessor.value["document_version"].clone(),
            "artifact_locator": predecessor.label.clone(),
            "package_id": predecessor.value["package_id"].clone(),
            "receipt_digest": predecessor.digest.clone()
        });
        successor
    }

    fn make_bundle_production_accepted(bundle: &mut LoadedDocument) {
        bundle.value["acceptance_status"] = json!("production_accepted");
        bundle.value["production_accepted"] = json!(true);
        bundle.value["normalized_result"] = json!("pass");
        bundle.value["evidence_lifecycle"] = json!("accepted");
        bundle.value["verified_at"] = json!("2026-07-15T00:05:00Z");
        bundle.value["accepted_at"] = json!("2026-07-15T00:10:00Z");
        bundle.value["expires_at"] = json!("2026-07-17T00:00:00Z");
    }

    fn make_receipt_candidate(receipt: &mut LoadedDocument) {
        receipt.value["acceptance_status"] = json!("production_candidate");
        receipt.value["production_accepted"] = json!(false);
        receipt.value["created_at"] = json!("2026-07-15T01:00:00Z");
        receipt.value["expires_at"] = json!("2026-07-17T00:00:00Z");
    }

    fn bundle_for_trace(
        bundle_id: &str,
        evidence_id: &str,
        trace: &Value,
        force_implementation_not_applicable: bool,
    ) -> LoadedDocument {
        let dimensions = |scope: &str| {
            array(&trace["evidence_instance_dimensions"], scope)
                .iter()
                .filter_map(Value::as_str)
                .map(|name| json!({"name": name, "value": "fixture"}))
                .collect::<Vec<_>>()
        };
        let implementation_applicable = !force_implementation_not_applicable;
        LoadedDocument {
            label: format!("test:{bundle_id}"),
            digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            value: json!({
                "document_version": 1,
                "bundle_id": bundle_id,
                "evidence_instance_id": evidence_id,
                "applicability_instance_id": "applicability:fixture",
                "trace_id": trace["trace_id"],
                "control_id": trace["control_id"],
                "acceptance_case_id": trace["acceptance_case_id"],
                "evaluated_applicability": {
                    "implementation": {
                        "applicable": implementation_applicable,
                        "dimensions": if implementation_applicable { dimensions("implementation") } else { Vec::new() }
                    },
                    "deployment": {
                        "applicable": true,
                        "dimensions": dimensions("deployment")
                    }
                },
                "provenance": {"evidence_tier": {"name": "externally_attested", "rank": 3}},
                "produced_at": "2026-01-01T00:00:00Z",
                "verified_at": null,
                "accepted_at": null,
                "expires_at": "2099-01-01T00:00:00Z",
                "supersedes_evidence_instance_id": null,
                "supersedes_evidence_ref": null
            }),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn receipt_for_trace(
        receipt_id: &str,
        digest: &str,
        package: &str,
        trace: &Value,
        evidence_id: &str,
        prerequisite: Option<(&str, &str)>,
        ledger: &Value,
    ) -> LoadedDocument {
        let prerequisites = prerequisite
            .map(|(id, receipt_digest)| {
                vec![json!({
                    "package_id": package,
                    "document_version": 1,
                    "receipt_id": id,
                    "artifact_kind": "package-exit-receipt",
                    "artifact_locator": format!("test:{id}"),
                    "receipt_digest": receipt_digest,
                    "acceptance_status": "implementation_only",
                    "production_accepted": false,
                    "evidence_tier": {"name": "repository_local", "rank": 1},
                    "result": "blocked",
                    "receipt_lifecycle": "produced",
                    "expires_at": "2099-01-01T00:00:00Z"
                })]
            })
            .unwrap_or_default();
        let ledger_bytes = fs::read(
            root().join("catalog/security-contracts/v1/control-trace.implementation.json"),
        )
        .expect("ledger bytes");
        let dimensions = |scope: &str| {
            array(&trace["evidence_instance_dimensions"], scope)
                .iter()
                .filter_map(Value::as_str)
                .map(|name| json!({"name": name, "value": "fixture"}))
                .collect::<Vec<_>>()
        };
        let mut receipt = LoadedDocument {
            label: format!("test:{receipt_id}"),
            digest: digest.to_string(),
            value: json!({
                "document_version": 1,
                "receipt_id": receipt_id,
                "acceptance_status": "implementation_only",
                "production_accepted": false,
                "package_id": package,
                "ledger_binding": {
                    "artifact_kind": "control-trace",
                    "document_id": ledger["document_id"],
                    "document_version": ledger["document_version"],
                    "artifact_locator": "catalog/security-contracts/v1/control-trace.implementation.json",
                    "ledger_id": ledger["ledger_id"],
                    "ledger_version": ledger["ledger_version"],
                    "ledger_digest": format!("sha256:{:x}", Sha256::digest(ledger_bytes))
                },
                "evaluated_sets": {
                    "trace_ids": [trace["trace_id"].clone()],
                    "control_ids": [trace["control_id"].clone()],
                    "acceptance_case_ids": [trace["acceptance_case_id"].clone()],
                    "evidence_bindings": [{
                        "evidence_instance_id": evidence_id,
                        "bundle_id": evidence_id.replacen("evidence", "bundle", 1),
                        "document_version": 1,
                        "artifact_kind": "conformance-bundle",
                        "artifact_locator": format!("test:{}", evidence_id.replacen("evidence", "bundle", 1)),
                        "bundle_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    }]
                },
                "closure_context": closure_context_fixture(),
                "applicability_instances": [{
                    "instance_id": "applicability:fixture",
                    "implementation_dimensions": dimensions("implementation"),
                    "deployment_dimensions": dimensions("deployment")
                }],
                "prerequisite_receipts": prerequisites,
                "input_digests": [],
                "output_digests": [],
                "evidence_tier": {"name": "repository_local", "rank": 1},
                "waivers": [],
                "retirement_closure": null,
                "result": "blocked",
                "receipt_lifecycle": "produced",
                "created_at": "2026-01-01T00:00:00Z",
                "expires_at": "2099-01-01T00:00:00Z",
                "supersedes_receipt_id": null,
                "supersedes_receipt_ref": null
            }),
        };
        refresh_receipt_digest_projections(&mut receipt);
        receipt
    }
}
