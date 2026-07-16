//! Repository-wide validation for the normative production-security contracts.
//!
//! This validator deliberately has no network-capable schema resolver.  The
//! versioned contract set is a closed repository input: a `$ref` that cannot be
//! resolved from its own schema is an error, never an invitation to fetch code
//! or policy from the network.

use jsonschema::{Retrieve, Uri};
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

const SCHEMAS: [(&str, &str); 7] = [
    (
        "action-resource-registry.schema.json",
        "https://ryuki.io/schemas/security-contracts/v1/action-resource-registry.schema.json",
    ),
    (
        "conformance-bundle.schema.json",
        "https://ryuki.io/schemas/security-contracts/v1/conformance-bundle.schema.json",
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
        "security-limit-profile.schema.json",
        "https://ryuki.io/schemas/security-contracts/v1/security-limit-profile.schema.json",
    ),
];

const INSTANCES: [(&str, &str); 5] = [
    (
        "action-resource-registry.implementation.json",
        "action-resource-registry.schema.json",
    ),
    (
        "control-trace.implementation.json",
        "control-trace.schema.json",
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
const CANONICAL_CONTROL_IDS: [&str; 134] = [
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
    // ControlTrace intentionally has no `$schema` instance member because its
    // closed schema predates the other four executable roots.  Its mapping is
    // nevertheless fixed by the exact file inventory above.
    if file_name == "control-trace.implementation.json" {
        return;
    }
    let expected = SCHEMAS
        .iter()
        .find_map(|(name, id)| (*name == schema_name).then_some(*id));
    if instance.get("$schema").and_then(Value::as_str) != expected {
        errors.push(format!(
            "{file_name}: $schema must reference the canonical {schema_name} URI"
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
    let canonical_cases: BTreeSet<String> = (1..=54).map(|n| format!("AC-{n:03}")).collect();

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

    let mut bundle_ids = BTreeSet::new();
    let mut evidence = BTreeMap::new();
    let mut evidence_supersession = BTreeMap::new();
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
        if let Some(target) = bundle
            .get("supersedes_evidence_instance_id")
            .and_then(Value::as_str)
        {
            if target == evidence_id {
                errors.push(format!(
                    "{}: evidence instance {evidence_id} cannot supersede itself",
                    document.label
                ));
            }
            evidence_supersession.insert(evidence_id.to_string(), target.to_string());
        }
    }
    for (source, target) in &evidence_supersession {
        if !evidence.contains_key(target) {
            errors.push(format!(
                "evidence instance {source} supersedes unknown evidence instance {target}"
            ));
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
        receipts,
        errors,
    );
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

#[allow(clippy::too_many_arguments)]
fn validate_receipts(
    ledger: &Value,
    ledger_digest: Option<&str>,
    traces: &BTreeMap<String, &Value>,
    controls: &BTreeMap<String, &Value>,
    evidence: &BTreeMap<String, &LoadedDocument>,
    receipts: &[LoadedDocument],
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
    for document in receipts {
        let receipt = &document.value;
        let receipt_id = string_field(receipt, "receipt_id").unwrap_or("");
        let package_id = string_field(receipt, "package_id").unwrap_or("");
        validate_ledger_binding(document, ledger, ledger_digest, errors);

        let evaluated = receipt.get("evaluated_sets").unwrap_or(&Value::Null);
        let trace_ids = string_set(array(evaluated, "trace_ids"));
        let control_ids = string_set(array(evaluated, "control_ids"));
        let case_ids = string_set(array(evaluated, "acceptance_case_ids"));
        let evidence_ids = string_set(array(evaluated, "evidence_instance_ids"));
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

        let mut evidenced_traces = BTreeSet::new();
        for evidence_id in &evidence_ids {
            let Some(bundle) = evidence.get(evidence_id) else {
                errors.push(format!(
                    "{}: receipt references unknown evidence_instance_id {evidence_id}",
                    document.label
                ));
                continue;
            };
            let trace_id = string_field(&bundle.value, "trace_id").unwrap_or("");
            if !trace_ids.contains(trace_id) {
                errors.push(format!(
                    "{}: evidence {evidence_id} is outside the receipt trace set",
                    document.label
                ));
            }
            evidenced_traces.insert(trace_id.to_string());
            validate_bundle_receipt_context(document, bundle, errors);
        }

        let waived_controls =
            validate_receipt_waivers(document, package_id, controls, &control_ids, errors);
        for trace_id in &trace_ids {
            let control_id = traces
                .get(trace_id)
                .and_then(|trace| string_field(trace, "control_id"))
                .unwrap_or("");
            if !evidenced_traces.contains(trace_id) && !waived_controls.contains(control_id) {
                errors.push(format!(
                    "{}: trace {trace_id} has neither evidence nor an authorized waiver",
                    document.label
                ));
            }
        }

        let accepted_pass = string_field(receipt, "receipt_lifecycle") == Some("accepted")
            && string_field(receipt, "result") == Some("pass");
        if accepted_pass {
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
        for prerequisite in array(receipt, "prerequisite_receipts") {
            let target_id = string_field(prerequisite, "receipt_id").unwrap_or("");
            prerequisites.insert(target_id.to_string());
            let Some(target) = receipt_map.get(target_id) else {
                errors.push(format!(
                    "{}: prerequisite references unknown receipt {target_id}",
                    document.label
                ));
                continue;
            };
            for key in ["package_id", "result", "receipt_lifecycle", "expires_at"] {
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
        }
        prerequisite_graph.insert(receipt_id.to_string(), prerequisites);

        if let Some(target) = receipt.get("supersedes_receipt_id").and_then(Value::as_str) {
            if target == receipt_id {
                errors.push(format!(
                    "{}: receipt {receipt_id} cannot supersede itself",
                    document.label
                ));
            }
            receipt_supersession.insert(receipt_id.to_string(), target.to_string());
        }
    }

    for (source, target) in &receipt_supersession {
        if !receipt_map.contains_key(target) {
            errors.push(format!(
                "receipt {source} supersedes unknown receipt {target}"
            ));
        }
    }
    detect_single_edge_cycles("receipt supersession", &receipt_supersession, errors);
    detect_multi_edge_cycles("prerequisite receipt", &prerequisite_graph, errors);
}

fn validate_ledger_binding(
    document: &LoadedDocument,
    ledger: &Value,
    ledger_digest: Option<&str>,
    errors: &mut Vec<String>,
) {
    let binding = document.value.get("ledger_binding").unwrap_or(&Value::Null);
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
    controls: &BTreeMap<String, &Value>,
    evaluated_controls: &BTreeSet<String>,
    errors: &mut Vec<String>,
) -> BTreeSet<String> {
    let mut waived = BTreeSet::new();
    for waiver in array(&document.value, "waivers") {
        let control_id = string_field(waiver, "control_id").unwrap_or("");
        if !waived.insert(control_id.to_string()) {
            errors.push(format!(
                "{}: duplicate waiver for control {control_id}",
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
        if string_field(waiver, "compensating_control_id") == Some(control_id) {
            errors.push(format!(
                "{}: control {control_id} cannot compensate for itself",
                document.label
            ));
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

    if let Some(provider) = instances.get("provider-registry.implementation.json") {
        validate_provider_registry(provider, errors);
    }
    if let Some(registry) = instances.get("action-resource-registry.implementation.json") {
        validate_action_resource_registry(root, registry, errors);
    }
    if let Some(profile) = instances.get("security-limit-profile.implementation.json") {
        validate_security_limit_profile(root, profile, errors);
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

fn validate_provider_registry(registry: &Value, errors: &mut Vec<String>) {
    let mut configuration_keys = BTreeSet::new();
    let mut provider_kinds = BTreeMap::new();
    for (index, configuration) in array(registry, "configurations").iter().enumerate() {
        let path = format!("provider-registry.implementation.json:/configurations/{index}");
        let provider_id = string_field(configuration, "provider_id").unwrap_or("");
        let version = configuration
            .get("config_version")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let key = format!("{provider_id}@{version}");
        if !configuration_keys.insert(key.clone()) {
            errors.push(format!("{path}: duplicate provider configuration {key}"));
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
        validate_provider_payload_digest(configuration, &path, errors);
    }

    let mut lifecycle_keys = BTreeSet::new();
    for (index, lifecycle) in array(registry, "provider_lifecycle").iter().enumerate() {
        let path = format!("provider-registry.implementation.json:/provider_lifecycle/{index}");
        let provider_id = string_field(lifecycle, "provider_id").unwrap_or("");
        let version = lifecycle
            .get("config_version")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let key = format!("{provider_id}@{version}");
        if !lifecycle_keys.insert(key.clone()) {
            errors.push(format!("{path}: duplicate provider lifecycle record {key}"));
        }
        if !configuration_keys.contains(&key) {
            errors.push(format!(
                "{path}: lifecycle record references unknown provider configuration {key}"
            ));
        }
    }

    let configured_ids: BTreeSet<String> = configuration_keys
        .iter()
        .filter_map(|key| key.split_once('@').map(|(id, _)| id.to_string()))
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
            &format!("action-resource-registry.implementation.json:/inventory_closure/inventory_sources/{index}"),
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
    let digest_field = if reference.contains_key("content_digest") {
        "content_digest"
    } else if reference.contains_key("reference_digest") {
        "reference_digest"
    } else {
        errors.push(format!(
            "{context}: artifact_locator requires content_digest or reference_digest"
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
            for key in ["document_id", "document_version"] {
                if reference.get(key).is_some()
                    && document.get(key).is_some()
                    && reference.get(key) != document.get(key)
                {
                    errors.push(format!(
                        "{context}: {key} does not match artifact_locator {locator}"
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
    use serde_json::json;

    fn root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn load(relative: &str) -> Value {
        serde_json::from_slice(&fs::read(root().join(relative)).expect("read fixture"))
            .expect("parse fixture")
    }

    fn ledger() -> Value {
        load("catalog/security-contracts/v1/control-trace.implementation.json")
    }

    fn semantic_errors(ledger: &Value) -> Vec<String> {
        let mut errors = Vec::new();
        validate_ledger_semantics(ledger, &mut errors);
        errors.sort();
        errors
    }

    #[test]
    fn repository_security_contracts_pass_the_real_gate() {
        let errors = validate_repository(&root()).expect("repository validation should run");
        assert!(errors.is_empty(), "{}", errors.join("\n"));
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
                "bundle_id": bundle_id,
                "evidence_instance_id": evidence_id,
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
                "supersedes_evidence_instance_id": null
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
                    "receipt_id": id,
                    "receipt_digest": receipt_digest,
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
        LoadedDocument {
            label: format!("test:{receipt_id}"),
            digest: digest.to_string(),
            value: json!({
                "receipt_id": receipt_id,
                "package_id": package,
                "ledger_binding": {
                    "ledger_id": ledger["ledger_id"],
                    "ledger_version": ledger["ledger_version"],
                    "ledger_digest": format!("sha256:{:x}", Sha256::digest(ledger_bytes))
                },
                "evaluated_sets": {
                    "trace_ids": [trace["trace_id"].clone()],
                    "control_ids": [trace["control_id"].clone()],
                    "acceptance_case_ids": [trace["acceptance_case_id"].clone()],
                    "evidence_instance_ids": [evidence_id]
                },
                "closure_context": {},
                "prerequisite_receipts": prerequisites,
                "waivers": [],
                "result": "blocked",
                "receipt_lifecycle": "produced",
                "expires_at": "2099-01-01T00:00:00Z",
                "supersedes_receipt_id": null
            }),
        }
    }
}
