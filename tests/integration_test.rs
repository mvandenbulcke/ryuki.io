#[test]
fn ryuki_core_types_round_trip() {
    let status = ryuki_core::types::BoundaryStatus::default();
    let json = serde_json::to_string(&status).unwrap();
    let parsed: ryuki_core::types::BoundaryStatus = serde_json::from_str(&json).unwrap();
    assert!(!parsed.http_request_allowed);
    assert!(!parsed.provider_calls_allowed);
}

#[test]
fn ryuki_engine_request_lifecycle_dry_run() {
    let req = ryuki_engine::request_lifecycle::create_request(
        "test-1",
        ryuki_engine::models::RequestType::ServerDeployment,
        "test-requester",
        "test-owner",
        "DEFRA",
        "production",
        "high",
    );
    assert!(req.is_ok());
    let req = req.unwrap();
    assert_eq!(req.status, ryuki_engine::models::RequestStatus::Intake);
}

#[test]
fn ryuki_engine_inventory_sync_dry_run() {
    let items = ryuki_engine::inventory_sync::sync_inventory_sources();
    assert!(items.is_ok());
}

// ─── Auth & requests seam fixtures (shared literals with the portal tests) ───
// The portal mirrors ryuki_engine::auth::AuthSession field-for-field instead
// of depending on ryuki-engine (keeps the engine out of the WASM build).
// These fixture literals are copied verbatim from the wave contract and are
// tested on BOTH sides; do not retype or reformat them.

/// Canonical POST /api/auth/local/login 200 response.
const LOCAL_LOGIN_RESPONSE_FIXTURE: &str = r#"{"session_token":"<session-token>","user_id":"admin","display_name":"admin","roles":["PlatformAdmin"],"token_valid":true,"provider_mode":"local","expires_at":"<rfc3339>"}"#;

/// Engine `AuthSession` serialization (GET /api/auth/local/me body).
const AUTH_SESSION_FIXTURE: &str = r#"{"user_id":"admin","display_name":"admin","roles":["PlatformAdmin"],"token_valid":true,"provider_mode":"local"}"#;

/// GET /api/requests list item: existing keys (request_id, request_type,
/// status, name, site, created_at) unchanged; environment and stage are
/// additive this wave.
const REQUESTS_LIST_ITEM_FIXTURE: &str = r#"{"request_id":"<uuid>","request_type":"server-deployment","status":"intake","name":"app-server-01","site":"DEFRA","environment":"production","stage":"intake","created_at":"<rfc3339>"}"#;

#[test]
fn engine_auth_session_serialization_matches_seam_fixture() {
    let session = ryuki_engine::auth::AuthSession {
        user_id: "admin".to_string(),
        display_name: "admin".to_string(),
        roles: vec!["PlatformAdmin".to_string()],
        token_valid: true,
        provider_mode: "local".to_string(),
        ..Default::default()
    };
    let expected: serde_json::Value = serde_json::from_str(AUTH_SESSION_FIXTURE).unwrap();
    assert_eq!(serde_json::to_value(&session).unwrap(), expected);

    // the fixture literal also deserializes back into the engine type
    let parsed: ryuki_engine::auth::AuthSession =
        serde_json::from_str(AUTH_SESSION_FIXTURE).unwrap();
    assert!(parsed.token_valid);
    assert_eq!(parsed.user_id, "admin");
    assert_eq!(parsed.display_name, "admin");
    assert_eq!(parsed.roles, vec!["PlatformAdmin"]);
    assert_eq!(parsed.provider_mode, "local");
}

#[test]
fn local_login_response_fixture_pins_canonical_shape() {
    let value: serde_json::Value = serde_json::from_str(LOCAL_LOGIN_RESPONSE_FIXTURE).unwrap();
    let object = value.as_object().unwrap();
    let expected_keys = [
        "session_token",
        "user_id",
        "display_name",
        "roles",
        "token_valid",
        "provider_mode",
        "expires_at",
    ];
    assert_eq!(object.len(), expected_keys.len());
    for key in expected_keys {
        assert!(object.contains_key(key), "missing key {key}");
    }
    assert_eq!(value["token_valid"], true);
    assert_eq!(value["provider_mode"], "local");
    assert_eq!(value["user_id"], "admin");
    assert_eq!(value["display_name"], "admin");
    assert_eq!(value["roles"], serde_json::json!(["PlatformAdmin"]));
}

#[test]
fn requests_list_item_fixture_keeps_existing_keys_and_adds_environment_stage() {
    let value: serde_json::Value = serde_json::from_str(REQUESTS_LIST_ITEM_FIXTURE).unwrap();
    let object = value.as_object().unwrap();
    // existing keys must stay exactly as-is; environment + stage are additive
    let expected_keys = [
        "request_id",
        "request_type",
        "status",
        "name",
        "site",
        "environment",
        "stage",
        "created_at",
    ];
    assert_eq!(object.len(), expected_keys.len());
    for key in expected_keys {
        assert!(object.contains_key(key), "missing key {key}");
    }
    assert_eq!(value["environment"], "production");
    assert_eq!(value["stage"], "intake");
}

#[test]
fn ryuki_engine_evidence_pipeline() {
    let req = ryuki_engine::request_lifecycle::create_request(
        "test-evidence",
        ryuki_engine::models::RequestType::ServerDeployment,
        "test-requester",
        "test-owner",
        "DEFRA",
        "production",
        "high",
    )
    .unwrap();
    let pack = ryuki_engine::evidence_pipeline::collect_evidence(&req).unwrap();
    assert!(pack.redacted);
    assert!(!pack.items.is_empty());
}
