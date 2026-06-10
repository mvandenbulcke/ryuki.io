use serde_json;

#[test]
fn ryuki_core_types_round_trip() {
    let status = ryuki_core::types::BoundaryStatus::default();
    let json = serde_json::to_string(&status).unwrap();
    let parsed: ryuki_core::types::BoundaryStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.http_request_allowed, false);
    assert_eq!(parsed.provider_calls_allowed, false);
}

#[test]
fn ryuki_engine_request_lifecycle_dry_run() {
    let req = ryuki_engine::request_lifecycle::create_request(
        "test-1",
        ryuki_engine::models::RequestType::ServerDeployment,
        "test-requester",
        "test-owner",
        "LOVE",
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

#[test]
fn ryuki_engine_evidence_pipeline() {
    let req = ryuki_engine::request_lifecycle::create_request(
        "test-evidence",
        ryuki_engine::models::RequestType::ServerDeployment,
        "test-requester",
        "test-owner",
        "LOVE",
        "production",
        "high",
    )
    .unwrap();
    let pack = ryuki_engine::evidence_pipeline::collect_evidence(&req).unwrap();
    assert!(pack.redacted);
    assert!(!pack.items.is_empty());
}
