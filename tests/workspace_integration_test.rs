#[test]
fn all_crates_build_and_link() {
    let _ = ryuki_core::types::BoundaryStatus::default();
    let _ = ryuki_engine::models::RequestType::ServerDeployment;
}
