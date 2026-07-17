use axum::{routing::get, Json, Router};
use ryuki_core::types::BoundaryStatus;

pub(crate) mod trust_checkpoint_transport;

pub fn routes() -> Router {
    Router::new().route("/api/boundary/status", get(boundary_status))
}

async fn boundary_status() -> Json<BoundaryStatus> {
    Json(BoundaryStatus::default())
}
