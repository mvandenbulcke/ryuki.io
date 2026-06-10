#[cfg(feature = "ssr")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use axum::{routing::get, Router};
    use leptos::prelude::*;
    use leptos_axum::{file_and_error_handler, generate_route_list, LeptosRoutes};
    use ryuki_portal_ui::app::{shell, App};
    use ryuki_portal_ui::server_boundary::PortalServerBoundary;

    let configuration = get_configuration(Some("Cargo.toml"))?;
    let leptos_options = configuration.leptos_options;
    let address = leptos_options.site_addr;
    let routes = generate_route_list(App);
    let boundary = PortalServerBoundary::static_dry_run();
    boundary.validate_platform_api_path("/api/platform/summary")?;
    let _core_read_plans = boundary.plan_core_platform_reads()?;

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(|| async { "ready" }))
        .leptos_routes(&leptos_options, routes, {
            let leptos_options = leptos_options.clone();
            move || shell(leptos_options.clone())
        })
        .fallback(file_and_error_handler(shell))
        .with_state(leptos_options);

    let listener = tokio::net::TcpListener::bind(address).await?;
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}

#[cfg(not(feature = "ssr"))]
fn main() {}
