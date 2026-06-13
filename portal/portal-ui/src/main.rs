// The bin is its own crate root: it needs the same query-depth headroom as
// the lib for the deeply nested Leptos view types in release builds.
#![recursion_limit = "256"]

#[cfg(feature = "ssr")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use axum::routing::any;
    use axum::{middleware, routing::get, Router};
    use leptos::prelude::*;
    use leptos_axum::{file_and_error_handler, generate_route_list, LeptosRoutes};
    use ryuki_portal_ui::app::{shell, App};
    use ryuki_portal_ui::server_boundary::PortalServerBoundary;
    use ryuki_portal_ui::upstream::UpstreamClient;

    // Read Leptos config from the environment: cargo-leptos injects LEPTOS_*
    // vars when serving, and the container image sets them explicitly. The
    // binary runs where no Cargo.toml exists, so file-based config can't work.
    let configuration = get_configuration(None)?;
    let leptos_options = configuration.leptos_options;
    let address = leptos_options.site_addr;
    let routes = generate_route_list(App);
    let boundary = PortalServerBoundary::static_dry_run();
    boundary.validate_platform_api_path("/api/platform/summary")?;
    let _core_read_plans = boundary.plan_core_platform_reads()?;

    // One upstream HTTP client for the whole process, handed to server
    // functions through Leptos context on both the SSR-render path and the
    // explicit server-function route below.
    let upstream = UpstreamClient::from_env();
    let upstream_for_server_fns = upstream.clone();
    let upstream_for_routes = upstream.clone();

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(|| async { "ready" }))
        .route(
            "/portal/api/{*fn_name}",
            any(move |request: axum::extract::Request| {
                let upstream = upstream_for_server_fns.clone();
                async move {
                    leptos_axum::handle_server_fns_with_context(
                        move || provide_context(upstream.clone()),
                        request,
                    )
                    .await
                }
            }),
        )
        .leptos_routes_with_context(
            &leptos_options,
            routes,
            move || provide_context(upstream_for_routes.clone()),
            {
                let leptos_options = leptos_options.clone();
                move || shell(leptos_options.clone())
            },
        )
        .fallback(file_and_error_handler(shell))
        .layer(middleware::from_fn(security_headers_middleware))
        .with_state(leptos_options);

    let listener = tokio::net::TcpListener::bind(address).await?;
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}

#[cfg(not(feature = "ssr"))]
fn main() {}

#[cfg(feature = "ssr")]
async fn security_headers_middleware(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut response = next.run(request).await;
    apply_security_headers(response.headers_mut());
    response
}

#[cfg(feature = "ssr")]
fn apply_security_headers(headers: &mut axum::http::HeaderMap) {
    use axum::http::{HeaderName, HeaderValue};

    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(
            "default-src 'self'; \
             script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; \
             style-src 'self' 'unsafe-inline'; \
             img-src 'self' data:; \
             font-src 'self'; \
             connect-src 'self' ws: wss:; \
             frame-ancestors 'none'; \
             base-uri 'self'; \
             form-action 'self'",
        ),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
}

#[cfg(all(test, feature = "ssr"))]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderName};

    #[test]
    fn security_headers_are_applied() {
        let mut headers = HeaderMap::new();

        apply_security_headers(&mut headers);

        assert_eq!(
            headers
                .get("x-frame-options")
                .and_then(|value| value.to_str().ok()),
            Some("DENY")
        );
        assert_eq!(
            headers
                .get("x-content-type-options")
                .and_then(|value| value.to_str().ok()),
            Some("nosniff")
        );
        assert_eq!(
            headers
                .get("referrer-policy")
                .and_then(|value| value.to_str().ok()),
            Some("strict-origin-when-cross-origin")
        );

        let csp = headers
            .get("content-security-policy")
            .and_then(|value| value.to_str().ok())
            .expect("content-security-policy header is set");
        assert!(csp.contains("default-src 'self'"));
        assert!(csp.contains("script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'"));
        assert!(csp.contains("style-src 'self' 'unsafe-inline'"));
        assert!(csp.contains("frame-ancestors 'none'"));
    }

    #[test]
    fn security_headers_do_not_apply_hsts_without_https_runtime_signal() {
        let mut headers = HeaderMap::new();

        apply_security_headers(&mut headers);

        assert!(!headers.contains_key(HeaderName::from_static("strict-transport-security")));
    }
}
