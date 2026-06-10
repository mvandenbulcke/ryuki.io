pub mod api;
pub mod api_client;
pub mod app;
pub mod models;
pub mod server_boundary;
pub mod shell;
pub mod views;
pub mod workspace_catalog;

#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    console_error_panic_hook::set_once();
    leptos::mount::hydrate_body(app::App);
}
