pub mod dashboard;
pub mod login;
pub mod request_create;
pub mod request_detail;
pub mod requests;
pub mod workspaces;

#[cfg(all(test, feature = "ssr"))]
mod tests;
