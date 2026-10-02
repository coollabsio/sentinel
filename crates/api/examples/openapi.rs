//! Writes the OpenAPI spec generated from the route annotations to
//! `openapi.json` at the repo root.
//!
//! Run: `cargo run -p api --features traffic --example openapi` (or `just openapi`).
//! The `traffic` feature is required (see `required-features` in Cargo.toml):
//! without it the spec would miss the traffic routes.

fn main() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../openapi.json");
    std::fs::write(path, api::openapi_json()).expect("write openapi.json");
    println!("wrote {path}");
}
