//! Root of the generated OpenAPI document: info, tags, and the
//! bearer security scheme. Paths and schemas are contributed by the
//! `#[utoipa::path]` annotations on the route handlers and composed in
//! `crate::openapi_document()` via utoipa-axum's `OpenApiRouter`.
//!
//! The version is the crate version (`CARGO_PKG_VERSION`), not
//! `config::VERSION`: a dev build tag from `SENTINEL_BUILD_VERSION` must not
//! change the committed `openapi.json`.
//!
//! No `servers` list: OpenAPI then defaults to `/`, the host that serves the API.

use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityRequirement, SecurityScheme};
use utoipa::openapi::tag::TagBuilder;
use utoipa::openapi::{
    ComponentsBuilder, ContactBuilder, InfoBuilder, LicenseBuilder, OpenApi, OpenApiBuilder,
};

pub fn base_openapi() -> OpenApi {
    OpenApiBuilder::new()
        .info(
            InfoBuilder::new()
                .title("Sentinel API")
                .description(Some(
                    "REST API for gathering Linux server and Docker Engine metrics.\n\n\
                     Sentinel collects system metrics (CPU, memory) and Docker container \
                     statistics, storing them in SQLite and providing both current and \
                     historical data through REST endpoints.\n\n\
                     This service is designed for integration with \
                     [Coolify.io](https://coolify.io).",
                ))
                .version(env!("CARGO_PKG_VERSION"))
                .contact(Some(
                    ContactBuilder::new()
                        .name(Some("Coolify"))
                        .url(Some("https://coolify.io"))
                        .build(),
                ))
                .license(Some(
                    LicenseBuilder::new()
                        .name("Apache-2.0")
                        .url(Some("https://www.apache.org/licenses/LICENSE-2.0"))
                        .build(),
                ))
                .build(),
        )
        .tags(Some(vec![
            TagBuilder::new()
                .name("Core")
                .description(Some("Health check and version endpoints"))
                .build(),
            TagBuilder::new()
                .name("System Metrics")
                .description(Some("CPU, memory, disk, network and load metrics for the host system"))
                .build(),
            TagBuilder::new()
                .name("Container Metrics")
                .description(Some("Metrics for Docker containers"))
                .build(),
            TagBuilder::new()
                .name("Traffic Analytics")
                .description(Some(
                    "On-box, aggregate-only web/traffic analytics computed from the \
                     reverse-proxy access log. Only present when Sentinel is built with the \
                     `traffic` Cargo feature and `TRAFFIC_ENABLED=true` at runtime; see \
                     README.md for the full feature description and Coolify handoff \
                     requirements.",
                ))
                .build(),
            TagBuilder::new()
                .name("Debug")
                .description(Some("Debug-only endpoints (available when DEBUG=true)"))
                .build(),
        ]))
        .components(Some(
            ComponentsBuilder::new()
                .security_scheme(
                    "bearerAuth",
                    SecurityScheme::Http(
                        HttpBuilder::new()
                            .scheme(HttpAuthScheme::Bearer)
                            .description(Some(
                                "Bearer token authentication. Set the TOKEN environment \
                                 variable when running Sentinel and include it in the \
                                 Authorization header.",
                            ))
                            .build(),
                    ),
                )
                .build(),
        ))
        .security(Some(vec![SecurityRequirement::new(
            "bearerAuth",
            Vec::<String>::new(),
        )]))
        .build()
}
