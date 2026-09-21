//! Root of the generated OpenAPI document: info, servers, tags, and the
//! bearer security scheme. Paths and schemas are contributed by the
//! `#[utoipa::path]` annotations on the route handlers and composed in
//! `crate::router()` via utoipa-axum's `OpenApiRouter`.
//!
//! This module replaces the old hand-written `openapi.yaml`. The version is
//! the build version (`config::VERSION`, honoring `SENTINEL_BUILD_VERSION`),
//! so the spec always matches `/api/version` with no manual bumping.

use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityRequirement, SecurityScheme};
use utoipa::openapi::tag::TagBuilder;
use utoipa::openapi::{
    ComponentsBuilder, ContactBuilder, InfoBuilder, LicenseBuilder, OpenApi, OpenApiBuilder,
    ServerBuilder,
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
                .version(config::VERSION)
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
        .servers(Some(vec![
            ServerBuilder::new()
                .url("http://localhost:8888")
                .description(Some("Local development server"))
                .build(),
            ServerBuilder::new()
                .url("https://sentinel.example.com")
                .description(Some("Production server"))
                .build(),
        ]))
        .tags(Some(vec![
            TagBuilder::new()
                .name("Core")
                .description(Some("Health check and version endpoints"))
                .build(),
            TagBuilder::new()
                .name("System Metrics")
                .description(Some("CPU and memory metrics for the host system"))
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
