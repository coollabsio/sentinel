#![forbid(unsafe_code)]

pub mod event;
pub mod parser;
pub mod sketches;
pub mod enrich;
pub mod aggregator;
pub mod tailer;
pub mod geoip;
pub mod service;

#[derive(Debug, thiserror::Error)]
pub enum TrafficError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("store: {0}")]
    Store(#[from] store::StoreError),
    #[error("download: {0}")]
    Download(String),
    #[error("decompress: {0}")]
    Decompress(String),
    #[error("geoip: {0}")]
    GeoIp(String),
}
