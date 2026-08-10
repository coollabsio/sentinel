// `geoip` needs one scoped unsafe allow for `maxminddb::Reader::open_mmap`;
// every other module has its own `#![forbid(unsafe_code)]`.
#![deny(unsafe_code)]

pub mod aggregator;
pub mod compaction;
pub mod enrich;
pub mod event;
pub mod geoip;
pub mod parser;
pub mod service;
pub mod sketches;
pub mod tailer;

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
    #[error("codec: {0}")]
    Codec(String),
}
