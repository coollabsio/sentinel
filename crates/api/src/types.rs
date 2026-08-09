use serde::Serialize;

/// WIRE FORMAT IS FROZEN. `percent` is a string here (history endpoints) but a
/// number in /api/cpu/current. Do not "fix" this — Coolify parses it as-is.
#[derive(Debug, Clone, Serialize)]
pub struct CpuUsage {
    pub time: String,
    pub percent: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub human_friendly_time: Option<String>,
}

/// WIRE FORMAT IS FROZEN. `usedPercent` is the only camelCase key in the API.
#[derive(Debug, Clone, Serialize)]
pub struct MemUsage {
    pub time: String,
    pub total: u64,
    pub available: u64,
    pub used: u64,
    #[serde(rename = "usedPercent")]
    pub used_percent: f64,
    pub free: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub human_friendly_time: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ErrorBody {
    pub error: String,
}
