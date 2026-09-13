use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::Path;
use std::process::Command;

const MAX_DNS_PACKET: usize = 1232;
const DNS_TTL_SECONDS: u32 = 30;

#[derive(Debug, PartialEq, Eq)]
struct Question {
    workload: String,
    namespace: String,
    end: usize,
}

fn valid_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
        && !value.starts_with('-')
        && !value.ends_with('-')
}

fn parse_question(packet: &[u8], zone: &str) -> Result<Question, &'static str> {
    if packet.len() < 17 || u16::from_be_bytes([packet[4], packet[5]]) != 1 {
        return Err("invalid DNS question count");
    }
    let mut offset = 12;
    let mut labels = Vec::new();
    loop {
        let length = *packet.get(offset).ok_or("truncated DNS name")? as usize;
        offset += 1;
        if length == 0 {
            break;
        }
        if length > 63 || length & 0xc0 != 0 {
            return Err("invalid DNS label");
        }
        let label = packet
            .get(offset..offset + length)
            .ok_or("truncated DNS label")?;
        let label = std::str::from_utf8(label).map_err(|_| "invalid DNS label")?;
        labels.push(label.to_ascii_lowercase());
        offset += length;
    }
    let question_end = offset.checked_add(4).ok_or("invalid DNS question")?;
    let fields = packet
        .get(offset..question_end)
        .ok_or("truncated DNS question")?;
    if fields != [0, 1, 0, 1] {
        return Err("unsupported DNS question");
    }
    let zone_labels = zone
        .trim_end_matches('.')
        .split('.')
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>();
    if labels.len() != zone_labels.len() + 2
        || labels[2..] != zone_labels
        || !valid_label(&labels[0])
        || !valid_label(&labels[1])
    {
        return Err("name is outside the internal discovery zone");
    }

    Ok(Question {
        workload: labels[0].clone(),
        namespace: labels[1].clone(),
        end: question_end,
    })
}

fn build_response(packet: &[u8], question: &Question, endpoints: &[Ipv4Addr]) -> Vec<u8> {
    let mut response = Vec::with_capacity(question.end + endpoints.len() * 16);
    response.extend_from_slice(&packet[0..2]);
    response.extend_from_slice(if endpoints.is_empty() {
        &[0x85, 0x83]
    } else {
        &[0x85, 0x80]
    });
    response.extend_from_slice(&[0, 1]);
    response.extend_from_slice(&(endpoints.len() as u16).to_be_bytes());
    response.extend_from_slice(&[0, 0, 0, 0]);
    response.extend_from_slice(&packet[12..question.end]);
    for endpoint in endpoints {
        response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
        response.extend_from_slice(&DNS_TTL_SECONDS.to_be_bytes());
        response.extend_from_slice(&[0, 4]);
        response.extend_from_slice(&endpoint.octets());
    }
    response
}

fn endpoint_lookup_sql() -> &'static str {
    "SELECT container_ip FROM workload_endpoints WHERE workload_id = ? AND namespace = ? AND state = 'running' AND health IN ('healthy', 'unknown') AND expires_at > unixepoch() ORDER BY container_ip"
}

fn lookup_endpoints(
    corrosion_config: &Path,
    workload: &str,
    namespace: &str,
) -> Result<Vec<Ipv4Addr>, String> {
    let output = Command::new("/usr/local/bin/corrosion")
        .args(["query", "--config"])
        .arg(corrosion_config)
        .args([
            "--param",
            workload,
            "--param",
            namespace,
            endpoint_lookup_sql(),
        ])
        .output()
        .map_err(|_| "Corrosion is unavailable.".to_string())?;
    if !output.status.success() {
        return Err("Corrosion could not query discovery endpoints.".into());
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|_| "Corrosion returned invalid endpoint data.".to_string())?;
    let mut endpoints = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            line.parse::<Ipv4Addr>()
                .map_err(|_| "Corrosion returned an invalid endpoint address.".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    endpoints.sort_unstable();
    endpoints.dedup();
    endpoints.truncate(64);
    Ok(endpoints)
}

pub(crate) fn run(bind: SocketAddr, zone: &str, corrosion_config: &Path) -> Result<(), String> {
    if !bind.ip().is_ipv4() || bind.ip().is_unspecified() || bind.port() != 53 {
        return Err(
            "The discovery DNS bind address must be a specific IPv4 address on port 53.".into(),
        );
    }
    let zone = zone.trim_end_matches('.').to_ascii_lowercase();
    if zone.is_empty() {
        return Err("The discovery DNS zone is invalid.".into());
    }
    let socket =
        UdpSocket::bind(bind).map_err(|error| format!("Discovery DNS bind failed: {error}"))?;
    let mut packet = [0_u8; MAX_DNS_PACKET];
    loop {
        let (length, source) = socket
            .recv_from(&mut packet)
            .map_err(|error| format!("Discovery DNS receive failed: {error}"))?;
        let request = &packet[..length];
        let Ok(question) = parse_question(request, &zone) else {
            continue;
        };
        let endpoints = lookup_endpoints(corrosion_config, &question.workload, &question.namespace)
            .unwrap_or_default();
        let response = build_response(request, &question, &endpoints);
        socket
            .send_to(&response, source)
            .map_err(|error| format!("Discovery DNS response failed: {error}"))?;
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    fn query(name: &str) -> Vec<u8> {
        let mut packet = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        for label in name.trim_end_matches('.').split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&[0, 1, 0, 1]);
        packet
    }

    #[test]
    fn parses_only_namespace_qualified_internal_names() {
        let packet = query("web.default.coolify.internal.");
        let question = super::parse_question(&packet, "coolify.internal").unwrap();

        assert_eq!(question.workload, "web");
        assert_eq!(question.namespace, "default");
        assert!(
            super::parse_question(&query("web.coolify.internal."), "coolify.internal").is_err()
        );
        assert!(
            super::parse_question(&query("web.default.example.com."), "coolify.internal").is_err()
        );
    }

    #[test]
    fn builds_an_authoritative_a_response_for_each_endpoint() {
        let packet = query("web.default.coolify.internal.");
        let question = super::parse_question(&packet, "coolify.internal").unwrap();
        let response = super::build_response(
            &packet,
            &question,
            &[
                "10.240.0.2".parse::<Ipv4Addr>().unwrap(),
                "10.240.0.3".parse::<Ipv4Addr>().unwrap(),
            ],
        );

        assert_eq!(&response[0..2], &[0x12, 0x34]);
        assert_eq!(&response[6..8], &[0, 2]);
        assert_eq!(&response[response.len() - 4..], &[10, 240, 0, 3]);
    }

    #[test]
    fn endpoint_lookup_excludes_unhealthy_and_expired_rows() {
        let sql = super::endpoint_lookup_sql();

        assert!(sql.contains("state = 'running'"));
        assert!(sql.contains("health IN ('healthy', 'unknown')"));
        assert!(sql.contains("expires_at > unixepoch()"));
    }
}
