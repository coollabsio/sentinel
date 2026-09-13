use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const MAX_DNS_PACKET: usize = 1232;
const DNS_TTL_SECONDS: u32 = 30;

#[derive(Debug, PartialEq, Eq)]
struct Question {
    workload: String,
    namespace: String,
    address: Option<Ipv4Addr>,
    record_type: u16,
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
    let record_type = u16::from_be_bytes([fields[0], fields[1]]);
    let class = u16::from_be_bytes([fields[2], fields[3]]);
    if !matches!(record_type, 1 | 12 | 28) || class != 1 {
        return Err("unsupported DNS question");
    }
    if record_type == 12 {
        if labels.len() != 6 || labels[4] != "in-addr" || labels[5] != "arpa" {
            return Err("invalid IPv4 reverse lookup name");
        }
        let octets = labels[..4]
            .iter()
            .rev()
            .map(|label| {
                label
                    .parse::<u8>()
                    .map_err(|_| "invalid IPv4 reverse lookup name")
            })
            .collect::<Result<Vec<_>, _>>()?;

        return Ok(Question {
            workload: String::new(),
            namespace: String::new(),
            address: Some(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3])),
            record_type,
            end: question_end,
        });
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
        address: None,
        record_type,
        end: question_end,
    })
}

fn build_response(packet: &[u8], question: &Question, endpoints: &[Ipv4Addr]) -> Vec<u8> {
    let endpoints = if question.record_type == 1 {
        endpoints
    } else {
        &[]
    };
    let mut response = Vec::with_capacity(question.end + endpoints.len() * 16);
    response.extend_from_slice(&packet[0..2]);
    response.extend_from_slice(if endpoints.is_empty() && question.record_type == 1 {
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

fn encode_dns_name(name: &str) -> Option<Vec<u8>> {
    let mut encoded = Vec::new();
    for label in name.trim_end_matches('.').split('.') {
        if !valid_label(label) {
            return None;
        }
        encoded.push(label.len() as u8);
        encoded.extend_from_slice(label.as_bytes());
    }
    encoded.push(0);
    Some(encoded)
}

fn build_ptr_response(
    packet: &[u8],
    question: &Question,
    names: &[String],
    max_packet: usize,
) -> Vec<u8> {
    let encoded_names = names
        .iter()
        .filter_map(|name| encode_dns_name(name))
        .collect::<Vec<_>>();
    let response_size = question.end
        + encoded_names
            .iter()
            .map(|name| name.len() + 12)
            .sum::<usize>();
    let truncated = response_size > max_packet;
    let encoded_names = if truncated {
        &[][..]
    } else {
        &encoded_names[..]
    };
    let mut response = Vec::with_capacity(
        question.end
            + encoded_names
                .iter()
                .map(|name| name.len() + 12)
                .sum::<usize>(),
    );
    response.extend_from_slice(&packet[0..2]);
    response.extend_from_slice(if truncated {
        &[0x87, 0x80]
    } else if encoded_names.is_empty() {
        &[0x85, 0x83]
    } else {
        &[0x85, 0x80]
    });
    response.extend_from_slice(&[0, 1]);
    response.extend_from_slice(&(encoded_names.len() as u16).to_be_bytes());
    response.extend_from_slice(&[0, 0, 0, 0]);
    response.extend_from_slice(&packet[12..question.end]);
    for name in encoded_names {
        response.extend_from_slice(&[0xc0, 0x0c, 0, 12, 0, 1]);
        response.extend_from_slice(&DNS_TTL_SECONDS.to_be_bytes());
        response.extend_from_slice(&(name.len() as u16).to_be_bytes());
        response.extend_from_slice(name);
    }
    response
}

fn endpoint_lookup_sql() -> &'static str {
    "SELECT container_ip FROM workload_endpoints WHERE workload_id = ? AND namespace = ? AND state = 'running' AND health IN ('healthy', 'unknown') AND expires_at > unixepoch() ORDER BY container_ip"
}

fn reverse_lookup_sql() -> &'static str {
    "SELECT workload_id || '.' || namespace FROM workload_endpoints WHERE container_ip = ? AND state = 'running' AND health IN ('healthy', 'unknown') AND expires_at > unixepoch() ORDER BY namespace, workload_id"
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

fn lookup_names(
    corrosion_config: &Path,
    address: Ipv4Addr,
    zone: &str,
) -> Result<Vec<String>, String> {
    let output = Command::new("/usr/local/bin/corrosion")
        .args(["query", "--config"])
        .arg(corrosion_config)
        .args(["--param", &address.to_string(), reverse_lookup_sql()])
        .output()
        .map_err(|_| "Corrosion is unavailable.".to_string())?;
    if !output.status.success() {
        return Err("Corrosion could not query reverse discovery endpoints.".into());
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|_| "Corrosion returned invalid reverse endpoint data.".to_string())?;
    let mut names = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter_map(|line| {
            let (workload, namespace) = line.split_once('.')?;
            (valid_label(workload) && valid_label(namespace))
                .then(|| format!("{workload}.{namespace}.{zone}"))
        })
        .collect::<Vec<_>>();
    names.sort_unstable();
    names.dedup();
    Ok(names)
}

fn answer_request(
    request: &[u8],
    zone: &str,
    corrosion_config: &Path,
    max_packet: usize,
) -> Option<Vec<u8>> {
    let question = parse_question(request, zone).ok()?;
    Some(match question.record_type {
        1 => {
            let endpoints =
                lookup_endpoints(corrosion_config, &question.workload, &question.namespace)
                    .unwrap_or_default();
            build_response(request, &question, &endpoints)
        }
        12 => {
            let names = lookup_names(
                corrosion_config,
                question
                    .address
                    .expect("PTR questions have an IPv4 address"),
                zone,
            )
            .unwrap_or_default();
            build_ptr_response(request, &question, &names, max_packet)
        }
        _ => build_response(request, &question, &[]),
    })
}

fn serve_tcp(listener: TcpListener, zone: String, corrosion_config: PathBuf) {
    for mut stream in listener.incoming().flatten() {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
        let mut length = [0_u8; 2];
        if stream.read_exact(&mut length).is_err() {
            continue;
        }
        let length = u16::from_be_bytes(length) as usize;
        if length == 0 || length > MAX_DNS_PACKET {
            continue;
        }
        let mut request = vec![0_u8; length];
        if stream.read_exact(&mut request).is_err() {
            continue;
        }
        let Some(response) = answer_request(&request, &zone, &corrosion_config, u16::MAX as usize)
        else {
            continue;
        };
        let response_length = (response.len() as u16).to_be_bytes();
        let _ = stream.write_all(&response_length);
        let _ = stream.write_all(&response);
    }
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
    let tcp_listener = TcpListener::bind(bind)
        .map_err(|error| format!("Discovery DNS TCP bind failed: {error}"))?;
    let socket =
        UdpSocket::bind(bind).map_err(|error| format!("Discovery DNS bind failed: {error}"))?;
    std::thread::spawn({
        let zone = zone.clone();
        let corrosion_config = corrosion_config.to_path_buf();
        move || serve_tcp(tcp_listener, zone, corrosion_config)
    });
    let mut packet = [0_u8; MAX_DNS_PACKET];
    loop {
        let (length, source) = socket
            .recv_from(&mut packet)
            .map_err(|error| format!("Discovery DNS receive failed: {error}"))?;
        let request = &packet[..length];
        let Some(response) = answer_request(request, &zone, corrosion_config, MAX_DNS_PACKET)
        else {
            continue;
        };
        socket
            .send_to(&response, source)
            .map_err(|error| format!("Discovery DNS response failed: {error}"))?;
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    fn query(name: &str) -> Vec<u8> {
        query_with_type(name, 1)
    }

    fn query_with_type(name: &str, record_type: u16) -> Vec<u8> {
        let mut packet = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        for label in name.trim_end_matches('.').split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&record_type.to_be_bytes());
        packet.extend_from_slice(&[0, 1]);
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
    fn parses_ipv4_ptr_queries() {
        let packet = query_with_type("2.0.240.10.in-addr.arpa.", 12);
        let question = super::parse_question(&packet, "coolify.internal").unwrap();

        assert_eq!(question.address, Some("10.240.0.2".parse().unwrap()));
        assert!(
            super::parse_question(
                &query_with_type("2.0.240.10.in-addr.arpa.", 1),
                "coolify.internal"
            )
            .is_err()
        );
        assert!(
            super::parse_question(
                &query_with_type("web.default.coolify.internal.", 12),
                "coolify.internal"
            )
            .is_err()
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
    fn builds_an_empty_authoritative_response_for_aaaa_queries() {
        let packet = query_with_type("web.default.coolify.internal.", 28);
        let question = super::parse_question(&packet, "coolify.internal").unwrap();
        let response = super::build_response(&packet, &question, &[]);

        assert_eq!(&response[2..4], &[0x85, 0x80]);
        assert_eq!(&response[6..8], &[0, 0]);
    }

    #[test]
    fn builds_an_authoritative_ptr_response_for_each_workload() {
        let packet = query_with_type("2.0.240.10.in-addr.arpa.", 12);
        let question = super::parse_question(&packet, "coolify.internal").unwrap();
        let response = super::build_ptr_response(
            &packet,
            &question,
            &[
                "api.default.coolify.internal".into(),
                "web.default.coolify.internal".into(),
            ],
            super::MAX_DNS_PACKET,
        );

        assert_eq!(&response[2..4], &[0x85, 0x80]);
        assert_eq!(&response[6..8], &[0, 2]);
        assert!(response.windows(3).any(|bytes| bytes == b"web"));
    }

    #[test]
    fn ptr_responses_stay_within_the_dns_udp_packet_limit() {
        let packet = query_with_type("2.0.240.10.in-addr.arpa.", 12);
        let question = super::parse_question(&packet, "coolify.internal").unwrap();
        let names = (0..64)
            .map(|index| {
                format!(
                    "workload-{index:02}-{}.default.coolify.internal",
                    "x".repeat(45)
                )
            })
            .collect::<Vec<_>>();
        let response = super::build_ptr_response(&packet, &question, &names, super::MAX_DNS_PACKET);

        assert!(response.len() <= super::MAX_DNS_PACKET);
        assert_eq!(response[2] & 0x02, 0x02);
        assert_eq!(&response[6..8], &[0, 0]);

        let tcp_response = super::build_ptr_response(&packet, &question, &names, u16::MAX as usize);
        assert_eq!(tcp_response[2] & 0x02, 0);
        assert_eq!(&tcp_response[6..8], &[0, 64]);
    }

    #[test]
    fn endpoint_lookup_excludes_unhealthy_and_expired_rows() {
        let sql = super::endpoint_lookup_sql();

        assert!(sql.contains("state = 'running'"));
        assert!(sql.contains("health IN ('healthy', 'unknown')"));
        assert!(sql.contains("expires_at > unixepoch()"));
    }

    #[test]
    fn reverse_lookup_returns_only_active_workload_names_for_an_address() {
        let sql = super::reverse_lookup_sql();

        assert!(sql.contains("container_ip = ?"));
        assert!(sql.contains("state = 'running'"));
        assert!(sql.contains("health IN ('healthy', 'unknown')"));
        assert!(sql.contains("expires_at > unixepoch()"));
    }
}
