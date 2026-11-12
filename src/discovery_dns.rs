use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

const MAX_DNS_PACKET: usize = 1232;
const DNS_TTL_SECONDS: u32 = 30;
const SYSTEMD_RESOLVED_STUB: &str = "127.0.0.53:53";
/// A hung Corrosion query must not stall the single DNS request loop.
const CORROSION_QUERY_TIMEOUT: Duration = Duration::from_secs(2);
/// Bounds the threads that slow TCP DNS clients can hold.
const MAX_TCP_CONNECTIONS: usize = 32;
/// Bounds the threads that slow UDP lookups and forwards can hold. A request
/// over the limit is dropped, and the client sends it again.
const MAX_UDP_REQUESTS: usize = 64;

trait OutputWithTimeout {
    fn output_with_timeout(&mut self) -> Result<std::process::Output, String>;
}

impl OutputWithTimeout for Command {
    /// Runs the command and kills it after `CORROSION_QUERY_TIMEOUT`. Query
    /// output is small, so it fits in the pipe buffer until the child exits.
    fn output_with_timeout(&mut self) -> Result<std::process::Output, String> {
        let mut child = self
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|_| "Corrosion is unavailable.".to_string())?;
        let deadline = std::time::Instant::now() + CORROSION_QUERY_TIMEOUT;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("Corrosion did not answer in time.".into());
                }
            }
        }
        child
            .wait_with_output()
            .map_err(|_| "Corrosion is unavailable.".to_string())
    }
}

/// The reverse zones that systemd-resolved routes to this server, one name on
/// each line. Sentinel writes the file next to the Corrosion configuration,
/// together with the routing domains.
const REVERSE_ZONES_FILE: &str = "coolify-reverse-zones";

/// Reads the reverse zones of this server. Without the file, every name under
/// `in-addr.arpa` counts as a name of this server: the routing domains are
/// then unknown, and a forward of a routed name comes back as a new query.
fn read_reverse_zones(corrosion_config: &Path) -> Option<Vec<String>> {
    let zones =
        std::fs::read_to_string(corrosion_config.with_file_name(REVERSE_ZONES_FILE)).ok()?;
    Some(
        zones
            .lines()
            .map(|zone| zone.trim().to_ascii_lowercase())
            .filter(|zone| !zone.is_empty())
            .collect(),
    )
}

/// A name that this server answers itself. systemd-resolved routes the
/// internal zone and the cluster reverse zones to this server, so a forward
/// of such a name comes back as a new query.
#[derive(Debug, PartialEq, Eq)]
enum Name {
    Workload {
        workload: String,
        namespace: String,
    },
    Address(Ipv4Addr),
    /// The name has no records, but a name below it can have records.
    Empty,
    Missing,
}

#[derive(Debug, PartialEq, Eq)]
struct Question {
    name: Name,
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

fn parse_question(
    packet: &[u8],
    zone: &str,
    reverse_zones: Option<&[String]>,
) -> Result<Question, &'static str> {
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
    if class != 1 {
        return Err("unsupported DNS question");
    }
    let zone_labels = zone
        .trim_end_matches('.')
        .split('.')
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>();
    let name = if let Some(octets) = labels.strip_suffix(&["in-addr".into(), "arpa".into()]) {
        if reverse_zones.is_some_and(|zones| {
            !zones.iter().any(|zone| {
                labels.ends_with(&zone.split('.').map(str::to_string).collect::<Vec<_>>())
            })
        }) {
            return Err("name is outside the cluster reverse zones");
        }
        let address = octets
            .iter()
            .rev()
            .map(|label| label.parse::<u8>().ok())
            .collect::<Option<Vec<_>>>();
        match (octets.len(), address) {
            (..4, _) => Name::Empty,
            (4, Some(address)) => Name::Address(Ipv4Addr::new(
                address[0], address[1], address[2], address[3],
            )),
            _ => Name::Missing,
        }
    } else if let Some(labels) = labels.strip_suffix(&zone_labels[..]) {
        match labels {
            [] => Name::Empty,
            [namespace] if valid_label(namespace) => Name::Empty,
            [workload, namespace] if valid_label(workload) && valid_label(namespace) => {
                Name::Workload {
                    workload: workload.clone(),
                    namespace: namespace.clone(),
                }
            }
            _ => Name::Missing,
        }
    } else {
        return Err("name is outside the internal discovery zone");
    };

    Ok(Question {
        name,
        record_type,
        end: question_end,
    })
}

/// An authoritative response without records: NXDOMAIN, or NOERROR for a name
/// that exists.
fn build_empty_response(packet: &[u8], question: &Question, name_exists: bool) -> Vec<u8> {
    let mut response = Vec::with_capacity(question.end);
    response.extend_from_slice(&packet[0..2]);
    response.extend_from_slice(if name_exists {
        &[0x85, 0x80]
    } else {
        &[0x85, 0x83]
    });
    response.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    response.extend_from_slice(&packet[12..question.end]);
    response
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

/// Node and cluster service names are endpoint rows of their own. Workload names map to a
/// workload ID through `workload_names`, which Coolify writes, so a rename
/// applies without touching the containers.
const NODE_NAMESPACE: &str = "nodes";
/// Cluster services, for example `registry.cluster`. Endpoint rows of their own.
const CLUSTER_NAMESPACE: &str = "cluster";

fn endpoint_lookup_sql(namespace: &str) -> &'static str {
    if namespace == NODE_NAMESPACE || namespace == CLUSTER_NAMESPACE {
        "SELECT container_ip FROM workload_endpoints WHERE workload_id = ? AND namespace = ? AND state = 'running' AND health IN ('healthy', 'unknown') AND expires_at > unixepoch() ORDER BY container_ip"
    } else {
        "SELECT e.container_ip FROM workload_names n JOIN workload_endpoints e ON e.namespace = n.namespace AND e.workload_id = n.workload_id WHERE n.name = ? AND n.namespace = ? AND n.revision = (SELECT MAX(revision) FROM workload_names) AND e.state = 'running' AND e.health IN ('healthy', 'unknown') AND e.expires_at > unixepoch() ORDER BY e.container_ip"
    }
}

/// Takes the address twice: once for Node rows, once for workload rows.
fn reverse_lookup_sql() -> &'static str {
    "SELECT workload_id || '.' || namespace AS fqdn FROM workload_endpoints WHERE container_ip = ? AND namespace = 'nodes' AND state = 'running' AND health IN ('healthy', 'unknown') AND expires_at > unixepoch() UNION SELECT n.name || '.' || n.namespace FROM workload_endpoints e JOIN workload_names n ON n.namespace = e.namespace AND n.workload_id = e.workload_id WHERE e.container_ip = ? AND e.namespace != 'nodes' AND n.revision = (SELECT MAX(revision) FROM workload_names) AND e.state = 'running' AND e.health IN ('healthy', 'unknown') AND e.expires_at > unixepoch() ORDER BY fqdn"
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
            endpoint_lookup_sql(namespace),
        ])
        .output_with_timeout()?;
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
        .args([
            "--param",
            &address.to_string(),
            "--param",
            &address.to_string(),
            reverse_lookup_sql(),
        ])
        .output_with_timeout()?;
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
    let reverse_zones = read_reverse_zones(corrosion_config);
    let question = parse_question(request, zone, reverse_zones.as_deref()).ok()?;
    Some(match (&question.name, question.record_type) {
        (
            Name::Workload {
                workload,
                namespace,
            },
            1,
        ) => {
            let endpoints =
                lookup_endpoints(corrosion_config, workload, namespace).unwrap_or_default();
            build_response(request, &question, &endpoints)
        }
        (Name::Address(address), 12) => {
            let names = lookup_names(corrosion_config, *address, zone).unwrap_or_default();
            build_ptr_response(request, &question, &names, max_packet)
        }
        (Name::Missing, _) => build_empty_response(request, &question, false),
        _ => build_empty_response(request, &question, true),
    })
}

fn forward_udp(request: &[u8]) -> Option<Vec<u8>> {
    let socket = UdpSocket::bind("127.0.0.1:0").ok()?;
    socket.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    socket
        .set_write_timeout(Some(Duration::from_secs(5)))
        .ok()?;
    socket.send_to(request, SYSTEMD_RESOLVED_STUB).ok()?;
    let mut response = vec![0_u8; MAX_DNS_PACKET];
    let length = socket.recv(&mut response).ok()?;
    response.truncate(length);
    (response.get(..2) == request.get(..2)).then_some(response)
}

fn forward_tcp(request: &[u8]) -> Option<Vec<u8>> {
    let address = SYSTEMD_RESOLVED_STUB.parse().ok()?;
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(5)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .ok()?;
    stream
        .write_all(&(request.len() as u16).to_be_bytes())
        .ok()?;
    stream.write_all(request).ok()?;
    let mut length = [0_u8; 2];
    stream.read_exact(&mut length).ok()?;
    let length = u16::from_be_bytes(length) as usize;
    if length == 0 {
        return None;
    }
    let mut response = vec![0_u8; length];
    stream.read_exact(&mut response).ok()?;
    (response.get(..2) == request.get(..2)).then_some(response)
}

fn serve_tcp(listener: TcpListener, zone: String, corrosion_config: PathBuf) {
    let zone = Arc::new(zone);
    let corrosion_config = Arc::new(corrosion_config);
    let active = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming().flatten() {
        if active.fetch_add(1, Ordering::AcqRel) >= MAX_TCP_CONNECTIONS {
            active.fetch_sub(1, Ordering::AcqRel);
            continue;
        }
        let zone = zone.clone();
        let corrosion_config = corrosion_config.clone();
        let active = active.clone();
        std::thread::spawn(move || {
            serve_tcp_connection(stream, &zone, &corrosion_config);
            active.fetch_sub(1, Ordering::AcqRel);
        });
    }
}

fn serve_tcp_connection(mut stream: TcpStream, zone: &str, corrosion_config: &Path) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let mut length = [0_u8; 2];
    if stream.read_exact(&mut length).is_err() {
        return;
    }
    let length = u16::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_DNS_PACKET {
        return;
    }
    let mut request = vec![0_u8; length];
    if stream.read_exact(&mut request).is_err() {
        return;
    }
    let Some(response) = answer_request(&request, zone, corrosion_config, u16::MAX as usize)
        .or_else(|| forward_tcp(&request))
    else {
        return;
    };
    let response_length = (response.len() as u16).to_be_bytes();
    let _ = stream.write_all(&response_length);
    let _ = stream.write_all(&response);
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
    let socket = Arc::new(socket);
    let zone = Arc::new(zone);
    let corrosion_config = Arc::new(corrosion_config.to_path_buf());
    let active = Arc::new(AtomicUsize::new(0));
    let mut packet = [0_u8; MAX_DNS_PACKET];
    loop {
        let (length, source) = socket
            .recv_from(&mut packet)
            .map_err(|error| format!("Discovery DNS receive failed: {error}"))?;
        if active.fetch_add(1, Ordering::AcqRel) >= MAX_UDP_REQUESTS {
            active.fetch_sub(1, Ordering::AcqRel);
            continue;
        }
        let request = packet[..length].to_vec();
        let socket = socket.clone();
        let zone = zone.clone();
        let corrosion_config = corrosion_config.clone();
        let active = active.clone();
        // A slow lookup or forward must not delay the other requests.
        std::thread::spawn(move || {
            if let Some(response) =
                answer_request(&request, &zone, &corrosion_config, MAX_DNS_PACKET)
                    .or_else(|| forward_udp(&request))
            {
                // A failed reply to one client must not stop the resolver.
                let _ = socket.send_to(&response, source);
            }
            active.fetch_sub(1, Ordering::AcqRel);
        });
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
        let question = super::parse_question(&packet, "coolify.internal", None).unwrap();

        assert_eq!(
            question.name,
            super::Name::Workload {
                workload: "web".into(),
                namespace: "default".into(),
            }
        );
        assert!(
            super::parse_question(&query("web.default.example.com."), "coolify.internal", None)
                .is_err()
        );
    }

    #[test]
    fn parses_ipv4_ptr_queries() {
        let packet = query_with_type("2.0.240.10.in-addr.arpa.", 12);
        let question = super::parse_question(&packet, "coolify.internal", None).unwrap();

        assert_eq!(
            question.name,
            super::Name::Address("10.240.0.2".parse().unwrap())
        );
    }

    #[test]
    fn answers_every_name_of_its_zones_without_a_forward() {
        let answer = |name: &str, record_type: u16| {
            let packet = query_with_type(name, record_type);
            let response = super::answer_request(
                &packet,
                "coolify.internal",
                std::path::Path::new("/nonexistent"),
                super::MAX_DNS_PACKET,
            )
            .expect("a name of the zone is not forwarded");
            assert_eq!(&response[6..8], &[0, 0]);
            [response[2], response[3]]
        };
        const NO_RECORDS: [u8; 2] = [0x85, 0x80];
        const NXDOMAIN: [u8; 2] = [0x85, 0x83];

        assert_eq!(answer("coolify.internal.", 1), NO_RECORDS);
        assert_eq!(answer("web.coolify.internal.", 1), NO_RECORDS);
        assert_eq!(answer("web.default.coolify.internal.", 12), NO_RECORDS);
        assert_eq!(answer("a.web.default.coolify.internal.", 1), NXDOMAIN);
        assert_eq!(answer("web_1.default.coolify.internal.", 1), NXDOMAIN);
        assert_eq!(answer("2.0.240.10.in-addr.arpa.", 1), NO_RECORDS);
        assert_eq!(answer("240.10.in-addr.arpa.", 12), NO_RECORDS);
        assert_eq!(answer("x.2.0.240.10.in-addr.arpa.", 12), NXDOMAIN);
        assert_eq!(answer("300.0.240.10.in-addr.arpa.", 12), NXDOMAIN);
    }

    #[test]
    fn builds_an_authoritative_a_response_for_each_endpoint() {
        let packet = query("web.default.coolify.internal.");
        let question = super::parse_question(&packet, "coolify.internal", None).unwrap();
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
        let question = super::parse_question(&packet, "coolify.internal", None).unwrap();
        let response = super::build_response(&packet, &question, &[]);

        assert_eq!(&response[2..4], &[0x85, 0x80]);
        assert_eq!(&response[6..8], &[0, 0]);
    }

    #[test]
    fn builds_an_authoritative_ptr_response_for_each_workload() {
        let packet = query_with_type("2.0.240.10.in-addr.arpa.", 12);
        let question = super::parse_question(&packet, "coolify.internal", None).unwrap();
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
        let question = super::parse_question(&packet, "coolify.internal", None).unwrap();
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

    /// A database with the Corrosion schema: two Nodes, `api` on two
    /// containers, a stale name of an older revision, and inactive endpoints.
    fn database() -> rusqlite::Connection {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        connection
            .execute_batch(&format!(
                "{}
                INSERT INTO workload_endpoints VALUES
                    ('worker-1', 'nodes', '10.240.0.1', '10.240.0.1', 'running', 'healthy', 1, unixepoch() + 60),
                    ('uuid-api', 'default', '10.240.0.1', '10.241.0.2', 'running', 'healthy', 1, unixepoch() + 60),
                    ('uuid-api', 'default', '10.240.0.2', '10.241.1.2', 'running', 'unknown', 1, unixepoch() + 60),
                    ('uuid-api', 'default', '10.240.0.2', '10.241.1.3', 'running', 'unhealthy', 1, unixepoch() + 60),
                    ('uuid-api', 'default', '10.240.0.2', '10.241.1.4', 'running', 'healthy', 1, unixepoch() - 1),
                    ('uuid-web', 'default', '10.240.0.1', '10.241.0.3', 'removing', 'healthy', 1, unixepoch() + 60);
                INSERT INTO workload_names VALUES
                    ('default', 'api', 'uuid-api', 4, 1),
                    ('default', 'web', 'uuid-web', 4, 1),
                    ('default', 'old-api', 'uuid-api', 3, 1);",
                control::corrosion_schema()
            ))
            .unwrap();
        connection
    }

    fn rows(connection: &rusqlite::Connection, sql: &str, params: &[&str]) -> Vec<String> {
        let mut statement = connection.prepare(sql).unwrap();
        statement
            .query_map(rusqlite::params_from_iter(params), |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    #[test]
    fn endpoint_lookup_resolves_names_through_the_current_name_table() {
        let connection = database();
        let lookup = |name: &str, namespace: &str| {
            rows(
                &connection,
                super::endpoint_lookup_sql(namespace),
                &[name, namespace],
            )
        };

        // Only running, healthy or unknown, unexpired endpoints answer.
        assert_eq!(lookup("api", "default"), ["10.241.0.2", "10.241.1.2"]);
        assert!(lookup("web", "default").is_empty());
        // A name of an older revision no longer resolves, and a workload ID is
        // not a name.
        assert!(lookup("old-api", "default").is_empty());
        assert!(lookup("uuid-api", "default").is_empty());
        assert_eq!(lookup("worker-1", "nodes"), ["10.240.0.1"]);
    }

    #[test]
    fn reverse_lookup_returns_current_names_for_an_address() {
        let connection = database();
        let lookup = |address: &str| {
            rows(
                &connection,
                super::reverse_lookup_sql(),
                &[address, address],
            )
        };

        assert_eq!(lookup("10.241.0.2"), ["api.default"]);
        assert_eq!(lookup("10.240.0.1"), ["worker-1.nodes"]);
        assert!(lookup("10.241.1.3").is_empty());
        assert!(lookup("10.241.0.3").is_empty());

        // A rename applies without touching the endpoint.
        connection
            .execute_batch("UPDATE workload_names SET name = 'backend' WHERE name = 'api'")
            .unwrap();
        assert_eq!(lookup("10.241.0.2"), ["backend.default"]);
    }
}
