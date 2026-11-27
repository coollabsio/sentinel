//! The NVIDIA GPUs of the Node, from the CDI specs that Podman reads
//! (`workload.gpu.v1`, decision 0032 of Coolify). The admin generates the spec
//! with `nvidia-ctk cdi generate`. A spec that does not parse adds no device.

use std::collections::BTreeSet;
use std::path::Path;

use serde::Deserialize;

pub(crate) const GPU_KIND: &str = "nvidia.com/gpu";
const SPEC_DIRECTORIES: [&str; 2] = ["etc/cdi", "var/run/cdi"];
const MAX_SPEC_BYTES: u64 = 4 * 1024 * 1024;
const MAX_SPEC_FILES: usize = 64;
const MAX_CDI_DEVICES: usize = 16;

/// The CDI devices of the kind `nvidia.com/gpu` and a one-line result.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Inventory {
    /// Full names, `nvidia.com/gpu=<name>`, sorted and unique.
    pub(crate) devices: Vec<String>,
    pub(crate) check: String,
}

/// Reads the specs below `root` (`/` on a Node).
pub(crate) fn inventory(root: &Path) -> Inventory {
    let mut devices = BTreeSet::new();
    let mut found_in = Vec::new();
    let mut errors = Vec::new();
    for directory in SPEC_DIRECTORIES {
        let display = format!("/{directory}");
        let entries = match std::fs::read_dir(root.join(directory)) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                errors.push(format!("Could not read {display}: {}.", error.kind()));
                continue;
            }
        };
        let mut files: Vec<_> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension()
                    .and_then(|extension| extension.to_str())
                    .is_some_and(|extension| matches!(extension, "yaml" | "yml" | "json"))
            })
            .collect();
        files.sort();
        files.truncate(MAX_SPEC_FILES);
        for path in files {
            let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let shown = format!("{display}/{file_name}");
            let content = match read_spec(&path) {
                Ok(content) => content,
                Err(error) => {
                    errors.push(format!("Could not read {shown}: {error}."));
                    continue;
                }
            };
            let parsed = if file_name.ends_with(".json") {
                parse_json(&content)
            } else {
                parse_yaml(&content)
            };
            match parsed {
                Ok(Some(names)) => {
                    found_in.push(shown);
                    devices.extend(names.into_iter().map(|name| format!("{GPU_KIND}={name}")));
                }
                Ok(None) => {}
                Err(error) => errors.push(format!("Could not parse {shown}: {error}.")),
            }
        }
    }
    let gpus = devices
        .iter()
        .filter_map(|device| device.strip_prefix("nvidia.com/gpu="))
        .filter(|name| !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_digit()))
        .count();
    let check = if !found_in.is_empty() {
        let mut check = format!(
            "Found {gpus} NVIDIA GPU {} ({} CDI {}) in {}.",
            if gpus == 1 { "device" } else { "devices" },
            devices.len(),
            if devices.len() == 1 { "name" } else { "names" },
            found_in.join(", ")
        );
        for error in &errors {
            check.push(' ');
            check.push_str(error);
        }
        check
    } else if let Some(error) = errors.first() {
        error.clone()
    } else {
        "No CDI spec for nvidia.com/gpu in /etc/cdi or /var/run/cdi.".into()
    };
    Inventory {
        devices: devices.into_iter().collect(),
        check,
    }
}

fn read_spec(path: &Path) -> Result<String, String> {
    let metadata = std::fs::metadata(path).map_err(|error| error.kind().to_string())?;
    if !metadata.is_file() {
        return Err("not a file".into());
    }
    if metadata.len() > MAX_SPEC_BYTES {
        return Err("larger than 4 MiB".into());
    }
    std::fs::read_to_string(path).map_err(|error| error.kind().to_string())
}

/// A device name of the CDI specification.
fn valid_device_name(name: &str) -> bool {
    name.len() <= 128
        && name
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
}

fn checked_names(names: Vec<String>) -> Result<Vec<String>, String> {
    if names.is_empty() {
        return Err("the spec has no devices".into());
    }
    if let Some(name) = names.iter().find(|name| !valid_device_name(name)) {
        return Err(format!(
            "the device name {:?} is invalid",
            name.chars().take(64).collect::<String>()
        ));
    }
    Ok(names)
}

#[derive(Deserialize)]
struct JsonSpec {
    kind: String,
    #[serde(default)]
    devices: Vec<JsonDevice>,
}

#[derive(Deserialize)]
struct JsonDevice {
    name: String,
}

/// The device names of a JSON spec, `None` for a spec of another kind.
fn parse_json(content: &str) -> Result<Option<Vec<String>>, String> {
    let spec: JsonSpec =
        serde_json::from_str(content).map_err(|_| "the JSON is invalid".to_string())?;
    if spec.kind != GPU_KIND {
        return Ok(None);
    }
    checked_names(spec.devices.into_iter().map(|device| device.name).collect()).map(Some)
}

/// The device names of a YAML spec as `nvidia-ctk cdi generate` writes it: the
/// top-level keys `kind:` and `devices:`, and in each item of `devices` a
/// `name:` at the indentation of the item. `None` for a spec of another kind.
/// Flow style, anchors, and more than one document are refused.
fn parse_yaml(content: &str) -> Result<Option<Vec<String>>, String> {
    let mut kind = None;
    let mut names = Vec::new();
    let mut in_devices = false;
    // The indentation of the `-` of a device item, and of its keys.
    let mut item_indent = None;
    let mut seen_content = false;
    for line in content.lines() {
        let trimmed = line.trim_end();
        let text = trimmed.trim_start();
        if text.is_empty() || text.starts_with('#') {
            continue;
        }
        if text == "---" {
            if seen_content {
                return Err("the spec has more than one YAML document".into());
            }
            continue;
        }
        seen_content = true;
        if line.contains('\t') {
            return Err("the YAML has a tab".into());
        }
        let indent = trimmed.len() - text.len();
        if indent == 0 && !text.starts_with('-') {
            in_devices = false;
            let Some((key, value)) = text.split_once(':') else {
                return Err("the YAML is invalid".into());
            };
            let value = value.trim();
            match key {
                "kind" => {
                    if kind.is_some() {
                        return Err("the spec has two kinds".into());
                    }
                    kind = Some(scalar(value)?);
                }
                "devices" => {
                    if !value.is_empty() {
                        return Err("the devices are not a block list".into());
                    }
                    if item_indent.is_some() || !names.is_empty() {
                        return Err("the spec has two device lists".into());
                    }
                    in_devices = true;
                }
                _ => {}
            }
            continue;
        }
        if !in_devices {
            continue;
        }
        let (dash, rest) = match text.strip_prefix('-') {
            Some(rest) if rest.is_empty() || rest.starts_with(' ') => (true, rest.trim_start()),
            _ => (false, text),
        };
        let item = *item_indent.get_or_insert(indent);
        if !dash && item_indent == Some(indent) && indent > 0 {
            // A key at the indentation of the `-` ends an indented list.
            return Err("the YAML is invalid".into());
        }
        let key_indent = if dash && indent == item {
            if rest.is_empty() {
                continue;
            }
            item + 2
        } else {
            indent
        };
        if key_indent != item + 2 {
            continue;
        }
        if let Some(value) = rest.strip_prefix("name:") {
            names.push(scalar(value.trim())?);
        }
    }
    match kind {
        None => Err("the spec has no kind".into()),
        Some(kind) if kind != GPU_KIND => Ok(None),
        Some(_) => checked_names(names).map(Some),
    }
}

/// A plain or quoted YAML scalar without escapes.
fn scalar(value: &str) -> Result<String, String> {
    let unquoted = if let Some(inner) = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
    {
        inner
    } else if let Some(inner) = value
        .strip_prefix('\'')
        .and_then(|value| value.strip_suffix('\''))
    {
        inner
    } else {
        value
    };
    if unquoted.is_empty()
        || unquoted
            .chars()
            .any(|character| "\"'\\{}[]&*!|>%@`#".contains(character) || character.is_control())
    {
        return Err("a YAML value is not supported".into());
    }
    Ok(unquoted.into())
}

/// Validates `cdi_devices` against the current inventory below `root` and
/// returns their `--device` arguments.
pub(crate) fn device_args(root: &Path, names: &[String]) -> Result<Vec<String>, String> {
    if names.is_empty() {
        return Ok(Vec::new());
    }
    if names.len() > MAX_CDI_DEVICES {
        return Err("The workload has too many GPU devices.".into());
    }
    let mut unique = BTreeSet::new();
    for name in names {
        let valid = name
            .strip_prefix(GPU_KIND)
            .and_then(|rest| rest.strip_prefix('='))
            .is_some_and(valid_device_name);
        if !valid {
            return Err("A GPU device must be a CDI name of the kind nvidia.com/gpu.".into());
        }
        if !unique.insert(name.as_str()) {
            return Err(format!("The GPU device {name} is set twice."));
        }
    }
    let inventory = inventory(root);
    let mut args = Vec::with_capacity(names.len() * 2);
    for name in names {
        if !inventory.devices.contains(name) {
            return Err(format!(
                "The GPU device {name} is not in the CDI specs of the Node."
            ));
        }
        args.extend(["--device".into(), name.clone()]);
    }
    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NVIDIA_CTK_YAML: &str = r#"---
cdiVersion: 0.5.0
containerEdits:
  deviceNodes:
  - path: /dev/nvidia-modeset
  - path: /dev/nvidiactl
  env:
  - NVIDIA_VISIBLE_DEVICES=void
  hooks:
  - args:
    - nvidia-cdi-hook
    - create-symlinks
    hookName: createContainer
    path: /usr/bin/nvidia-cdi-hook
  mounts:
  - containerPath: /usr/bin/nvidia-smi
    hostPath: /usr/bin/nvidia-smi
    options:
    - ro
devices:
- containerEdits:
    deviceNodes:
    - path: /dev/nvidia0
  name: "0"
- containerEdits:
    deviceNodes:
    - path: /dev/nvidia0
  name: GPU-6a3c1f0e-1d2b-4c6a-9b5e-2f8e7d6c5b4a
- containerEdits:
    deviceNodes:
    - path: /dev/nvidia1
  name: '1'
- containerEdits:
    deviceNodes:
    - path: /dev/nvidia0
    - path: /dev/nvidia1
  name: all
kind: nvidia.com/gpu
"#;

    const JSON_SPEC: &str = r#"{"cdiVersion":"0.6.0","kind":"nvidia.com/gpu","devices":[{"name":"0","containerEdits":{"deviceNodes":[{"path":"/dev/nvidia0"}]}},{"name":"all","containerEdits":{}}],"containerEdits":{}}"#;

    fn write(root: &Path, path: &str, content: &str) {
        let path = root.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn parses_the_yaml_of_nvidia_ctk() {
        assert_eq!(
            parse_yaml(NVIDIA_CTK_YAML).unwrap().unwrap(),
            ["0", "GPU-6a3c1f0e-1d2b-4c6a-9b5e-2f8e7d6c5b4a", "1", "all"]
        );
        let indented = "kind: nvidia.com/gpu\ndevices:\n  - name: \"0\"\n    containerEdits:\n      deviceNodes:\n        - path: /dev/nvidia0\n  - name: all\n";
        assert_eq!(parse_yaml(indented).unwrap().unwrap(), ["0", "all"]);
        assert_eq!(
            parse_yaml("kind: amd.com/gpu\ndevices:\n- name: \"0\"\n").unwrap(),
            None
        );
    }

    #[test]
    fn parses_a_json_spec() {
        assert_eq!(parse_json(JSON_SPEC).unwrap().unwrap(), ["0", "all"]);
        assert_eq!(
            parse_json(r#"{"kind":"vendor.com/net","devices":[{"name":"x"}]}"#).unwrap(),
            None
        );
    }

    #[test]
    fn refuses_a_broken_spec() {
        for spec in [
            "kind: nvidia.com/gpu\ndevices: [{name: \"0\"}]\n",
            "kind: nvidia.com/gpu\ndevices:\n- name: *anchor\n",
            "devices:\n- name: \"0\"\n",
            "kind: nvidia.com/gpu\ndevices:\n",
            "kind: nvidia.com/gpu\ndevices:\n- name: ../../dev/sda\n",
            "kind: nvidia.com/gpu\ndevices:\n- name: \"0\"\n---\nkind: nvidia.com/gpu\n",
            "kind: nvidia.com/gpu\ndevices:\n\t- name: \"0\"\n",
            "not yaml",
        ] {
            assert!(parse_yaml(spec).is_err(), "{spec:?}");
        }
        assert!(parse_json("{\"kind\":\"nvidia.com/gpu\"").is_err());
        assert!(parse_json(r#"{"kind":"nvidia.com/gpu","devices":[{"name":"a b"}]}"#).is_err());
    }

    #[test]
    fn reports_the_inventory_of_both_directories() {
        let root = tempfile::tempdir().unwrap();
        assert_eq!(
            inventory(root.path()),
            Inventory {
                devices: vec![],
                check: "No CDI spec for nvidia.com/gpu in /etc/cdi or /var/run/cdi.".into(),
            }
        );
        write(root.path(), "etc/cdi/nvidia.yaml", NVIDIA_CTK_YAML);
        write(root.path(), "var/run/cdi/nvidia.json", JSON_SPEC);
        write(
            root.path(),
            "var/run/cdi/other.yaml",
            "kind: vendor.com/net\ndevices:\n- name: x\n",
        );
        write(root.path(), "etc/cdi/README.txt", "ignored");
        let found = inventory(root.path());
        assert_eq!(
            found.devices,
            [
                "nvidia.com/gpu=0",
                "nvidia.com/gpu=1",
                "nvidia.com/gpu=GPU-6a3c1f0e-1d2b-4c6a-9b5e-2f8e7d6c5b4a",
                "nvidia.com/gpu=all",
            ]
        );
        assert_eq!(
            found.check,
            "Found 2 NVIDIA GPU devices (4 CDI names) in /etc/cdi/nvidia.yaml, /var/run/cdi/nvidia.json."
        );
    }

    #[test]
    fn a_broken_spec_adds_no_devices() {
        let root = tempfile::tempdir().unwrap();
        write(
            root.path(),
            "etc/cdi/nvidia.yaml",
            "kind: nvidia.com/gpu\ndevices: [x]\n",
        );
        let found = inventory(root.path());
        assert!(found.devices.is_empty());
        assert_eq!(
            found.check,
            "Could not parse /etc/cdi/nvidia.yaml: the devices are not a block list."
        );
    }

    #[test]
    fn gives_devices_of_the_inventory_only() {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "etc/cdi/nvidia.yaml", NVIDIA_CTK_YAML);
        let names = |values: &[&str]| {
            values
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            device_args(
                root.path(),
                &names(&["nvidia.com/gpu=0", "nvidia.com/gpu=all"])
            )
            .unwrap(),
            [
                "--device",
                "nvidia.com/gpu=0",
                "--device",
                "nvidia.com/gpu=all"
            ]
        );
        assert_eq!(
            device_args(root.path(), &names(&["nvidia.com/gpu=7"])).unwrap_err(),
            "The GPU device nvidia.com/gpu=7 is not in the CDI specs of the Node."
        );
        for name in [
            "amd.com/gpu=0",
            "nvidia.com/gpu",
            "nvidia.com/gpu=",
            "/dev/sda",
            "nvidia.com/gpu=0,/dev/sda",
        ] {
            assert_eq!(
                device_args(root.path(), &names(&[name])).unwrap_err(),
                "A GPU device must be a CDI name of the kind nvidia.com/gpu.",
                "{name}"
            );
        }
        assert_eq!(
            device_args(
                root.path(),
                &names(&["nvidia.com/gpu=0", "nvidia.com/gpu=0"])
            )
            .unwrap_err(),
            "The GPU device nvidia.com/gpu=0 is set twice."
        );
        let empty = tempfile::tempdir().unwrap();
        assert!(device_args(empty.path(), &names(&["nvidia.com/gpu=0"])).is_err());
    }
}
