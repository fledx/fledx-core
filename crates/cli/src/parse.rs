use chrono::{DateTime, Duration as ChronoDuration, Utc};
use common::api;
use uuid::Uuid;

pub fn parse_kv(s: &str) -> Result<(String, String), String> {
    let (k, v) = s
        .split_once('=')
        .ok_or_else(|| "env must be KEY=VALUE".to_string())?;
    if k.is_empty() {
        return Err("env key cannot be empty".into());
    }
    Ok((k.to_string(), v.to_string()))
}

pub fn parse_uuid(value: &str) -> Result<Uuid, String> {
    Uuid::parse_str(value).map_err(|err| format!("invalid UUID '{}': {}", value, err))
}

pub fn parse_duration_arg(input: &str) -> Result<ChronoDuration, String> {
    let trimmed = input.trim().to_lowercase();
    if trimmed.len() < 2 {
        return Err("range must include a positive value and unit (s|m|h|d)".into());
    }

    let (value_part, unit_part) = trimmed.split_at(trimmed.len() - 1);
    let value: i64 = value_part
        .parse()
        .map_err(|_| format!("invalid range '{}': expected number+unit", input))?;
    if value <= 0 {
        return Err("range must be greater than zero".into());
    }

    match unit_part {
        "s" => Ok(ChronoDuration::seconds(value)),
        "m" => Ok(ChronoDuration::minutes(value)),
        "h" => Ok(ChronoDuration::hours(value)),
        "d" => Ok(ChronoDuration::days(value)),
        _ => Err("range unit must be one of: s, m, h, d".into()),
    }
}

fn parse_secret_env_with_optional(input: &str, optional: bool) -> Result<api::SecretEnv, String> {
    let (name, secret) = input
        .split_once('=')
        .ok_or_else(|| "secret env must be NAME=SECRET_NAME".to_string())?;
    if name.trim().is_empty() {
        return Err("secret env name cannot be empty".into());
    }
    if name.chars().any(char::is_whitespace) || name.contains('=') {
        return Err("secret env name cannot include whitespace or '='".into());
    }
    if secret.trim().is_empty() {
        return Err("secret env secret cannot be empty".into());
    }
    if secret
        .chars()
        .any(|c| c.is_whitespace() || c == '/' || c == '\\')
    {
        return Err("secret env secret cannot include slashes or whitespace".into());
    }

    Ok(api::SecretEnv {
        name: name.to_string(),
        secret: secret.to_string(),
        optional,
    })
}

pub fn parse_secret_env(input: &str) -> Result<api::SecretEnv, String> {
    parse_secret_env_with_optional(input, false)
}

pub fn parse_optional_secret_env(input: &str) -> Result<api::SecretEnv, String> {
    parse_secret_env_with_optional(input, true)
}

fn parse_secret_file_with_optional(input: &str, optional: bool) -> Result<api::SecretFile, String> {
    let (path, secret) = input
        .split_once('=')
        .ok_or_else(|| "secret file must be /path=SECRET_NAME".to_string())?;
    if path.is_empty() {
        return Err("secret file path cannot be empty".into());
    }
    if !path.starts_with('/') {
        return Err("secret file path must be absolute".into());
    }
    if path.contains(['\n', '\r']) {
        return Err("secret file path cannot include newlines".into());
    }
    if secret.trim().is_empty() {
        return Err("secret file secret cannot be empty".into());
    }
    if secret
        .chars()
        .any(|c| c.is_whitespace() || c == '/' || c == '\\')
    {
        return Err("secret file secret cannot include slashes or whitespace".into());
    }

    Ok(api::SecretFile {
        path: path.to_string(),
        secret: secret.to_string(),
        optional,
    })
}

pub fn parse_secret_file(input: &str) -> Result<api::SecretFile, String> {
    parse_secret_file_with_optional(input, false)
}

pub fn parse_optional_secret_file(input: &str) -> Result<api::SecretFile, String> {
    parse_secret_file_with_optional(input, true)
}

pub fn parse_timestamp(value: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|err| format!("invalid timestamp '{}': {}", value, err))
}

pub fn parse_volume(input: &str) -> Result<api::VolumeMount, String> {
    let parts: Vec<&str> = input.split(':').collect();
    if parts.len() < 2 || parts.len() > 3 {
        return Err("volume must be HOST_PATH:CONTAINER_PATH[:ro|rw]".into());
    }
    let host_path = parts[0].trim();
    let container_path = parts[1].trim();
    if host_path.is_empty() || container_path.is_empty() {
        return Err("volume paths cannot be empty".into());
    }
    if !host_path.starts_with('/') {
        return Err("host path must be absolute".into());
    }
    if !container_path.starts_with('/') {
        return Err("container path must be absolute".into());
    }
    let read_only = match parts.get(2) {
        None => None,
        Some(flag) => match flag.trim() {
            "ro" => Some(true),
            "rw" => Some(false),
            other => {
                return Err(format!("volume flag must be 'ro' or 'rw', got '{other}'"));
            }
        },
    };

    Ok(api::VolumeMount {
        host_path: host_path.to_string(),
        container_path: container_path.to_string(),
        read_only,
    })
}

pub fn parse_port(s: &str) -> Result<api::PortMapping, String> {
    let trimmed = s.trim();
    let (spec, options) = match trimmed.split_once(',') {
        Some((base, opts)) => (base.trim(), Some(opts)),
        None => (trimmed, None),
    };
    if spec.is_empty() {
        return Err("port specification cannot be empty".into());
    }

    let mut expose = false;
    if let Some(opts) = options {
        for token in opts.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            let (name, value) = if let Some((key, val)) = token.split_once('=') {
                (key.trim(), Some(val.trim()))
            } else {
                (token, None)
            };
            match name.to_ascii_lowercase().as_str() {
                "expose" => match value {
                    None => expose = true,
                    Some(val) => match val.to_ascii_lowercase().as_str() {
                        "true" => expose = true,
                        "false" => expose = false,
                        other => {
                            return Err(format!(
                                "expose option must be true or false, got '{other}'"
                            ));
                        }
                    },
                },
                other => {
                    return Err(format!("unknown port option '{other}'"));
                }
            }
        }
    }

    let (base, protocol) = if let Some((left, proto)) = spec.rsplit_once('/') {
        let proto_lower = proto.trim().to_ascii_lowercase();
        if proto_lower != "tcp" && proto_lower != "udp" {
            return Err("protocol must be tcp or udp".into());
        }
        (left, proto_lower)
    } else {
        (spec, "tcp".into())
    };

    let parts: Vec<&str> = base.split(':').collect();
    let (host_ip, host_port, container_port) = match parts.as_slice() {
        [single] => {
            let port = parse_port_num(single)?;
            (None, Some(port), port)
        }
        [host, container] => (
            None,
            parse_optional_host_port(host)?,
            parse_port_num(container)?,
        ),
        [ip, host, container] => {
            let ip = ip.trim();
            if ip.is_empty() {
                return Err("host_ip cannot be empty".into());
            }
            (
                Some(ip.to_string()),
                parse_optional_host_port(host)?,
                parse_port_num(container)?,
            )
        }
        _ => {
            return Err(
                "port must be <container>[/proto], <host_or_auto>:<container>[/proto], or <ip>:<host_or_auto>:<container>[/proto]"
                    .into(),
            )
        }
    };

    Ok(api::PortMapping {
        container_port,
        host_port,
        protocol,
        host_ip,
        expose,
        endpoint: None,
    })
}

pub fn parse_port_num(input: &str) -> Result<u16, String> {
    let trimmed = input.trim();
    let port: u16 = trimmed
        .parse()
        .map_err(|_| format!("invalid port '{}'", trimmed))?;
    if port == 0 {
        return Err("port must be between 1 and 65535".into());
    }
    Ok(port)
}

pub fn parse_optional_host_port(input: &str) -> Result<Option<u16>, String> {
    if input.trim().is_empty() {
        return Ok(None);
    }
    if input.eq_ignore_ascii_case("auto") {
        return Ok(None);
    }
    parse_port_num(input).map(Some)
}

pub fn validate_domain(domain: &str) -> Result<(), String> {
    let trimmed = domain.trim();
    if trimmed.is_empty() {
        return Err("domain cannot be empty".into());
    }
    if trimmed.len() > 253 {
        return Err("domain must be 253 characters or fewer".into());
    }
    if trimmed.ends_with('.') || trimmed.starts_with('.') {
        return Err("domain cannot start or end with '.'".into());
    }
    if trimmed.contains(' ') {
        return Err("domain cannot contain whitespace".into());
    }

    let labels: Vec<&str> = trimmed.split('.').collect();
    if labels.len() < 2 {
        return Err("domain must include at least one dot".into());
    }

    for label in labels {
        if label.is_empty() {
            return Err("domain labels cannot be empty".into());
        }
        if label.len() > 63 {
            return Err("domain labels must be 63 characters or fewer".into());
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err("domain labels may only contain letters, numbers, or '-'".into());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("domain labels cannot start or end with '-'".into());
        }
    }

    Ok(())
}

pub fn validate_path_prefix(path: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err("path prefix cannot be empty".into());
    }
    if !path.starts_with('/') {
        return Err("path prefix must start with '/'".into());
    }
    if path.contains(' ') {
        return Err("path prefix cannot contain whitespace".into());
    }
    Ok(())
}

pub fn validate_tls_ref(tls_ref: &str) -> Result<(), String> {
    if tls_ref.trim().is_empty() {
        return Err("TLS reference cannot be empty".into());
    }
    Ok(())
}

/// Ensure backend identifiers are not the nil UUID.
pub fn validate_backend_id(backend_id: Uuid) -> Result<(), String> {
    if backend_id == Uuid::nil() {
        return Err("backend id cannot be the nil UUID".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::SecondsFormat;

    #[test]
    fn parse_uuid_returns_error_for_invalid_input() {
        assert!(parse_uuid("not-a-uuid").is_err());
        let valid = Uuid::new_v4().to_string();
        assert_eq!(
            parse_uuid(&valid).unwrap(),
            Uuid::parse_str(&valid).unwrap()
        );
    }

    #[test]
    fn parse_kv_rejects_missing_separator_and_empty_key() {
        assert!(parse_kv("missing").is_err());
        let err = parse_kv("=value").unwrap_err();
        assert!(err.contains("env key cannot be empty"));
    }

    #[test]
    fn parse_kv_parses_key_value() {
        let (key, value) = parse_kv("FOO=bar").expect("kv");
        assert_eq!(key, "FOO");
        assert_eq!(value, "bar");
    }

    #[test]
    fn parse_duration_arg_parses_units() {
        assert_eq!(
            parse_duration_arg("5m").unwrap(),
            ChronoDuration::minutes(5)
        );
        assert_eq!(parse_duration_arg("2h").unwrap(), ChronoDuration::hours(2));
    }

    #[test]
    fn parse_duration_arg_rejects_invalid_inputs() {
        assert!(parse_duration_arg("0m").is_err());
        assert!(parse_duration_arg("12").is_err());
        assert!(parse_duration_arg("12w").is_err());
    }

    #[test]
    fn parse_timestamp_parses_rfc3339() {
        let parsed = parse_timestamp("2024-01-02T03:04:05Z").expect("timestamp");
        assert_eq!(
            parsed.to_rfc3339_opts(SecondsFormat::Secs, true),
            "2024-01-02T03:04:05Z"
        );
    }

    #[test]
    fn parse_timestamp_rejects_invalid() {
        assert!(parse_timestamp("not-a-timestamp").is_err());
    }

    #[test]
    fn parse_port_supports_host_and_protocol() {
        let port = parse_port("127.0.0.1:8080:80/udp").unwrap();
        assert_eq!(
            port,
            api::PortMapping {
                container_port: 80,
                host_port: Some(8080),
                protocol: "udp".into(),
                host_ip: Some("127.0.0.1".into()),
                expose: false,
                endpoint: None
            }
        );
    }

    #[test]
    fn parse_port_defaults_host_port_and_protocol() {
        let port = parse_port("80").unwrap();
        assert_eq!(
            port,
            api::PortMapping {
                container_port: 80,
                host_port: Some(80),
                protocol: "tcp".into(),
                host_ip: None,
                expose: false,
                endpoint: None
            }
        );
    }

    #[test]
    fn parse_port_allows_auto_host_port() {
        let port = parse_port("auto:8080/udp").unwrap();
        assert_eq!(
            port,
            api::PortMapping {
                container_port: 8080,
                host_port: None,
                protocol: "udp".into(),
                host_ip: None,
                expose: false,
                endpoint: None
            }
        );
    }

    #[test]
    fn parse_port_allows_blank_host_for_auto_assignment() {
        let port = parse_port(":8080/tcp").unwrap();
        assert_eq!(
            port,
            api::PortMapping {
                container_port: 8080,
                host_port: None,
                protocol: "tcp".into(),
                host_ip: None,
                expose: false,
                endpoint: None
            }
        );
    }

    #[test]
    fn parse_port_allows_blank_host_with_ip() {
        let port = parse_port("127.0.0.1::8080").unwrap();
        assert_eq!(
            port,
            api::PortMapping {
                container_port: 8080,
                host_port: None,
                protocol: "tcp".into(),
                host_ip: Some("127.0.0.1".into()),
                expose: false,
                endpoint: None
            }
        );
    }

    #[test]
    fn parse_port_accepts_expose_option() {
        let port = parse_port("8080,expose").unwrap();
        assert!(port.expose);
        assert_eq!(port.container_port, 8080);
        assert_eq!(port.host_port, Some(8080));
    }

    #[test]
    fn parse_port_accepts_explicit_false_expose() {
        let port = parse_port("8080,expose=false").unwrap();
        assert!(!port.expose);
    }

    #[test]
    fn parse_port_rejects_invalid_expose_value() {
        let err = parse_port("8080,expose=maybe").unwrap_err();
        assert!(err.contains("expose option must be true or false"));
    }

    #[test]
    fn parse_port_rejects_unknown_option() {
        assert!(parse_port("8080,bogus").is_err());
    }

    #[test]
    fn parse_port_rejects_invalid() {
        assert!(parse_port("80/sctp").is_err());
        assert!(parse_port("0").is_err());
        assert!(parse_port("a:b:c:d").is_err());
    }

    #[test]
    fn parse_volume_accepts_ro_and_rw() {
        let ro = parse_volume("/data:/var/data:ro").unwrap();
        assert_eq!(ro.host_path, "/data");
        assert_eq!(ro.container_path, "/var/data");
        assert_eq!(ro.read_only, Some(true));

        let rw = parse_volume("/logs:/var/log:rw").unwrap();
        assert_eq!(rw.read_only, Some(false));

        let default = parse_volume("/cache:/var/cache").unwrap();
        assert_eq!(default.read_only, None);
    }

    #[test]
    fn parse_volume_rejects_relative_or_bad_flag() {
        assert!(parse_volume("data:/var").is_err());
        assert!(parse_volume("/data:var").is_err());
        assert!(parse_volume("/data:/var:bogus").is_err());
        assert!(parse_volume("/data").is_err());
    }

    #[test]
    fn parse_secret_env_sets_optional_flag() {
        let required = parse_secret_env("TOKEN=api").expect("secret env");
        assert_eq!(required.name, "TOKEN");
        assert_eq!(required.secret, "api");
        assert!(!required.optional);

        let optional = parse_optional_secret_env("TOKEN=api").expect("optional secret env");
        assert!(optional.optional);
    }

    #[test]
    fn parse_secret_file_rejects_relative_path() {
        assert!(parse_secret_file("relative=secret").is_err());
        let parsed = parse_secret_file("/etc/secret=api").expect("secret file");
        assert_eq!(parsed.path, "/etc/secret");
        assert_eq!(parsed.secret, "api");
        assert!(!parsed.optional);
    }

    #[test]
    fn validate_domain_rejects_bad_inputs() {
        assert!(validate_domain("").is_err());
        assert!(validate_domain("example").is_err());
        assert!(validate_domain("-bad.example.com").is_err());
        assert!(validate_domain("bad-.example.com").is_err());
        assert!(validate_domain("ex ample.com").is_err());
    }

    #[test]
    fn validate_domain_accepts_common_domain() {
        assert!(validate_domain("api.example.com").is_ok());
    }

    #[test]
    fn validate_path_prefix_checks_shape() {
        assert!(validate_path_prefix("/").is_ok());
        assert!(validate_path_prefix("/api/v1").is_ok());
        assert!(validate_path_prefix("api").is_err());
        assert!(validate_path_prefix("").is_err());
    }

    #[test]
    fn validate_tls_ref_rejects_empty() {
        assert!(validate_tls_ref("").is_err());
        assert!(validate_tls_ref("   ").is_err());
        assert!(validate_tls_ref("tls-prod").is_ok());
    }

    #[test]
    fn validate_backend_id_rejects_nil() {
        assert!(validate_backend_id(Uuid::nil()).is_err());
        assert!(validate_backend_id(Uuid::new_v4()).is_ok());
    }
}
