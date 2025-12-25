use std::str::FromStr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperatorRole {
    Admin,
    Operator,
    ReadOnly,
}

impl OperatorRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            OperatorRole::Admin => "admin",
            OperatorRole::Operator => "operator",
            OperatorRole::ReadOnly => "read_only",
        }
    }
}

impl FromStr for OperatorRole {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let normalized = value.trim().to_ascii_lowercase().replace('-', "_");
        match normalized.as_str() {
            "admin" => Ok(OperatorRole::Admin),
            "operator" => Ok(OperatorRole::Operator),
            "read_only" | "readonly" => Ok(OperatorRole::ReadOnly),
            _ => Err(()),
        }
    }
}

pub const ADMIN_SCOPES: [&str; 14] = [
    "deployment.read",
    "deployment.write",
    "config.read",
    "config.write",
    "node.read",
    "node_token.rotate",
    "metrics.read",
    "usage.read",
    "ingress_route.read",
    "ingress_route.write",
    "tls_cert.read",
    "tls_cert.write",
    "audit_log.read",
    "operator_token.manage",
];

pub const OPERATOR_SCOPES: [&str; 12] = [
    "deployment.read",
    "deployment.write",
    "config.read",
    "config.write",
    "node.read",
    "metrics.read",
    "usage.read",
    "ingress_route.read",
    "ingress_route.write",
    "tls_cert.read",
    "tls_cert.write",
    "audit_log.read",
];

pub const READ_ONLY_SCOPES: [&str; 8] = [
    "deployment.read",
    "config.read",
    "node.read",
    "metrics.read",
    "usage.read",
    "ingress_route.read",
    "tls_cert.read",
    "audit_log.read",
];

pub const VALID_SCOPES: [&str; 14] = ADMIN_SCOPES;

pub fn default_scopes_for_role(role: OperatorRole) -> Vec<String> {
    let scopes = match role {
        OperatorRole::Admin => ADMIN_SCOPES.as_slice(),
        OperatorRole::Operator => OPERATOR_SCOPES.as_slice(),
        OperatorRole::ReadOnly => READ_ONLY_SCOPES.as_slice(),
    };
    scopes.iter().map(|scope| (*scope).to_string()).collect()
}

pub fn is_valid_scope(scope: &str) -> bool {
    VALID_SCOPES.contains(&scope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn to_vec(scopes: &[&str]) -> Vec<String> {
        scopes.iter().map(|scope| (*scope).to_string()).collect()
    }

    #[test]
    fn operator_role_from_str_normalizes_input() {
        assert_eq!(
            OperatorRole::from_str("ADMIN").unwrap(),
            OperatorRole::Admin
        );
        assert_eq!(
            OperatorRole::from_str("read-only").unwrap(),
            OperatorRole::ReadOnly
        );
        assert_eq!(
            OperatorRole::from_str("  read_only ").unwrap(),
            OperatorRole::ReadOnly
        );
    }

    #[test]
    fn operator_role_from_str_rejects_unknown_role() {
        assert!(OperatorRole::from_str("superuser").is_err());
    }

    #[test]
    fn default_scopes_match_role() {
        assert_eq!(
            default_scopes_for_role(OperatorRole::Admin),
            to_vec(&ADMIN_SCOPES)
        );
        assert_eq!(
            default_scopes_for_role(OperatorRole::Operator),
            to_vec(&OPERATOR_SCOPES)
        );
        assert_eq!(
            default_scopes_for_role(OperatorRole::ReadOnly),
            to_vec(&READ_ONLY_SCOPES)
        );
    }

    #[test]
    fn is_valid_scope_filters_unknown_scopes() {
        assert!(is_valid_scope("deployment.read"));
        assert!(!is_valid_scope("deployment.delete"));
    }
}
