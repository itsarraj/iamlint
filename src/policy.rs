use serde_json::Value;

/// One `Statement` entry from an IAM policy document, normalized so the
/// rest of this crate never has to care whether `Action`/`Resource` was
/// written as a bare string or an array — the IAM policy grammar allows
/// both interchangeably and real-world policies use both forms.
#[derive(Debug, Clone, Default)]
pub struct Statement {
    pub sid: Option<String>,
    pub effect: String,
    pub actions: Vec<String>,
    pub not_actions: Vec<String>,
    /// `Resource` values. Empty + `resource_present == false` means the
    /// key was absent entirely (which, for an `Allow` statement, means
    /// unconstrained in practice for any action that doesn't itself
    /// require a specific resource-level ARN).
    pub resources: Vec<String>,
    pub resource_present: bool,
    pub not_resources: Vec<String>,
    pub not_resource_present: bool,
    /// Raw `Principal` value, kept as-is (string or object) since the
    /// wildcard-principal check needs to look inside `{"AWS": "*"}` /
    /// `{"AWS": ["*", ...]}` shapes, not just a bare `"*"`.
    pub principal: Option<Value>,
    pub has_condition: bool,
}

#[derive(Debug, Clone)]
pub struct Policy {
    pub version: Option<String>,
    pub statements: Vec<Statement>,
}

/// Accepts a JSON value that's either a bare string or an array of
/// strings — the shape `Action`, `NotAction`, `Resource`, and
/// `NotResource` all share in the IAM policy grammar.
fn string_list(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

fn condition_is_meaningful(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Object(map)) => !map.is_empty(),
        _ => false,
    }
}

pub fn parse_policy(content: &str) -> Result<Policy, String> {
    let root: Value = serde_json::from_str(content).map_err(|e| format!("not valid JSON: {e}"))?;

    let version = root
        .get("Version")
        .and_then(Value::as_str)
        .map(String::from);

    let statement_value = root.get("Statement").ok_or_else(|| {
        "no top-level \"Statement\" key found — is this an IAM policy document?".to_string()
    })?;

    // A single statement may be written as one bare object instead of a
    // one-element array — both are valid IAM policy JSON.
    let raw_statements: Vec<&Value> = match statement_value {
        Value::Array(items) => items.iter().collect(),
        Value::Object(_) => vec![statement_value],
        _ => return Err("\"Statement\" must be an object or an array of objects".to_string()),
    };

    let mut statements = Vec::with_capacity(raw_statements.len());
    for (idx, raw) in raw_statements.iter().enumerate() {
        let effect = raw
            .get("Effect")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("statement {idx}: missing required \"Effect\" field"))?
            .to_string();

        statements.push(Statement {
            sid: raw.get("Sid").and_then(Value::as_str).map(String::from),
            effect,
            actions: string_list(raw.get("Action")),
            not_actions: string_list(raw.get("NotAction")),
            resources: string_list(raw.get("Resource")),
            resource_present: raw.get("Resource").is_some(),
            not_resources: string_list(raw.get("NotResource")),
            not_resource_present: raw.get("NotResource").is_some(),
            principal: raw.get("Principal").cloned(),
            has_condition: condition_is_meaningful(raw.get("Condition")),
        });
    }

    Ok(Policy {
        version,
        statements,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_action_and_resource_as_bare_strings() {
        let content = r#"{
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*"
            }
        }"#;
        let policy = parse_policy(content).unwrap();
        assert_eq!(policy.statements.len(), 1);
        assert_eq!(policy.statements[0].actions, vec!["s3:GetObject"]);
        assert_eq!(
            policy.statements[0].resources,
            vec!["arn:aws:s3:::my-bucket/*"]
        );
    }

    #[test]
    fn parses_action_and_resource_as_arrays() {
        let content = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "Multi",
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": ["arn:aws:s3:::a/*", "arn:aws:s3:::b/*"]
            }]
        }"#;
        let policy = parse_policy(content).unwrap();
        let stmt = &policy.statements[0];
        assert_eq!(stmt.sid.as_deref(), Some("Multi"));
        assert_eq!(stmt.actions.len(), 2);
        assert_eq!(stmt.resources.len(), 2);
    }

    #[test]
    fn missing_resource_key_is_recorded_as_absent_not_empty() {
        let content = r#"{
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "iam:*"}]
        }"#;
        let policy = parse_policy(content).unwrap();
        assert!(!policy.statements[0].resource_present);
        assert!(policy.statements[0].resources.is_empty());
    }

    #[test]
    fn condition_object_with_content_is_meaningful() {
        let content = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": "*",
                "Condition": {"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}}
            }]
        }"#;
        let policy = parse_policy(content).unwrap();
        assert!(policy.statements[0].has_condition);
    }

    #[test]
    fn empty_condition_object_is_not_meaningful() {
        let content = r#"{
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*", "Condition": {}}]
        }"#;
        let policy = parse_policy(content).unwrap();
        assert!(!policy.statements[0].has_condition);
    }

    #[test]
    fn principal_is_captured_raw_for_later_wildcard_inspection() {
        let content = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::bucket/*"
            }]
        }"#;
        let policy = parse_policy(content).unwrap();
        assert!(policy.statements[0].principal.is_some());
    }

    #[test]
    fn missing_statement_key_is_a_clean_error() {
        let content = r#"{"Version": "2012-10-17"}"#;
        assert!(parse_policy(content).is_err());
    }

    #[test]
    fn missing_effect_is_a_clean_error() {
        let content =
            r#"{"Version": "2012-10-17", "Statement": [{"Action": "*", "Resource": "*"}]}"#;
        assert!(parse_policy(content).is_err());
    }

    #[test]
    fn malformed_json_is_a_clean_error() {
        assert!(parse_policy("not json at all {{{").is_err());
    }

    #[test]
    fn notaction_and_notresource_are_captured() {
        let content = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "NotAction": "iam:*",
                "NotResource": "arn:aws:s3:::protected/*"
            }]
        }"#;
        let policy = parse_policy(content).unwrap();
        let stmt = &policy.statements[0];
        assert!(stmt.actions.is_empty());
        assert_eq!(stmt.not_actions, vec!["iam:*"]);
        assert!(stmt.not_resource_present);
    }
}
