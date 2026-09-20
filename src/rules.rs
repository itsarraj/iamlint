use serde::Serialize;
use serde_json::Value;

use crate::policy::{Policy, Statement};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub statement_index: usize,
    pub sid: Option<String>,
    pub rule: &'static str,
    pub severity: Severity,
    pub message: String,
}

/// Case-insensitive glob match supporting `*` (any run, including empty)
/// and `?` (exactly one character) — the same two wildcard characters
/// AWS's own IAM policy grammar recognizes inside `Action`/`Resource`
/// strings. Classic two-pointer matcher with backtracking on the most
/// recent `*`.
fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.to_lowercase().chars().collect();
    let text: Vec<char> = text.to_lowercase().chars().collect();

    let (mut p, mut t) = (0usize, 0usize);
    let (mut star_p, mut star_t) = (None, 0usize);

    while t < text.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star_p = Some(p);
            star_t = t;
            p += 1;
        } else if let Some(sp) = star_p {
            p = sp + 1;
            star_t += 1;
            t = star_t;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}

/// Two action patterns "overlap" if either one, read as a glob, matches
/// the other's literal text. This is a heuristic, not a full set-overlap
/// solver (two genuinely partial wildcards like `iam:C*` and `iam:*User`
/// aren't resolved precisely) — see README.
fn actions_overlap(a: &str, b: &str) -> bool {
    glob_match(a, b) || glob_match(b, a)
}

/// Actions whose unconditional grant is a well-documented privilege-
/// escalation or blast-radius risk: full-service wildcards for IAM/STS/
/// Organizations/KMS, plus specific destructive or trust-boundary
/// actions across S3/EC2/RDS. Matched case-insensitively and via
/// [`actions_overlap`], so a statement granting `iam:*` is caught by the
/// literal `iam:*` entry, and a statement granting exactly
/// `iam:CreateAccessKey` is caught by the same entry via glob overlap.
const SENSITIVE_ACTIONS: &[&str] = &[
    "iam:*",
    "iam:createuser",
    "iam:createaccesskey",
    "iam:attachuserpolicy",
    "iam:attachrolepolicy",
    "iam:putuserpolicy",
    "iam:putrolepolicy",
    "iam:updateassumerolepolicy",
    "iam:passrole",
    "iam:createpolicyversion",
    "iam:setdefaultpolicyversion",
    "iam:deleteuserpolicy",
    "iam:deleterolepolicy",
    "sts:assumerole",
    "s3:deletebucket",
    "s3:deletebucketpolicy",
    "s3:putbucketpolicy",
    "s3:putbucketacl",
    "s3:putbucketpublicaccessblock",
    "ec2:terminateinstances",
    "rds:deletedbinstance",
    "rds:deletedbcluster",
    "kms:scheduledeletion",
    "kms:disablekey",
    "kms:putkeypolicy",
    "organizations:leaveorganization",
    "organizations:deleteorganization",
    "cloudtrail:deletetrail",
    "cloudtrail:stoplogging",
];

/// Read-only verb prefixes (matched against the part of the action after
/// the `:`) that AWS's own IAM documentation says require `Resource: "*"`
/// — there's no resource-level ARN a `DescribeInstances`-style call can
/// be scoped to. A statement whose *every* action is one of these is not
/// flagged for having an unconstrained resource; this is what keeps a
/// genuinely least-privilege policy from being drowned in false
/// positives for a pattern AWS itself requires.
const SAFE_READ_VERBS: &[&str] = &[
    "describe", "get", "list", "view", "head", "check", "lookup", "search", "query",
];

fn is_safe_read_action(action: &str) -> bool {
    let verb = action.split_once(':').map(|(_, v)| v).unwrap_or(action);
    let verb_lower = verb.to_lowercase();
    SAFE_READ_VERBS.iter().any(|v| verb_lower.starts_with(v))
}

fn resource_unconstrained(stmt: &Statement) -> bool {
    !stmt.resource_present || stmt.resources.iter().any(|r| r == "*")
}

fn is_allow(stmt: &Statement) -> bool {
    stmt.effect.eq_ignore_ascii_case("Allow")
}

fn rule_wildcard_action(idx: usize, stmt: &Statement) -> Option<Finding> {
    if !is_allow(stmt) || !stmt.actions.iter().any(|a| a == "*") {
        return None;
    }
    let (severity, message) = if resource_unconstrained(stmt) {
        (
            Severity::Critical,
            "Action: \"*\" combined with an unconstrained Resource (\"*\" or omitted) — \
             equivalent to full administrator access for this statement"
                .to_string(),
        )
    } else {
        (
            Severity::High,
            format!(
                "Action: \"*\" allows every AWS action, even though Resource is scoped to {:?}",
                stmt.resources
            ),
        )
    };
    Some(Finding {
        statement_index: idx,
        sid: stmt.sid.clone(),
        rule: "wildcard-action",
        severity,
        message,
    })
}

fn rule_unconstrained_resource(idx: usize, stmt: &Statement) -> Option<Finding> {
    if !is_allow(stmt) || !resource_unconstrained(stmt) {
        return None;
    }
    if stmt.actions.iter().any(|a| a == "*") {
        // Already fully covered by rule_wildcard_action's Critical finding.
        return None;
    }
    if stmt.actions.is_empty() {
        // A bare NotAction statement with no Action list — there's no
        // concrete verb set to judge as "safe read-only" here, and
        // rule_notaction_with_allow already flags the real risk in this
        // shape without a misleading empty-list message.
        return None;
    }
    if stmt.actions.iter().all(|a| is_safe_read_action(a)) {
        return None; // legitimate Describe*/Get*/List*-style requirement
    }
    let resource_desc = if stmt.resource_present {
        "Resource: \"*\"".to_string()
    } else {
        "no Resource key at all (defaults to unconstrained)".to_string()
    };
    Some(Finding {
        statement_index: idx,
        sid: stmt.sid.clone(),
        rule: "unconstrained-resource",
        severity: Severity::Medium,
        message: format!(
            "{resource_desc} for action(s) {:?}, which are not limited to read-only \
             Describe/Get/List-style verbs that AWS requires \"*\" for",
            stmt.actions
        ),
    })
}

fn rule_sensitive_action_without_condition(idx: usize, stmt: &Statement) -> Option<Finding> {
    if !is_allow(stmt) || stmt.has_condition {
        return None;
    }
    let matched: Vec<&String> = stmt
        .actions
        .iter()
        .filter(|a| SENSITIVE_ACTIONS.iter().any(|s| actions_overlap(a, s)))
        .collect();
    if matched.is_empty() {
        return None;
    }
    Some(Finding {
        statement_index: idx,
        sid: stmt.sid.clone(),
        rule: "sensitive-action-no-condition",
        severity: Severity::High,
        message: format!(
            "Sensitive action(s) {matched:?} allowed with no Condition — a scoping \
             Condition (e.g. iam:PassedToService, aws:SourceIp, aws:MultiFactorAuthPresent) \
             is the usual guard for actions this broad"
        ),
    })
}

fn principal_has_wildcard(value: &Value) -> bool {
    match value {
        Value::String(s) => s == "*",
        Value::Object(map) => map.values().any(|v| match v {
            Value::String(s) => s == "*",
            Value::Array(items) => items.iter().any(|i| i.as_str() == Some("*")),
            _ => false,
        }),
        _ => false,
    }
}

fn rule_wildcard_principal(idx: usize, stmt: &Statement) -> Option<Finding> {
    if !is_allow(stmt) {
        return None;
    }
    let principal = stmt.principal.as_ref()?;
    if !principal_has_wildcard(principal) {
        return None;
    }
    Some(Finding {
        statement_index: idx,
        sid: stmt.sid.clone(),
        rule: "wildcard-principal",
        severity: Severity::Critical,
        message: "Principal: \"*\" (or {\"AWS\": \"*\"}) — any AWS account, or the public \
                   internet for an unauthenticated resource policy, can take this action"
            .to_string(),
    })
}

fn rule_notaction_with_allow(idx: usize, stmt: &Statement) -> Option<Finding> {
    if !is_allow(stmt) || stmt.not_actions.is_empty() {
        return None;
    }
    Some(Finding {
        statement_index: idx,
        sid: stmt.sid.clone(),
        rule: "notaction-with-allow",
        severity: Severity::High,
        message: format!(
            "Effect: Allow combined with NotAction: {:?} grants every action EXCEPT the \
             ones listed — effectively unbounded and grows automatically as AWS adds new APIs",
            stmt.not_actions
        ),
    })
}

fn rule_notresource_with_allow(idx: usize, stmt: &Statement) -> Option<Finding> {
    if !is_allow(stmt) || stmt.not_resources.is_empty() {
        return None;
    }
    Some(Finding {
        statement_index: idx,
        sid: stmt.sid.clone(),
        rule: "notresource-with-allow",
        severity: Severity::High,
        message: format!(
            "Effect: Allow combined with NotResource: {:?} grants access to every resource \
             EXCEPT the ones listed",
            stmt.not_resources
        ),
    })
}

pub fn lint(policy: &Policy) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (idx, stmt) in policy.statements.iter().enumerate() {
        findings.extend(rule_wildcard_action(idx, stmt));
        findings.extend(rule_unconstrained_resource(idx, stmt));
        findings.extend(rule_sensitive_action_without_condition(idx, stmt));
        findings.extend(rule_wildcard_principal(idx, stmt));
        findings.extend(rule_notaction_with_allow(idx, stmt));
        findings.extend(rule_notresource_with_allow(idx, stmt));
    }
    findings
}

pub fn has_blocking_findings(findings: &[Finding]) -> bool {
    findings.iter().any(|f| f.severity >= Severity::High)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::parse_policy;

    fn lint_str(content: &str) -> Vec<Finding> {
        lint(&parse_policy(content).unwrap())
    }

    #[test]
    fn glob_match_handles_star_and_question_mark() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("iam:*", "iam:CreateUser"));
        assert!(!glob_match("iam:*", "s3:GetObject"));
        assert!(glob_match("s3:Get?bject", "s3:GetObject"));
        assert!(glob_match("IAM:*", "iam:createuser"), "case-insensitive");
    }

    #[test]
    fn action_and_resource_wildcard_is_critical() {
        let findings = lint_str(
            r#"{"Version":"2012-10-17","Statement":[
                {"Effect":"Allow","Action":"*","Resource":"*"}
            ]}"#,
        );
        assert!(findings
            .iter()
            .any(|f| f.rule == "wildcard-action" && f.severity == Severity::Critical));
    }

    #[test]
    fn action_wildcard_scoped_to_resource_is_high_not_critical() {
        let findings = lint_str(
            r#"{"Version":"2012-10-17","Statement":[
                {"Effect":"Allow","Action":"*","Resource":"arn:aws:s3:::my-bucket/*"}
            ]}"#,
        );
        let f = findings
            .iter()
            .find(|f| f.rule == "wildcard-action")
            .expect("expected a wildcard-action finding");
        assert_eq!(f.severity, Severity::High);
    }

    #[test]
    fn sensitive_action_without_condition_is_flagged() {
        let findings = lint_str(
            r#"{"Version":"2012-10-17","Statement":[
                {"Effect":"Allow","Action":"s3:DeleteBucket","Resource":"arn:aws:s3:::prod-data"}
            ]}"#,
        );
        assert!(findings
            .iter()
            .any(|f| f.rule == "sensitive-action-no-condition"));
    }

    #[test]
    fn sensitive_action_with_real_condition_is_not_flagged() {
        let findings = lint_str(
            r#"{"Version":"2012-10-17","Statement":[
                {"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::123456789012:role/app-role",
                 "Condition":{"StringEquals":{"iam:PassedToService":"ec2.amazonaws.com"}}}
            ]}"#,
        );
        assert!(!findings
            .iter()
            .any(|f| f.rule == "sensitive-action-no-condition"));
    }

    #[test]
    fn iam_star_action_is_flagged_as_sensitive_even_without_wildcard_resource() {
        let findings = lint_str(
            r#"{"Version":"2012-10-17","Statement":[
                {"Effect":"Allow","Action":"iam:*","Resource":"arn:aws:iam::123456789012:role/app-role"}
            ]}"#,
        );
        assert!(findings
            .iter()
            .any(|f| f.rule == "sensitive-action-no-condition"));
    }

    #[test]
    fn wildcard_principal_string_is_critical() {
        let findings = lint_str(
            r#"{"Version":"2012-10-17","Statement":[
                {"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket/*"}
            ]}"#,
        );
        assert!(findings
            .iter()
            .any(|f| f.rule == "wildcard-principal" && f.severity == Severity::Critical));
    }

    #[test]
    fn wildcard_principal_aws_object_is_critical() {
        let findings = lint_str(
            r#"{"Version":"2012-10-17","Statement":[
                {"Effect":"Allow","Principal":{"AWS":"*"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket/*"}
            ]}"#,
        );
        assert!(findings.iter().any(|f| f.rule == "wildcard-principal"));
    }

    #[test]
    fn scoped_principal_is_not_flagged() {
        let findings = lint_str(
            r#"{"Version":"2012-10-17","Statement":[
                {"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},
                 "Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket/*"}
            ]}"#,
        );
        assert!(!findings.iter().any(|f| f.rule == "wildcard-principal"));
    }

    #[test]
    fn bare_notaction_statement_does_not_also_emit_a_confusing_empty_action_finding() {
        // A statement with only NotAction (no Action key) has nothing in
        // `actions` to judge as "safe read-only" — this must not produce
        // an unconstrained-resource finding listing an empty action set;
        // notaction-with-allow already names the real risk here.
        let findings = lint_str(
            r#"{"Version":"2012-10-17","Statement":[
                {"Effect":"Allow","NotAction":"iam:*","Resource":"*"}
            ]}"#,
        );
        assert!(!findings.iter().any(|f| f.rule == "unconstrained-resource"));
        assert!(findings.iter().any(|f| f.rule == "notaction-with-allow"));
    }

    #[test]
    fn notaction_with_allow_is_flagged() {
        let findings = lint_str(
            r#"{"Version":"2012-10-17","Statement":[
                {"Effect":"Allow","NotAction":"iam:*","Resource":"*"}
            ]}"#,
        );
        assert!(findings.iter().any(|f| f.rule == "notaction-with-allow"));
    }

    #[test]
    fn notresource_with_allow_is_flagged() {
        let findings = lint_str(
            r#"{"Version":"2012-10-17","Statement":[
                {"Effect":"Allow","Action":"s3:GetObject","NotResource":"arn:aws:s3:::protected/*"}
            ]}"#,
        );
        assert!(findings.iter().any(|f| f.rule == "notresource-with-allow"));
    }

    #[test]
    fn deny_statements_are_never_flagged() {
        let findings = lint_str(
            r#"{"Version":"2012-10-17","Statement":[
                {"Effect":"Deny","Action":"*","Resource":"*","Principal":"*","NotAction":"s3:*"}
            ]}"#,
        );
        assert!(
            findings.is_empty(),
            "Deny statements are restrictions, never a permission risk"
        );
    }

    #[test]
    fn describe_action_with_wildcard_resource_is_not_flagged() {
        // ec2:DescribeInstances is a real AWS action that *requires*
        // Resource: "*" — there is no resource-level ARN for it. This
        // must not trip unconstrained-resource.
        let findings = lint_str(
            r#"{"Version":"2012-10-17","Statement":[
                {"Effect":"Allow","Action":"ec2:DescribeInstances","Resource":"*"}
            ]}"#,
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn mixed_describe_and_mutating_action_with_wildcard_resource_is_flagged() {
        let findings = lint_str(
            r#"{"Version":"2012-10-17","Statement":[
                {"Effect":"Allow","Action":["ec2:DescribeInstances","ec2:TerminateInstances"],"Resource":"*"}
            ]}"#,
        );
        assert!(findings.iter().any(|f| f.rule == "unconstrained-resource"));
    }

    #[test]
    fn a_genuinely_safe_least_privilege_policy_produces_zero_findings() {
        let content = r#"{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ReadOwnObjects",
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:ListBucket"],
                    "Resource": [
                        "arn:aws:s3:::my-app-bucket",
                        "arn:aws:s3:::my-app-bucket/${aws:username}/*"
                    ]
                },
                {
                    "Sid": "DescribeOwnInstances",
                    "Effect": "Allow",
                    "Action": "ec2:DescribeInstances",
                    "Resource": "*"
                },
                {
                    "Sid": "PassRoleToECSOnly",
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": "arn:aws:iam::123456789012:role/ecs-task-role",
                    "Condition": {
                        "StringEquals": {"iam:PassedToService": "ecs-tasks.amazonaws.com"}
                    }
                }
            ]
        }"#;
        let findings = lint_str(content);
        assert!(
            findings.is_empty(),
            "a real least-privilege policy must not be flagged, but got: {findings:?}"
        );
    }

    #[test]
    fn has_blocking_findings_is_true_only_for_high_or_critical() {
        let only_medium = vec![Finding {
            statement_index: 0,
            sid: None,
            rule: "unconstrained-resource",
            severity: Severity::Medium,
            message: String::new(),
        }];
        assert!(!has_blocking_findings(&only_medium));

        let with_high = vec![Finding {
            statement_index: 0,
            sid: None,
            rule: "wildcard-action",
            severity: Severity::High,
            message: String::new(),
        }];
        assert!(has_blocking_findings(&with_high));
    }

    #[test]
    fn missing_resource_key_on_allow_is_treated_as_unconstrained() {
        let findings = lint_str(
            r#"{"Version":"2012-10-17","Statement":[
                {"Effect":"Allow","Action":"s3:PutObject"}
            ]}"#,
        );
        assert!(findings.iter().any(|f| f.rule == "unconstrained-resource"));
    }
}
