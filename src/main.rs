use std::fs;
use std::path::PathBuf;

use clap::Parser;

use iamlint::policy::parse_policy;
use iamlint::rules::{has_blocking_findings, lint, Severity};

#[derive(Parser)]
#[command(
    name = "iamlint",
    about = "Lints an AWS IAM policy JSON document for overly-permissive statements"
)]
struct Cli {
    /// Path to a policy JSON document (an identity-based policy, an
    /// inline policy, or a resource-based policy with a Principal).
    policy: PathBuf,

    /// Emit findings as a JSON array instead of the human-readable report.
    #[arg(long)]
    json: bool,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let content = fs::read_to_string(&cli.policy)
        .map_err(|e| anyhow::anyhow!("reading {}: {e}", cli.policy.display()))?;
    let policy = parse_policy(&content).map_err(|e| anyhow::anyhow!(e))?;
    let findings = lint(&policy);

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&findings)?);
    } else if findings.is_empty() {
        println!(
            "{}: no findings — {} statement(s) checked",
            cli.policy.display(),
            policy.statements.len()
        );
    } else {
        println!(
            "{}: {} finding(s) across {} statement(s)\n",
            cli.policy.display(),
            findings.len(),
            policy.statements.len()
        );
        for f in &findings {
            let sid = f.sid.as_deref().unwrap_or("(no Sid)");
            println!(
                "[{}] statement #{} ({sid}) — {}\n    {}\n",
                f.severity, f.statement_index, f.rule, f.message
            );
        }
        let critical = findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count();
        let high = findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .count();
        let medium = findings
            .iter()
            .filter(|f| f.severity == Severity::Medium)
            .count();
        println!("{critical} critical, {high} high, {medium} medium");
    }

    if has_blocking_findings(&findings) {
        std::process::exit(1);
    }
    Ok(())
}
