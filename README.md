# iamlint

A static linter for AWS IAM policy JSON documents. `aws iam simulate-principal-policy`
tells you whether a *specific* call would be allowed; AWS Access Analyzer needs
the policy actually attached to a real principal in a real account before it'll
say anything. Neither one just looks at a policy document sitting in a repo (a
Terraform `aws_iam_policy_document`, a CDK-synthesized JSON file, a raw policy
pasted into a PR) and says "this statement is a wildcard-action, wildcard-resource
grant" before it ever gets applied. `iamlint` does exactly that, offline, against
the JSON directly — no AWS account, no credentials, no API calls.

## Usage

```bash
iamlint policy.json                # human-readable report
iamlint policy.json --json         # machine-readable findings for CI
```

Exit code `1` if any finding is `HIGH` or `CRITICAL` severity — `MEDIUM`
findings are printed but don't fail the run, which is what makes this usable
as a CI gate without also blocking on every legitimate `Resource: "*"`
read-only statement.

## What it flags

- **`wildcard-action`** — `Action: "*"`. `CRITICAL` if `Resource` is also `"*"`
  or omitted (an effectively-AdministratorAccess statement); `HIGH` if
  `Resource` is at least scoped to something specific (still "any action,"
  just against a narrower target).
- **`sensitive-action-no-condition`** — a statement grants a named
  high-blast-radius action (`iam:*`, `iam:PassRole`, `iam:CreateAccessKey`,
  `iam:AttachUserPolicy`, `sts:AssumeRole`, `s3:DeleteBucket`,
  `s3:PutBucketPolicy`, `ec2:TerminateInstances`, `kms:DisableKey`,
  `organizations:LeaveOrganization`, and about a dozen others — see
  `SENSITIVE_ACTIONS` in `src/rules.rs`) with no `Condition` block at all.
  A `Condition` (`iam:PassedToService`, `aws:SourceIp`,
  `aws:MultiFactorAuthPresent`, ...) is the normal way these get scoped down;
  its total absence on an already-dangerous action is the smell.
- **`wildcard-principal`** — `Principal: "*"` or `Principal: {"AWS": "*"}`
  (or an array containing `"*"`) on a resource-based policy statement (S3
  bucket policies, KMS key policies, etc. — the only place `Principal`
  legitimately appears). This is the exact shape of a publicly-readable S3
  bucket.
- **`notaction-with-allow`** / **`notresource-with-allow`** — `NotAction`/
  `NotResource` combined with `Effect: Allow` grants everything *except* the
  listed actions/resources. This is a real, valid, and rarely-what-you-meant
  IAM construct: it silently grants any new action AWS ever adds to the
  excluded service.
- **`unconstrained-resource`** — `Resource: "*"` (or no `Resource` key at
  all) for actions that aren't read-only `Describe`/`Get`/`List`/`View`-style
  calls. This one is deliberately narrow (see below).

`Effect: Deny` statements are never flagged — a `Deny` is a restriction, not
a grant, so none of the above risk shapes apply to one.

## Avoiding false positives on real least-privilege policies

The riskiest rule to get wrong here is `unconstrained-resource`: a huge
number of genuinely least-privilege policies legitimately use
`Resource: "*"` because AWS's own IAM documentation says so — actions like
`ec2:DescribeInstances` have no resource-level ARN to scope to at all. A
naive "flag any `Resource: "*"`" rule would drown every real policy in noise
on day one.

`iamlint` special-cases this: a statement whose *every* action starts with
`Describe`/`Get`/`List`/`View`/`Head`/`Check`/`Lookup`/`Search`/`Query`
(after the `service:` prefix, case-insensitively) is exempt from
`unconstrained-resource` even when `Resource` is `"*"`. Mix in a single
mutating action (`ec2:TerminateInstances` alongside `ec2:DescribeInstances`,
say) and the statement is flagged again — the exemption is per-statement,
not per-action, and it only holds as long as *nothing* in that statement
needs scoping.

This is also why `wildcard-action` and `unconstrained-resource` don't stack
on the same statement: a `wildcard-action` `CRITICAL`/`HIGH` finding already
says everything `unconstrained-resource`'s narrower `MEDIUM` would add.

## Action-pattern matching

`Action`/`Resource`/sensitive-action entries can all contain `*` and `?`
wildcards under AWS's own policy grammar (`s3:Get*`, `iam:*`). Matching is
done with a from-scratch case-insensitive glob matcher (`glob_match` in
`src/rules.rs`) checked in both directions — a statement's action pattern
against a sensitive-action pattern, and vice versa — so `iam:*` in a policy
is caught by the literal `iam:*` sensitive-action entry, and a policy
granting the exact action `iam:CreateAccessKey` is caught by the same entry
via the reverse glob check. This is a heuristic, not a full set-overlap
solver: two partial wildcards that only partially overlap (`iam:C*` and
`iam:*User`) aren't resolved precisely — see **Not done** below.

## Status: built and verified against realistic hand-built IAM policy JSON, including a real false-positive-shaped bug caught and fixed

- **28 unit tests** (`cargo test --lib`): `policy` module (10 — bare-string
  vs. array `Action`/`Resource`, a single bare-object `Statement` vs. an
  array of them, `Resource` genuinely absent vs. present-but-empty,
  `Condition: {}` correctly *not* counted as a real condition, malformed
  JSON and a missing `Effect` both clean errors, not panics); `rules`
  module (18 — every rule's true-positive shape, every rule's
  false-positive guard, `glob_match` itself including case-insensitivity
  and `?`, and the `has_blocking_findings` severity threshold).
- **A false-positive-shaped bug found and fixed by running the tool against
  its own fixture, not just by writing a unit test for it first**: a
  bare-`NotAction`-with-`Allow` statement (`Effect: Allow, NotAction:
  "iam:*", Resource: "*"`, no `Action` key at all) was correctly flagged by
  `notaction-with-allow`, but `unconstrained-resource` *also* fired on it
  with the message `"Resource: \"*\" for action(s) []"` — a technically-true
  but genuinely confusing empty-list finding, since there's no `Action`
  list on a bare-`NotAction` statement for the "is every action a safe read
  verb" check to look at. Fixed by having `rule_unconstrained_resource`
  skip statements with no `Action` entries at all (the real risk in that
  shape is already fully named by `notaction-with-allow`), re-verified via
  `cargo test --lib` and by re-running the compiled binary against
  `tests/fixtures/dangerous.json` before and after — the confusing
  duplicate finding disappeared and no real finding was lost (6 findings
  instead of 7, same 5 statements, `notaction-with-allow` still present).
- **Live-verified against two hand-built, realistic policy fixtures through
  the actual compiled binary** (not just the library API):
  `tests/fixtures/dangerous.json` (5 statements: a full-admin
  `Action:"*"/Resource:"*"` grant, an unconditioned `s3:DeleteBucket`, a
  `Principal: "*"` bucket-policy-style statement, a bare `NotAction` grant,
  and a resource-scoped `iam:*` with no condition) produces exactly 6
  findings (2 critical, 4 high) and exit code `1`.
  `tests/fixtures/safe.json` (a real least-privilege shape: scoped
  `s3:GetObject`/`s3:ListBucket` to a user-prefixed path, `ec2:DescribeInstances`
  on `Resource: "*"` because AWS requires it, and `iam:PassRole` scoped to
  one role ARN with a real `iam:PassedToService` condition) produces **zero**
  findings and exit code `0` — the false-positive check the task called out
  as equally important as the true-positive one.

**Not done / deliberately deferred**: no real AWS account or Access
Analyzer call of any kind — everything here is static analysis of the JSON
document itself, which is the entire point (works in CI with zero
credentials) but also the limit (it can't know what a `*` resource actually
expands to for a *specific* account, and it can't catch a
privilege-escalation *chain* across multiple separately-fine-looking
policies, which is what tools like PMapper exist for). The action-pattern
overlap check is a heuristic (see above) — two independently-wildcarded
patterns that only partially overlap aren't resolved with full set logic.
Policy variables (`${aws:username}`) are treated as opaque resource-string
text, not expanded or validated. `Condition` is checked only for
*presence* (any non-empty `Condition` block silences
`sensitive-action-no-condition`) — a `Condition` whose actual operator is
trivially satisfiable (e.g. `"StringLike": {"aws:SourceIp": "0.0.0.0/0"}`)
is not evaluated as "does this condition actually constrain anything."
Service Control Policies and permission boundaries (which interact with an
identity policy's *effective* permissions) aren't modeled — this lints one
policy document in isolation, matching how one would actually be reviewed
in a PR.
