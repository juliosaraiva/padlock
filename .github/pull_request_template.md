## Intent

<!-- Link the issue or decision. Describe the behavior change, why it matters, and who or what is affected. -->

The PR author is responsible for reviewing and verifying the entire change, including code written by an agent.

## Risk

- Impact (Low / Medium / High) —
- Detectability (Low / Medium / High) —
- Reversibility (Low / Medium / High) —
- Overall tier and rationale —
- Protected paths and reviewers requested —

<!--
Score each axis using the table below. Overall tier is the highest axis rating.
Protected paths have a Medium floor. Rate an unknown axis High until evidence resolves it.
Judge the credible failure mode for this change.

Axis           | Low                         | Medium                              | High
Impact         | No runtime or user impact   | Bounded user or operational impact  | Secret exposure, data loss, trust-boundary failure, or broad release impact
Detectability  | Targeted check before merge | Staged smoke test or clear signal   | Silent, delayed, or weakly observable failure
Reversibility  | Clean revert, no state work | Redeploy or tested state recovery   | Irreversible exposure, destructive state change, or unproven recovery

All tiers use existing CI and human approval requirements. Pilot guidance is advisory.
Low: Cite a relevant check or explain why it does not apply.
Medium: Add targeted regression or rollout verification evidence and request applicable path review.
High: Request independent domain review. Record failure-path evidence, staged rollout,
stop criteria, and a recovery rehearsal or explicitly record the evidence gap.

Protected-path routing (request a named maintainer for every applicable domain):
- Vault/security: crates/padlock-core/src/{crypto,vault,entries,generate,session,audit,ssh_agent,signing,sync}/**
- CLI/security: crates/padlock-cli/src/** when changing secret handling, process execution,
  signing, agent IPC, or session lifecycle. Include the CLI maintainer.
- Build/release: .github/workflows/**, .cargo/**, **/Cargo.toml, Cargo.lock, deny.toml.
  Include a security maintainer when credentials, permissions, or artifact trust change.
- Review policy: .github/pull_request_template.md and any CODEOWNERS or PR template
  directory changes. Request a repository maintainer.

Also route changes that touch these trust boundaries through shared code. If no maintainer
is identified for a domain, ask the repository maintainer to name one and record the gap.
-->

## Evidence

<!-- Cite current PR head, CI run or exact commands and results, and relevant platforms. Record failures, untested cases, or evidence gaps. For Medium/High, tie evidence to the stated failure mode. -->

- Bug fixes — Link the regression test and show it failing for the reported bug before the fix and passing with the fix. Include the revisions and test command.
- UI changes — Attach a screenshot or recording showing the affected flow.
- Automated findings — Link each finding and record either the fix with verification evidence or the reason for dismissing it. State when no findings were reported or when automated review did not run.

## Revert and rollout

- Revert or recovery steps —
- Rollout owner (@handle) —
- Rollout sequence, verification signal, and stop condition —

<!-- Name the person responsible for monitoring and initiating recovery. For changes with no deployment, state that and name the owner for post-merge follow-up. -->
