# pi-dependency-audit

A Python CLI that runs [pi-review-bot](../pi-review-bot) over a portfolio of GitHub dependencies, then ranks the issues worth investigating. Use it to audit the exact versions you depend on, understand gaps in the review, and prepare fixes with evidence.

Each repository is cloned and pinned to a commit. Reviews run sequentially by default, through a rolling pool with `--jobs N`, or in fixed waves with `--batch-size N`. Optional portfolio synthesis assesses every parsed finding from security, data safety, performance, availability, and correctness perspectives. Selected findings can be handed to a separate fix checkout to produce a patch and verification logs.

The tool calls pi-review-bot's existing launchers. It does not modify pi-review-bot, Pi, or the repositories you supply. Fixes stay in disposable copies until you choose to apply their patches.

## Requirements and installation

- Python 3.11 or newer, on macOS or Linux. No runtime Python packages are required.
- Git, a working pi-review-bot checkout and its prerequisites, and Pi 0.83.0 or newer. Use the Node version required by your installed Pi.
- A sandbox backend: macOS `sandbox-exec` or Linux `bwrap`.
- Model credentials/configuration used by pi-review-bot. Existing environment values take precedence over literal values read from its `.env`.

Run directly from this repository:

```sh
./pi-dependency-audit doctor
./pi-dependency-audit --help
```

Or install in a virtual environment:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/pi-dependency-audit --help
```

The default bot location is `~/experiments/pi-review-bot`. Override it with `--bot /path/to/pi-review-bot` or `PI_REVIEW_BOT`. Portfolio synthesis and fixing use `pi` on your PATH; select another executable with `--pi`. If an old nvm installation shadows a newer Pi/Node, update PATH before running the tool. `doctor` checks the Pi on PATH; pi-review-bot may have its own runtime selection.

## Audit repositories

Replace the illustrative `owner/tool` names and tags below with your dependencies. Planning never clones repositories, creates an audit workspace, or calls models:

```sh
./pi-dependency-audit run owner/tool-a@v1.2.3 owner/tool-b@main \
  --workspace audits/tools --modes bug,security,data-safety,perf --dry-run
```

Start a sequential review:

```sh
./pi-dependency-audit run owner/tool-a@v1.2.3 \
  --workspace audits/tools --modes bug,security,data-safety,perf
```

Review a list in waves of three repositories:

```sh
./pi-dependency-audit run --repos-file dependencies.toml \
  --workspace audits/tools --batch-size 3 \
  --modes bug,security,data-safety,perf
```

Use `--jobs 3` for a rolling pool: each finished repository frees a slot immediately. `--batch-size 3` waits for the entire wave to finish before starting another. These options are mutually exclusive. Each repository's phases run one after another.

`--review-jobs` controls batch concurrency **per review model**, default 1. pi-review-bot may launch multiple models concurrently within one repository. Outer concurrency therefore does not impose a global API request limit. Batch transport can also leave jobs running at the provider after a local timeout or interruption; inspect the saved pi-review-bot logs before abandoning a campaign.

### Inputs

Accepts `owner/repo`, `owner/repo@branch-or-tag-or-sha`, GitHub HTTPS clone URLs, and `git@github.com:owner/repo.git`. GitHub entries are normalized to HTTPS; use your existing Git HTTPS authentication for private repositories. Git credentials are not placed in manifests. GitHub web URLs such as `/tree/main` are not accepted.

Text lists contain one repository per line, with blank lines and `#` comments:

```text
owner/tool-a@v1.2.3
https://github.com/owner/tool-b.git
owner/tool-c@release/2026-10 # an inline comment
```

JSON accepts an array, or an object containing a `repositories` array. TOML supports usage context and priority:

```toml
[[repositories]]
repo = "owner/tool-a"
ref = "v1.2.3"
usage = "Parses untrusted uploads and writes customer data"
criticality = "critical"

[[repositories]]
repo = "owner/tool-b"
ref = "main"
usage = "Offline build tool; runs only in CI"
criticality = "normal"
```

`criticality` is `critical`, `normal`, or `low`; it breaks ties between findings of the same severity. Usage context is passed to the optional portfolio assessor. Pin the version actually deployed: a clean review of `main` says little about an older release you use.

`--repos-file` and `--local-repo /path/to/repo` are repeatable. Manifest entries can use `path` instead of `repo`, relative to the manifest. Local repositories are cloned from their **committed** state; uncommitted local edits are not audited. Submodules are not initialized, and runtime/package dependencies are not recursively audited. Include those repositories explicitly if they are in scope.

### Review modes

| Mode | pi-review-bot workflow |
|---|---|
| `bug` | Default recall review and per-repository triage |
| `security` | A verified single-pass review focused on security |
| `data-safety` | A verified single-pass review focused on data safety |
| `perf` | Performance reviews and union triage |
| `ultra` | Broad multi-lens review, coverage matrix, triage, and runtime verification |

The default is `bug,perf`. Add the explicit security and data-safety phases when those are the main concerns. `ultra` is a broader, more expensive alternative; it cannot use live transport or disable per-repository triage.

`--models provider/model,provider/other-model` overrides review models; `--triage-model provider/model` overrides per-repository triage. Otherwise the bot's presets apply. `--transport default|live|batch|flex` delegates the choice to the bot; availability, price, and behavior depend on its configured providers. Normal runs can incur model charges. `--no-repo-triage` retains raw review candidates, except for `ultra`.

### Resume and provenance

Rerun the same command to resume. Completed phases with intact archived reports are skipped; failed or partial phases are retried. To resume without repeating the list, omit repository arguments but keep the original review options. Adjusting outer `--jobs` or `--batch-size` is allowed.

The campaign keeps the first resolved commit even when an upstream branch moves. Changed review configuration, changed bot launcher/prompt contents, or edited audited source requires a new workspace. To review a new upstream version or repeat completed work, choose another `--workspace`. Do not edit `state.json` to bypass those checks.

```sh
./pi-dependency-audit status --workspace audits/tools
./pi-dependency-audit report --workspace audits/tools --top 30
```

`report` rebuilds the portfolio report without model calls. A workspace lock prevents simultaneous writers. Local processes and their children are terminated on timeout/cancellation. Earlier reports and retry history remain archived when a retry fails.

## Review the portfolio

Without model synthesis, findings are ranked by reported severity and dependency criticality. Perspective labels initially come from review mode and keyword rules; they are not an independent assessment.

Assess the completed reviews with an explicit model:

```sh
./pi-dependency-audit summarize --workspace audits/tools \
  --model provider/triage-model --batch-size 12
```

Or add `--summarize --summary-model provider/triage-model` to `run`. A different model from the original reviewers can help challenge shared assumptions.

Synthesis reads every parsed candidate, its provenance, dependency usage, and source excerpts from the pinned Git commit. It runs with no tools, repository extensions, skills, or context files; trusted pi-review-bot provider configuration extensions are loaded explicitly. Excerpts are bounded and can lack caller context. The assessor must mark uncertain claims `needs-context` instead of inventing evidence.

Each finding gets a `prioritize`, `defer`, `reject`, or `needs-context` decision, severity, perspectives, confidence, rationale, and proposed action. Every supplied ID must appear exactly once. Omitted, duplicate, unknown, or malformed decisions fail the batch; the original candidates remain visible. Successful batches are cached by evidence, model, and bot contents, so failed synthesis can resume without repeating completed batches. Rejected findings remain in the audit trail.

### Outputs

| File/directory | Contents |
|---|---|
| `AUDIT.md` | Repository status, coverage, and worst issues per perspective |
| `findings.json` / `findings.csv` | All parsed candidates, stable IDs, commit/path/line citations, and provenance |
| `assessments.json` | Optional synthesis decisions, status, and errors |
| `state.json` | Campaign configuration, progress, diagnostics, and retry history |
| `reports/` | Archived final reports and separate coverage reports |
| `logs/`, `events.jsonl` | Reviewer output and progress records |
| `repos/`, `boxes/` | Pinned clones and review sandbox copies |
| `synthesis/` | Cached assessment batches and model logs |
| `fixes/` | Fix patches, isolated copies, model reports, and check logs |

The Markdown report shows up to `--top 20` candidates per perspective; JSON and CSV retain all candidates. Findings can appear under more than one perspective. Source links point at the audited commit. Findings with invalid/missing citations are retained and marked unanchored; they cannot be passed to the fix workflow.

`complete` means the requested invocation produced its reports without detected gaps. `reported` coverage means the report declared evidence, not that an independent reader proved every file was understood. Missing/failed reviews, stale output, unread files, malformed finding lines, and mismatched commit receipts remain visible. Unknown coverage remains unknown. No findings is not a safety certification.

For CI, `--fail-on high` fails on any raw candidate at or above that severity, even when synthesis rejects it. Exit codes: `0` completed operation, `1` severity gate triggered, `2` error/incomplete review or failed fix verification, `130` interrupted. A completed `fix` without checks can return 0 with `unverified` status; use its result file to gate acceptance.

## Prepare and verify a fix

Choose finding IDs from the report. A fix invocation accepts related findings from one repository:

```sh
./pi-dependency-audit fix --workspace audits/tools \
  --finding F-example-id --model provider/fix-model \
  --verify 'python3 -m unittest discover -s tests'
```

The fixer starts on a new branch at the audited commit, inside a pi-box copy. It is instructed to confirm the issue, make a focused change and regression test, and document any unsupported claims. It does not install dependencies automatically. Use a prepared checkout/environment if a reproduction needs dependencies.

The output includes `fix.patch`, `PI_FIX_REPORT.md` when produced, and `result.json` with the base commit, selected IDs, patch digest, sandbox checkout path, and exact check commands/results. No commit, push, or PR is created. Inspect the patch and apply it to your own working branch with `git apply --check /path/to/fix.patch` followed by `git apply /path/to/fix.patch`.

Repeat `--verify` for multiple commands. These commands run after the agent in a separate sandbox copy of the patched tree; they are independently executed, not independently designed tests. `verified` means those supplied commands passed. It does not establish that the finding was real, that tests cover the defect, or that the patch is safe. With no checks the patch is `unverified`; failed checks produce `verification-failed`.

The current pi-box launcher can mask a child command's exit code during bring-back. Verification therefore requires an exit receipt written by a wrapper inside the box, as well as a successful launcher call. Missing receipts fail verification. Boxed reviewer failures printed in review logs also make the phase incomplete.

Both review and fix calls set `PI_BOX_FORCE=0`, so a missing sandbox backend fails instead of falling back to unrestricted writes. pi-box provides write confinement and uses network access for models; this is not a fully isolated malware laboratory. Its existing trust and read/network boundaries still apply. The audit workspace contains source and model outputs, so keep it private and out of version control.

## Development

```sh
python3 -m unittest discover -s tests -v
```

Tests use real temporary Git repositories and fake fleet/Pi/box adapters, with no model charges or external GitHub access. They exercise pinned revisions, resume, batching, coverage, timeouts, failed/missing reports, strict synthesis accounting, and fix patches/independent check execution. Fake box tests do not certify the real pi-box sandbox or provider integration.

To exercise the actual bot launchers, transport, union merge, and sandbox with a local mock model endpoint:

```sh
PI_AUDIT_INTEGRATION_BOT=../pi-review-bot python3 -m unittest discover -s tests -v
```

This opt-in integration checks two repositories in parallel through `bug`, `security`, `data-safety`, and `perf`; report and coverage ingestion; resume without repeated model requests; portfolio synthesis; fix patches; passing and failing verification commands; and pi-box's Flutter Dart shim. Pi/model answers are deterministic stubs, so it checks orchestration rather than review quality, without hosted model charges. It requires localhost access and permission to launch the sandbox.

Compatibility was checked against pi-review-bot commit `c6e992e` (2026-10-04). Its available-reviewer selection and Pi/Node fallback preserve the explicit model and branch arguments used here. The CLI continues to use pi-fleet's presets unless `--models` overrides them; plain pi-review's automatic local reviewer choice does not replace fleet presets. The Dart shim benefits boxed Dart verification by calling the SDK executable directly. After bot changes, start a new audit workspace if the saved configuration fingerprint differs.

## Follow-up work

- Add dependency/advisory and SBOM input alongside source review, with explicit version matching.
- Add a global request/cost budget across nested pi-review-bot model workers.
- Add richer retrieval for `needs-context` assessments and a human disposition workflow.
- Add a patch verification protocol that runs the regression test against both the base and patched revision.
- Benchmark Pi 1.0 codemode in pi-review-bot's live triage/fix passes. This orchestrator benefits only when its underlying bot paths opt in; direct batch/flex transports and this tool's synthesis pass do not gain codemode automatically.
- Add opt-in PR creation after patch inspection and verification.
