from __future__ import annotations

import hashlib
import json
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .core import AuditError, ProcessRunner, Repository, digest, model_environment, now, write_json
from .reports import collect_phase, report_paths

MODES = ("bug", "security", "data-safety", "perf", "ultra")
SNAPSHOT_BRANCH = "pi-dependency-snapshot"
FOCUSES = {"security": "security", "data-safety": "data-safety"}


def launcher_fingerprint(bot: Path) -> str:
    paths = [bot / name for name in ("pi-fleet", "pi-review", "pi-ultra", "pi-box")]
    paths += list((bot / "agent").rglob("*.md")) + list((bot / "agent/extensions").rglob("*.ts"))
    paths += list((bot / "tools").glob("*.py"))
    return digest([(str(path.relative_to(bot)), hashlib.sha256(path.read_bytes()).hexdigest())
                   for path in sorted(paths) if path.is_file()])


def review_command(config: dict, mode: str, checkout: Path) -> list[str]:
    verb = "verified" if mode in FOCUSES else mode
    command = [config["reviewer"], verb]
    if config.get("models"):
        command.append(config["models"])
    command += [str(checkout), "--review-branch", SNAPSHOT_BRANCH]
    if mode in FOCUSES:
        command += ["--single-pass", "--focus", FOCUSES[mode]]
    if config.get("triage_model"):
        command += ["--triage", config["triage_model"]]
    if config.get("no_repo_triage"):
        command.append("--no-triage")
    if config["transport"] != "default":
        command.append({"batch": "--batch", "flex": "--flex", "live": "--live"}[config["transport"]])
    return command


def load_state(workspace: Path) -> dict:
    try:
        state = json.loads((workspace / "state.json").read_text())
        if state.get("schema") != 1 or not isinstance(state.get("repositories"), list):
            raise AuditError("Unsupported or invalid audit state")
        return state
    except (OSError, ValueError) as exc:
        raise AuditError(f"Cannot read {workspace / 'state.json'}: {exc}") from exc


class Campaign:
    def __init__(self, workspace: Path, config: dict, repositories: list[Repository],
                 *, processes: ProcessRunner | None = None):
        self.workspace = workspace
        self.config = config
        self.processes = processes or ProcessRunner()
        self.lock = threading.RLock()
        state_file = workspace / "state.json"
        if state_file.exists():
            self.state = load_state(workspace)
            if self.state["config"] != config:
                raise AuditError("Review configuration or pi-review-bot contents changed. Use a new workspace to preserve audit provenance.")
        else:
            self.state = {"schema": 1, "created": now(), "config": config, "repositories": []}
        existing = {repo["key"]: repo for repo in self.state["repositories"]}
        date = self.state["created"][:10].replace("-", "")
        for repo in repositories:
            if repo.key in existing:
                previous = existing[repo.key]
                if any(previous.get(field) != value for field, value in repo.as_dict().items()):
                    raise AuditError(f"Repository usage or revision changed for {repo.name}; use a new workspace")
            else:
                self.state["repositories"].append(repo.as_dict() | {
                    "status": "pending", "date": date, "phases": {}, "commit": None})
        if not self.state["repositories"]:
            raise AuditError("Provide a repository or --repos-file, or resume an existing workspace")
        self.save()

    def save(self):
        with self.lock:
            write_json(self.workspace / "state.json", self.state)

    def event(self, record: dict, message: str):
        with self.lock:
            print(f'[{record["name"]}] {message}', flush=True)
            with (self.workspace / "events.jsonl").open("a") as log:
                log.write(json.dumps({"at": now(), "repo": record["name"], "key": record["key"], "message": message}) + "\n")

    def git(self, checkout: Path, *args: str, timeout: int = 180) -> str:
        return self.processes.run(["git", "-C", str(checkout), *args], timeout=timeout)

    def prepare(self, record: dict) -> Path:
        checkout = self.workspace / "repos" / record["key"]
        checkout.parent.mkdir(parents=True, exist_ok=True)
        if not checkout.exists():
            record["status"] = "cloning"
            self.save()
            self.processes.run(["git", "clone", "--no-checkout", "--no-hardlinks", "--depth", "1", "--",
                                record["source"], str(checkout)], timeout=self.config["clone_timeout"],
                               log=self.workspace / "logs" / record["key"] / "clone.log")
        if not (checkout / ".git").exists():
            raise AuditError(f"Incomplete clone at {checkout}; inspect it and use a new workspace")
        if self.git(checkout, "remote", "get-url", "origin") != record["source"]:
            raise AuditError("Checkout origin changed; refusing to review a different repository")
        if not record.get("commit"):
            if record["ref"]:
                self.git(checkout, "fetch", "--depth", "1", "origin", record["ref"], timeout=self.config["clone_timeout"])
                commit = self.git(checkout, "rev-parse", "FETCH_HEAD")
            else:
                commit = self.git(checkout, "rev-parse", "HEAD")
            self.git(checkout, "checkout", "-q", "-B", SNAPSHOT_BRANCH, commit)
            record["commit"] = commit
            record["resolved_at"] = now()
            self.save()
        self.check_tree(record, checkout)
        return checkout

    def check_tree(self, record: dict, checkout: Path):
        if self.git(checkout, "rev-parse", "HEAD") != record["commit"]:
            raise AuditError("Checkout HEAD changed from its pinned audit commit; use a new workspace")
        changed = self.git(checkout, "diff", "--name-only", record["commit"], "--").splitlines()
        # Reports can overwrite a report tracked by the upstream project.
        source_changes = [path for path in changed if not (len(Path(path).parts) == 1
                          and path.startswith(("PI_REVIEW", "REVIEW_")) and path.endswith(".md"))]
        if source_changes:
            raise AuditError("Review changed tracked source files: " + ", ".join(source_changes[:10]))

    def review(self, record: dict):
        try:
            checkout = self.prepare(record)
            record.pop("error", None)
            any_failed = False
            for mode in self.config["modes"]:
                if self.processes.cancel.is_set():
                    raise AuditError("Run interrupted")
                self.check_tree(record, checkout)
                phase = record["phases"].get(mode, {})
                if phase.get("status") == "complete":
                    for relative, fingerprint in phase.get("report_hashes", {}).items():
                        archived = self.workspace / relative
                        if not archived.is_file() or hashlib.sha256(archived.read_bytes()).hexdigest() != fingerprint:
                            raise AuditError(f"Archived evidence changed: {relative}. Use a new workspace.")
                    self.event(record, mode + " already complete; skipped")
                    continue
                record["status"] = "reviewing"
                record["phases"][mode] = phase | {"status": "running", "started": now()}
                self.save()
                self.event(record, mode + " started at " + record["commit"][:12])
                env = model_environment(Path(self.config["bot"]))
                env.update(PI_REVIEW_DATE=record["date"], PI_BRINGBACK="artifacts",
                           PI_BOX_FORCE="0",
                           PI_BOX_HOME=str(self.workspace / "boxes" / record["key"]),
                           PI_FLEET_JOBS=str(self.config["review_jobs"]),
                           PI_SWEEP_JOBS=str(self.config["review_jobs"]),
                           PI_BATCH_FLEX_CONCURRENCY=str(self.config["review_jobs"]))
                error = None
                previous_reports = {path.name: path.stat().st_mtime_ns for path in
                                    report_paths(checkout, mode, record["date"])}
                try:
                    phase_log = self.workspace / "logs" / record["key"] / (mode + ".log")
                    log_start = phase_log.stat().st_size if phase_log.exists() else 0
                    self.processes.run(review_command(self.config, mode, checkout), cwd=checkout, env=env,
                                       log=phase_log,
                                       timeout=self.config["timeout"])
                    with phase_log.open("rb") as handle:
                        handle.seek(log_start)
                        if any(re.search(rb"\(boxed command exited [1-9][0-9]*\)", line) for line in handle):
                            raise AuditError(f"A boxed reviewer command failed despite the launcher exit code; see {phase_log}")
                    self.check_tree(record, checkout)
                except (AuditError, OSError) as exc:
                    error = str(exc)
                artifacts = collect_phase(self.workspace, record, mode, previous_reports=previous_reports)
                gaps = any(x.get("unread") or x.get("unparsed_findings") or x.get("tree_binding") == "mismatch"
                           or x.get("unsafe_report") for x in artifacts["diagnostics"])
                status = "interrupted" if self.processes.cancel.is_set() else "failed" if error else "partial" if gaps else "complete"
                if not artifacts["reports"]:
                    status = "failed"
                    error = error or "Reviewer produced no final report for this phase"
                    # Retain earlier candidates when a retry fails before producing new evidence.
                    for field in ("reports", "findings", "coverage_reports"):
                        if phase.get(field):
                            artifacts[field] = phase[field]
                history = list(phase.get("history", []))
                if phase:
                    history.append({key: value for key, value in phase.items() if key != "history"})
                phase = artifacts | {"status": status, "finished": now(), "error": error,
                                     "history": history,
                                     "report_hashes": {p: hashlib.sha256((self.workspace / p).read_bytes()).hexdigest()
                                                       for p in artifacts["reports"] + artifacts.get("coverage_reports", [])}}
                record["phases"][mode] = phase
                any_failed |= status != "complete"
                self.save()
                self.event(record, f'{mode} {status}; {len(artifacts["findings"])} candidates')
                self.check_tree(record, checkout)
            record["status"] = "partial" if any_failed else "complete"
        except (AuditError, OSError) as exc:
            record["status"] = "interrupted" if self.processes.cancel.is_set() else "failed"
            record["error"] = str(exc)
            self.event(record, record["status"] + ": " + str(exc))
        finally:
            self.save()

    def run(self, *, jobs: int = 1, batch_size: int | None = None):
        records = self.state["repositories"]
        groups = [records] if batch_size is None else [records[i:i + batch_size] for i in range(0, len(records), batch_size)]
        for group in groups:
            if self.processes.cancel.is_set():
                break
            with ThreadPoolExecutor(max_workers=jobs) as executor:
                futures = [executor.submit(self.review, record) for record in group]
                for future in as_completed(futures):
                    future.result()
        self.save()
