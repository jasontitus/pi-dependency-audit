from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import sys
import threading
from pathlib import Path

from . import __version__
from .core import AuditError, ProcessRunner, bot_path, load_repositories, workspace_lock
from .fixes import fix_findings
from .models import synthesize
from .reports import SEVERITIES, render_portfolio
from .runner import Campaign, MODES, launcher_fingerprint, load_state, review_command


def positive(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="Audit GitHub dependencies with pi-review-bot and rank portfolio findings.")
    root.add_argument("--version", action="version", version=__version__)
    sub = root.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="clone/pin and review repositories; rerunning resumes")
    run.add_argument("repositories", nargs="*", help="owner/repo, owner/repo@ref, or GitHub HTTPS URL")
    run.add_argument("--repos-file", action="append", default=[], help="text, JSON, or TOML repository list; repeatable")
    run.add_argument("--local-repo", action="append", default=[], help="audit a clone of a local Git repository")
    run.add_argument("--workspace", default="audits/default", help="persistent campaign directory")
    run.add_argument("--bot", help="pi-review-bot checkout (default PI_REVIEW_BOT or ~/experiments/pi-review-bot)")
    run.add_argument("--reviewer", help="override the pi-fleet executable, for adapters/testing")
    run.add_argument("--modes", default="bug,perf", help="comma-separated bug,security,data-safety,perf,ultra")
    run.add_argument("--models", help="comma-separated Pi review model patterns; otherwise use pi-fleet presets")
    run.add_argument("--triage-model", help="override pi-fleet's per-repo triage model")
    run.add_argument("--no-repo-triage", action="store_true", help="retain raw per-repo findings (not supported by ultra)")
    run.add_argument("--transport", choices=["default", "live", "batch", "flex"], default="default")
    concurrency = run.add_mutually_exclusive_group()
    concurrency.add_argument("--jobs", type=positive, help="rolling pool of N repositories; default sequential")
    concurrency.add_argument("--batch-size", type=positive, help="waves of N repositories; wait for a wave before starting the next")
    run.add_argument("--review-jobs", type=positive, default=1, help="in-flight batches per review model (default 1); models may run concurrently")
    run.add_argument("--timeout", type=positive, default=7200, help="seconds per review phase, including children")
    run.add_argument("--clone-timeout", type=positive, default=300)
    run.add_argument("--dry-run", action="store_true", help="print the plan without cloning, creating a workspace, or calling models")
    run.add_argument("--summarize", action="store_true", help="optionally assess all candidates across repositories using Pi")
    run.add_argument("--summary-model", help="required with --summarize; independent triage model recommended")
    run.add_argument("--summary-batch-size", type=positive, default=12)
    run.add_argument("--summary-timeout", type=positive, default=600)
    run.add_argument("--pi", default="pi", help="Pi executable for portfolio synthesis")
    run.add_argument("--top", type=positive, default=20, help="issues displayed per perspective; all are retained in JSON/CSV")
    run.add_argument("--fail-on", choices=list(SEVERITIES), help="exit 1 if candidates meet this severity; incomplete runs exit 2")
    for command in ("status", "report", "summarize", "fix"):
        child = sub.add_parser(command, help={"status": "inspect saved progress", "report": "rebuild ranked Markdown/JSON/CSV without model calls",
                                               "summarize": "assess existing candidates across repositories", "fix": "fix selected IDs in an isolated checkout and emit a patch"}[command])
        child.add_argument("--workspace", default="audits/default")
        if command in {"report", "summarize"}:
            child.add_argument("--top", type=positive, default=20)
        if command in {"summarize", "fix"}:
            child.add_argument("--model", required=True)
            child.add_argument("--bot")
            child.add_argument("--pi", default="pi")
            child.add_argument("--timeout", type=positive, default=600 if command == "summarize" else 3600)
        if command == "summarize":
            child.add_argument("--batch-size", type=positive, default=12)
        if command == "fix":
            child.add_argument("--finding", action="append", required=True, help="finding ID; repeat for related findings in one repository")
            child.add_argument("--verify", action="append", default=[], help="independent verification command run in a fresh pi-box copy; repeatable")
    doctor = sub.add_parser("doctor", help="check prerequisites without model calls")
    doctor.add_argument("--bot")
    doctor.add_argument("--pi", default="pi")
    return root


def campaign_config(args) -> dict:
    modes = list(dict.fromkeys(args.modes.split(",")))
    if any(mode not in MODES for mode in modes):
        raise AuditError("Invalid --modes; choose " + ",".join(MODES))
    if "ultra" in modes and (args.no_repo_triage or args.transport == "live"):
        raise AuditError("ultra requires triage and does not accept live transport")
    if args.summarize and not args.summary_model:
        raise AuditError("--summarize requires --summary-model")
    bot = bot_path(args.bot)
    reviewer = Path(args.reviewer).expanduser().resolve() if args.reviewer else bot / "pi-fleet"
    return {"bot": str(bot), "bot_fingerprint": launcher_fingerprint(bot), "reviewer": str(reviewer),
            "modes": modes, "models": args.models, "triage_model": args.triage_model,
            "no_repo_triage": args.no_repo_triage, "transport": args.transport,
            "review_jobs": args.review_jobs, "timeout": args.timeout, "clone_timeout": args.clone_timeout}


def run(args, processes: ProcessRunner) -> int:
    repositories = load_repositories(args.repositories, args.repos_file, args.local_repo)
    workspace = Path(args.workspace).expanduser().resolve()
    config = campaign_config(args)
    if args.dry_run:
        if not repositories and (workspace / "state.json").exists():
            saved = load_state(workspace)
            plan = saved["repositories"]
        else:
            plan = [repo.as_dict() for repo in repositories]
        if not plan:
            raise AuditError("Provide repositories to plan a run")
        print(json.dumps({"workspace": str(workspace), "jobs": args.jobs or args.batch_size or 1,
                          "batch_size": args.batch_size, "config": config,
                          "repositories": [repo | {"commands": [review_command(config, mode, workspace / "repos" / repo["key"])
                                                                for mode in config["modes"]]} for repo in plan]}, indent=2))
        return 0
    if not shutil.which("git") or not os.access(config["reviewer"], os.X_OK):
        raise AuditError("git and an executable pi-fleet are required; run doctor or supply --bot/--reviewer")
    with workspace_lock(workspace):
        campaign = Campaign(workspace, config, repositories, processes=processes)
        campaign.run(jobs=args.jobs or args.batch_size or 1, batch_size=args.batch_size)
        if args.summarize and not processes.cancel.is_set():
            synthesize(workspace, campaign.state, model=args.summary_model, pi=args.pi, bot=Path(config["bot"]),
                       processes=processes, batch_size=args.summary_batch_size, timeout=args.summary_timeout)
        findings = render_portfolio(workspace, campaign.state, top=args.top)
        print(f"Report: {workspace / 'AUDIT.md'}", flush=True)
        if processes.cancel.is_set():
            return 130
        if any(repo["status"] != "complete" for repo in campaign.state["repositories"]):
            return 2
        if args.summarize and campaign.state.get("synthesis", {}).get("status") != "complete":
            return 2
        if args.fail_on and any(SEVERITIES[f["severity"]] <= SEVERITIES[args.fail_on] for f in findings):
            return 1
        return 0


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    processes = ProcessRunner(threading.Event())
    previous = {}
    if threading.current_thread() is threading.main_thread():
        for sig in (signal.SIGINT, signal.SIGTERM):
            previous[sig] = signal.getsignal(sig)
            signal.signal(sig, lambda signum, frame: processes.cancel.set())
    try:
        if args.command == "run":
            return run(args, processes)
        if args.command == "doctor":
            bot = bot_path(args.bot)
            missing = False
            for name, executable in [("git", "git"), ("pi", args.pi), ("pi-fleet", str(bot / "pi-fleet")), ("pi-box", str(bot / "pi-box"))]:
                found = shutil.which(executable)
                missing |= found is None
                print(f"{name}: {found or 'MISSING'}")
            if shutil.which(args.pi):
                version = processes.run([args.pi, "--version"], timeout=30)
                print("Pi version: " + version)
                match = re.search(r"(?<!\d)(\d+)\.(\d+)\.(\d+)", version)
                if not match or tuple(map(int, match.groups())) < (0, 83, 0):
                    missing = True
                    print("pi-review-bot requires Pi 0.83.0 or newer; select the appropriate Pi/Node installation on PATH")
            backend = shutil.which("sandbox-exec") or shutil.which("bwrap")
            missing |= backend is None
            print("Sandbox backend: " + str(backend or "MISSING"))
            return 2 if missing else 0
        workspace = Path(args.workspace).expanduser().resolve()
        if args.command == "status":
            state = load_state(workspace)
            for record in state["repositories"]:
                phases = ", ".join(f'{mode}={phase["status"]}' for mode, phase in record.get("phases", {}).items())
                print(f'{record["name"]}@{record.get("commit") or "unresolved"}: {record["status"]} ({phases})')
            print("Synthesis: " + state.get("synthesis", {}).get("status", "not requested"))
            return 0
        with workspace_lock(workspace):
            state = load_state(workspace)
            if args.command == "report":
                render_portfolio(workspace, state, top=args.top)
                print(workspace / "AUDIT.md")
                return 0
            if args.command == "summarize":
                bot = bot_path(args.bot or state["config"]["bot"])
                synthesize(workspace, state, model=args.model, pi=args.pi, bot=bot, processes=processes,
                           batch_size=args.batch_size, timeout=args.timeout)
                render_portfolio(workspace, state, top=args.top)
                return 130 if processes.cancel.is_set() else 0 if state["synthesis"]["status"] == "complete" else 2
            if args.command == "fix":
                result = fix_findings(workspace, state, identifiers=args.finding, model=args.model,
                                      bot=bot_path(args.bot or state["config"]["bot"]), pi=args.pi,
                                      processes=processes, verify=args.verify, timeout=args.timeout)
                print(json.dumps(result, indent=2))
                return 130 if processes.cancel.is_set() else 2 if result["status"] in {"failed", "verification-failed"} else 0
    except (AuditError, OSError, ValueError) as exc:
        print(f"pi-dependency-audit: {exc}", file=sys.stderr)
        return 130 if processes.cancel.is_set() else 2
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    return 0
