from __future__ import annotations

import csv
import hashlib
import json
import re
import uuid
from pathlib import Path
from urllib.parse import quote

from .core import digest, write_json

SEVERITIES = {"critical": 0, "high": 1, "medium": 2, "low": 3, "nit": 4, "info": 5}
PERSPECTIVES = ("security", "data-safety", "performance", "availability", "correctness")
PATTERNS = {
    "security": r"security|inject|auth|credential|secret|token leak|permission|privilege|exploit|xss|ssrf|traversal|untrusted|rce|vulnerab",
    "data-safety": r"data.loss|corrupt|durab|transaction|rollback|migration|overwrite|truncate|delete|persist|backup|integrity|atomic|serialization",
    "performance": r"performance|slow|latency|throughput|n\+1|o\(n|quadratic|allocat|unbounded|cache|memory leak|hot.path|blocking|recomput",
    "availability": r"crash|deadlock|hang|timeout|retry|outage|denial.of.service|resource.exhaust|livelock|shutdown",
}
_FINDING = re.compile(r"^\s*[-*]\s+\[([^\]]+)\]\s+(.+)$")
_LOCATION = re.compile(r"^(?:\([^)]*\)\s*|\[(?:high|medium|low)\]\s*)*(?:`([^`]+)`|([^\s]+?)):(\d+)(?:[-–]\d+)?(?:\s|[—–:]|$)")
_BACKTICK_LOCATION = re.compile(r"^`(.+?):(\d+)(?:[-–]\d+)?`(?:\s|[—–:]|$)")
_COVERAGE = re.compile(r"^(?:[-*]\s+)?`?([^`]+?)`?\s+[—–]\s+(.+)$")


def source_path(checkout: Path, relative: str) -> Path | None:
    if not relative or Path(relative).is_absolute() or ".." in Path(relative).parts:
        return None
    target = (checkout / relative).resolve()
    if not target.is_relative_to(checkout.resolve()) or not target.is_file():
        return None
    return target


def perspectives(text: str, mode: str) -> list[str]:
    values = [p for p, pattern in PATTERNS.items() if re.search(pattern, text, re.I)]
    if mode in PERSPECTIVES and mode not in values:
        values.append(mode)
    return values or ["correctness"]


def parse_report(text: str, *, repo: dict, mode: str, origin: str,
                 checkout: Path) -> tuple[list[dict], dict]:
    findings, unparsed, coverage, bindings = [], [], {}, []
    section = ""
    in_code = False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            in_code = not in_code
            continue
        if in_code:
            continue
        heading = re.match(r"^#{1,2}\s+(.+)", line)
        if heading:
            section = heading.group(1).lower()
        tree = re.search(r"^Tree:.*\bhead=([0-9a-f]+)", line)
        if tree:
            bindings.append(tree.group(1))
        if section.startswith(("refuted", "dismissed", "rejected")):
            continue
        if "coverage" in section:
            if line.startswith("|"):
                columns = [part.strip().strip("`") for part in line.strip("|").split("|")]
                if len(columns) >= 5 and columns[3] in {"ran", "partial", "filtered", "scheduled"}:
                    coverage[columns[0] + " / " + columns[2]] = columns[3] + ": " + columns[4]
            m = _COVERAGE.match(line.strip())
            if m and not line.strip().startswith("- ["):
                coverage[m.group(1).strip()] = m.group(2).strip()
            continue
        m = _FINDING.match(line)
        if not m:
            continue
        severity, body = m.group(1).lower(), m.group(2)
        if severity in {"refuted", "dismissed", "duplicate", "confirmed", "clean", "ok"}:
            continue
        location = _LOCATION.match(body) or _BACKTICK_LOCATION.match(body)
        if severity not in SEVERITIES or not location:
            unparsed.append(line)
            continue
        if location.re is _BACKTICK_LOCATION:
            path, number = location.groups()
        else:
            a, b, number = location.groups()
            path = a or b
        path = path.removeprefix("./")
        line_number = int(number)
        detail = body[location.end():].lstrip(" —–:") or body
        # A suffix is provenance only when it has a lens/model shape.
        tag = re.search(r"\s+\{([^{}]+)\}\s*$", detail)
        tags = []
        if tag and any(c in tag.group(1) for c in "-/,@:"):
            tags = tag.group(1).split(",")
            detail = detail[:tag.start()].strip()
        found = source_path(checkout, path)
        anchored = bool(found and line_number > 0)
        if found:
            try:
                anchored = anchored and line_number <= len(found.read_text(errors="replace").splitlines())
            except OSError:
                anchored = False
        finding_id = "F-" + digest([repo["key"], repo["commit"], path, line_number, detail])[:16]
        findings.append({"id": finding_id, "repo_key": repo["key"], "repo": repo["name"],
                         "commit": repo["commit"], "usage": repo.get("usage", ""),
                         "criticality": repo.get("criticality", "normal"), "path": path,
                         "line": line_number, "severity": severity, "description": detail,
                         "perspectives": perspectives(detail, mode), "anchored": anchored,
                         "reports": [origin], "modes": [mode], "provenance": tags,
                         "assessment": "candidate", "checkout": str(checkout)})
    unread = {path: result for path, result in coverage.items()
              if re.search(r"NOT[ _]REVIEWED|UNEVIDENCED|unread|skipped|truncated|deferred|missing|^partial:|^filtered:|^scheduled:", result, re.I)}
    binding_matches = all(repo["commit"].startswith(value) for value in bindings)
    return findings, {"coverage": "partial" if unread else "reported" if coverage else "unknown",
                      "coverage_entries": len(coverage), "unread": unread,
                      "unparsed_findings": unparsed, "tree_binding": "mismatch" if not binding_matches
                      else "matched" if bindings else "not-reported"}


def report_paths(checkout: Path, mode: str, date: str) -> list[Path]:
    candidates = list(checkout.glob("PI_REVIEW*.md"))
    prefixes = {"bug": "PI_REVIEW_", "security": "PI_REVIEW_SECURITY_",
                "data-safety": "PI_REVIEW_DATA_SAFETY_", "perf": "PI_REVIEW_PERF_",
                "ultra": "PI_REVIEW_ULTRA_"}
    selected = []
    for path in candidates:
        name = path.name
        if not name.endswith(f"_{date}.md") or "COVERAGE" in name or "REVIEWED" in name:
            continue
        if not name.startswith(prefixes[mode]):
            continue
        if mode == "bug" and name.startswith(tuple(prefixes[x] for x in prefixes if x != "bug")):
            continue
        if mode == "ultra" and name != f"PI_REVIEW_ULTRA_{date}.md":
            continue
        selected.append(path)
    return selected


def collect_phase(workspace: Path, record: dict, mode: str, *, previous_reports: dict | None = None) -> dict:
    checkout = workspace / "repos" / record["key"]
    date = record["date"]
    selected = report_paths(checkout, mode, date)
    stale = [path for path in selected if previous_reports is not None and
             previous_reports.get(path.name) == path.stat().st_mtime_ns]
    selected = [path for path in selected if path not in stale]
    unions = [path for path in selected if "_UNION_" in path.name]
    if unions:
        selected = unions
    artifacts = workspace / "reports" / record["key"] / mode / uuid.uuid4().hex[:12]
    artifacts.mkdir(parents=True, exist_ok=True)
    result = {"reports": [], "findings": [], "diagnostics": []}
    if stale:
        result["diagnostics"].append({"stale_reports": [path.name for path in stale]})
    for path in sorted(selected):
        # Never ingest symlinks pointing outside the checkout.
        if source_path(checkout, path.name) is None:
            result["diagnostics"].append({"unsafe_report": path.name})
            continue
        body = path.read_text(errors="replace")
        destination = artifacts / path.name
        destination.write_text(body)
        relative = str(destination.relative_to(workspace))
        found, metadata = parse_report(body, repo=record, mode=mode, origin=relative, checkout=checkout)
        result["reports"].append(relative)
        result["findings"].extend(found)
        result["diagnostics"].append(metadata | {"report": relative})
    # Coverage matrices are evidence too, even when they do not use per-file blocks.
    for path in checkout.glob(f"*COVERAGE*_{date}.md"):
        focus = {"security": "SECURITY_", "data-safety": "DATA_SAFETY_", "perf": "PERF_", "ultra": "ULTRA_"}.get(mode, "")
        if mode == "ultra":
            if not path.name.startswith("PI_REVIEW_ULTRA_COVERAGE_"):
                continue
        elif not path.name.startswith("PI_REVIEW_COVERAGE_" + focus):
            continue
        elif mode == "bug" and path.name.startswith(tuple("PI_REVIEW_COVERAGE_" + f for f in ("SECURITY_", "DATA_SAFETY_", "PERF_", "ULTRA_"))):
            continue
        if source_path(checkout, path.name) is not None:
            destination = artifacts / path.name
            destination.write_text(path.read_text(errors="replace"))
            result.setdefault("coverage_reports", []).append(str(destination.relative_to(workspace)))
            _, metadata = parse_report(path.read_text(errors="replace"), repo=record, mode=mode,
                                       origin=str(destination.relative_to(workspace)), checkout=checkout)
            result["diagnostics"].append(metadata | {"coverage_report": str(destination.relative_to(workspace))})
    return result


def all_findings(state: dict) -> list[dict]:
    merged = {}
    for record in state["repositories"]:
        for phase in record.get("phases", {}).values():
            for finding in phase.get("findings", []):
                if finding["id"] not in merged:
                    merged[finding["id"]] = dict(finding)
                    continue
                current = merged[finding["id"]]
                for field in ("reports", "modes", "perspectives", "provenance"):
                    current[field] = sorted(set(current[field]) | set(finding[field]))
                current["severity"] = min((current["severity"], finding["severity"]), key=SEVERITIES.get)
    return sorted(merged.values(), key=rank_key)


def rank_key(finding: dict):
    return (SEVERITIES[finding["severity"]], {"critical": 0, "normal": 1, "low": 2}[finding["criticality"]],
            finding["repo"], finding["path"], finding["line"], finding["id"])


def md(value: str) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def link(finding: dict) -> str:
    label = md(f'{finding["path"]}:{finding["line"]}')
    if finding["repo"].startswith("local/") or not finding["anchored"]:
        return label
    return f'[{label}](https://github.com/{finding["repo"]}/blob/{finding["commit"]}/{quote(finding["path"], safe="/")}#L{finding["line"]})'


def render_portfolio(workspace: Path, state: dict, *, top: int = 20) -> list[dict]:
    findings = all_findings(state)
    write_json(workspace / "findings.json", findings)
    write_json(workspace / "assessments.json", state.get("synthesis", {"status": "not requested", "verdicts": {}}))
    with (workspace / "findings.csv").open("w", newline="") as handle:
        writer = csv.writer(handle)
        fields = ["id", "repo", "commit", "severity", "perspectives", "path", "line", "anchored", "description"]
        writer.writerow(fields)
        for finding in findings:
            row = []
            for field in fields:
                value = finding[field]
                value = ",".join(value) if isinstance(value, list) else str(value)
                row.append("'" + value if value.startswith(("=", "+", "-", "@")) else value)
            writer.writerow(row)
    lines = ["# Dependency audit", "", f'Created: {state["created"]}', "",
             "Findings are candidates unless independently validated. A completed invocation",
             "with no findings does not establish that a dependency is safe. Coverage and",
             "failed or missing reviews are shown below.", "", "## Repository status", "",
             "| Repository / usage | Commit | Phase | State | Coverage | Reports |",
             "|---|---|---|---|---|---|"]
    for repo in state["repositories"]:
        phases = repo.get("phases", {}) or {"not-started": {"status": repo["status"]}}
        for mode, phase in phases.items():
            diagnostics = phase.get("diagnostics", [])
            coverage = sorted({x.get("coverage", "unknown") for x in diagnostics}) or ["unknown"]
            reports = " ".join(f'[{Path(p).name}]({quote(p)})' for p in phase.get("reports", []) + phase.get("coverage_reports", []))
            lines.append(f'| {md(repo["name"])} {md(repo.get("usage", ""))} | {(repo.get("commit") or "unresolved")[:12]} | {mode} | {phase["status"]} | {", ".join(coverage)} | {reports} |')
            if phase.get("error"):
                lines += ["", f'**{md(repo["name"])} / {mode}:** {md(phase["error"])}', ""]
        if repo.get("error"):
            lines += ["", f'**{md(repo["name"])}:** {md(repo["error"])}', ""]
    verdicts = state.get("synthesis", {}).get("verdicts", {})
    lines += ["", "## Synthesis", "", f'Status: {state.get("synthesis", {}).get("status", "not requested")}.',
              "All candidates and provenance remain in findings.json and findings.csv."]
    for perspective in PERSPECTIVES:
        lines += ["", f"## {perspective}", ""]
        ranked = []
        for original in findings:
            verdict = verdicts.get(original["id"], {})
            finding = dict(original) | {k: verdict[k] for k in ("severity", "perspectives") if k in verdict}
            if perspective in finding["perspectives"] and verdict.get("status") != "reject":
                ranked.append((finding, verdict))
        ranked.sort(key=lambda pair: rank_key(pair[0]))
        if not ranked:
            lines.append("No candidates recorded for this perspective; check repository coverage above.")
        for finding, verdict in ranked[:top]:
            assessment = verdict.get("status", "candidate")
            anchor = "" if finding["anchored"] else "; source citation could not be anchored"
            lines += [f'- **[{finding["severity"]}] {md(finding["repo"])} — {link(finding)}**',
                      f'  {md(finding["description"])}',
                      f'  ID: `{finding["id"]}` · {assessment}{anchor}']
            if verdict:
                lines.append(f'  Assessment ({verdict["confidence"]} confidence): {md(verdict["reason"])}')
                lines.append(f'  Action: {md(verdict["action"])}')
        if len(ranked) > top:
            lines.append(f"\n{len(ranked) - top} additional candidates retained in findings.json.")
    rejected = [(finding, verdicts[finding["id"]]) for finding in findings
                if verdicts.get(finding["id"], {}).get("status") == "reject"]
    if rejected:
        lines += ["", "## Rejected by synthesis", ""]
        for finding, verdict in rejected:
            lines.append(f'- `{finding["id"]}` {md(finding["repo"])}: {md(verdict["reason"])}')
    problems = [(repo["name"], mode, diagnostic) for repo in state["repositories"]
                for mode, phase in repo.get("phases", {}).items() for diagnostic in phase.get("diagnostics", [])
                if diagnostic.get("unread") or diagnostic.get("unparsed_findings")
                or diagnostic.get("tree_binding") == "mismatch" or diagnostic.get("unsafe_report")]
    if problems:
        lines += ["", "## Evidence gaps", "", "Full diagnostics are recorded in state.json."]
        for name, mode, diagnostic in problems:
            lines.append(f'- {md(name)} / {mode}: {md(json.dumps(diagnostic, sort_keys=True))}')
    (workspace / "AUDIT.md").write_text("\n".join(lines) + "\n")
    return findings
