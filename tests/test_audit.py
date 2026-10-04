from __future__ import annotations

import contextlib
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from pi_dependency_audit.cli import main
from pi_dependency_audit.core import AuditError, ProcessRunner, parse_repository, workspace_lock
from pi_dependency_audit.models import finding_evidence, verdicts_from_text
from pi_dependency_audit.reports import parse_report, render_portfolio


FLEET = r'''#!/usr/bin/env python3
import os,sys,json,time,subprocess
from pathlib import Path
mode=sys.argv[1]; repo=Path(sys.argv[2]); source=(repo/'source.py').read_text()
focus=sys.argv[sys.argv.index('--focus')+1] if '--focus' in sys.argv else None
mode=focus or mode
with open(os.environ['FIXTURE_EVENTS'],'a') as h: h.write(json.dumps({'kind':'start','repo':repo.name,'mode':mode,'at':time.time()})+'\n')
time.sleep(float(os.environ.get('FIXTURE_SLEEP','0')) + (0.8 if 'SLOW' in source else 0))
if 'FAIL' in source: sys.exit(17)
if 'NO_REPORT' not in source:
    date=os.environ['PI_REVIEW_DATE']; prefix={'bug':'','perf':'PERF_','security':'SECURITY_','data-safety':'DATA_SAFETY_','ultra':'ULTRA_'}[mode]
    filename=f'PI_REVIEW_{prefix}STUB_{date}.md' if mode!='ultra' else f'PI_REVIEW_ULTRA_{date}.md'
    sha=subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip()
    findings='- [high] source.py:1 — untrusted eval allows code injection\n' if 'RISK' in source else ''
    verdict='NOT REVIEWED' if 'PARTIAL' in source else 'findings: 1' if findings else 'clean'
    (repo/filename).write_text(f'# Fixture review\nTree: branch=pi-dependency-snapshot head={sha}\n\n## Findings\n'+findings+('' if 'SEPARATE' in source else '\n## Coverage\nsource.py — '+verdict+'\n'))
    if 'SEPARATE' in source:
        (repo/f'PI_REVIEW_COVERAGE_{prefix}STUB_{date}.md').write_text(f'# Sweep coverage — per-file evidence\nTree: branch=pi-dependency-snapshot head={sha}\n\n- source.py — UNEVIDENCED\n')
with open(os.environ['FIXTURE_EVENTS'],'a') as h: h.write(json.dumps({'kind':'end','repo':repo.name,'mode':mode,'at':time.time()})+'\n')
if 'MASKED' in source: print('(boxed command exited 9)')
'''

PI = r'''#!/usr/bin/env python3
import sys,json,os
from pathlib import Path
prompt=sys.argv[sys.argv.index('-p')+1]
if 'SELECTED FINDINGS:\n' in prompt:
    Path('source.py').write_text('safe = True\n')
    Path('test_regression.py').write_text('assert True\n')
    Path('PI_FIX_REPORT.md').write_text('Fixed the fixture; verification is pending.\n')
    response='Fixture fix complete.'
else:
    batch=json.loads(prompt.split('EVIDENCE:\n',1)[1]); verdicts=[]
    for f in batch:
        verdicts.append({'id':f['id'],'status':'prioritize','severity':'high','perspectives':['security'],'confidence':'medium','reason':'Concrete injection candidate; confirm caller reachability.','action':'Replace eval with a constrained parser and reproduce.'})
    if os.environ.get('FIXTURE_BAD_SUMMARY'): verdicts=[]
    response=json.dumps({'verdicts':verdicts})
print(json.dumps({'type':'message_end','message':{'role':'assistant','content':[{'type':'text','text':response}],'stopReason':'stop'}}))
'''

BOX = r'''#!/usr/bin/env python3
import sys,os,hashlib,shutil,subprocess
from pathlib import Path
source=Path(sys.argv[2] if sys.argv[1]=='--print-work' else sys.argv[1]).resolve()
work=Path(os.environ['PI_BOX_HOME'])/'work'/hashlib.sha256(str(source).encode()).hexdigest()[:8]
if sys.argv[1]=='--print-work': print(work); sys.exit(0)
assert os.environ['PI_BOX_FORCE']=='0'
if not work.exists(): shutil.copytree(source,work)
args=sys.argv[sys.argv.index('--')+1:]
code = subprocess.run(args,cwd=work).returncode
sys.exit(0 if os.environ.get('FIXTURE_BOX_MASK_EXIT') else code)
'''


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.bot = self.root / "bot"
        self.bot.mkdir()
        self.executable(self.bot / "pi-fleet", FLEET)
        self.executable(self.bot / "pi-box", BOX)
        self.pi = self.root / "pi"
        self.executable(self.pi, PI)
        self.events = self.root / "events.jsonl"
        self.workspace = self.root / "audit"
        self.environment = patch.dict(os.environ, {"FIXTURE_EVENTS": str(self.events), "PI_BOX_FORCE": "1"})
        self.environment.start()

    def tearDown(self):
        self.environment.stop()
        self.temp.cleanup()

    def executable(self, path, body):
        path.write_text(body)
        path.chmod(0o755)

    def git(self, repo, *args):
        return subprocess.check_output(["git", "-C", str(repo), *args], stderr=subprocess.DEVNULL, text=True).strip()

    def repo(self, name="tool", body="RISK\n"):
        repo = self.root / name
        repo.mkdir()
        subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
        self.git(repo, "config", "user.name", "Fixture")
        self.git(repo, "config", "user.email", "fixture@example.invalid")
        (repo / "source.py").write_text(body)
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-qm", "Fixture baseline")
        return repo

    def call(self, *args):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return main(list(args))

    def run_args(self, repos, *extra):
        args = ["run", "--bot", str(self.bot), "--workspace", str(self.workspace), "--modes", "bug"]
        for repo in repos:
            args += ["--local-repo", str(repo)]
        return args + list(extra)

    def state(self):
        return json.loads((self.workspace / "state.json").read_text())

    def events_list(self):
        return [json.loads(line) for line in self.events.read_text().splitlines()]

    def test_input_validation_and_revision_identity(self):
        repo = parse_repository("https://github.com/Owner/Tool.git@v1.2")
        self.assertEqual((repo.name, repo.ref), ("owner/tool", "v1.2"))
        self.assertEqual(repo.key, parse_repository("owner/tool@v1.2").key)
        self.assertNotEqual(repo.key, parse_repository("owner/tool@v1.3").key)
        self.assertEqual(parse_repository("git@github.com:owner/tool.git").name, "owner/tool")
        for bad in ["https://evil.example/o/r", "https://secret@github.com/o/r", "owner/../tool", "owner/repo@--upload-pack=evil", "owner/repo@main~1"]:
            with self.assertRaises(AuditError): parse_repository(bad)

    def test_dry_run_never_clones_or_creates_workspace(self):
        self.assertEqual(self.call("run", "owner/tool@v1", "--bot", str(self.bot), "--workspace", str(self.workspace), "--dry-run"), 0)
        self.assertFalse(self.workspace.exists())
        self.assertFalse(self.events.exists())

    def test_pinned_ref_resume_skips_completed_work_and_preserves_source(self):
        repo = self.repo()
        original = self.git(repo, "rev-parse", "HEAD")
        self.assertEqual(self.call(*self.run_args([repo])), 0)
        first_events = self.events.read_text()
        (repo / "source.py").write_text("new upstream version\n")
        self.git(repo, "commit", "-am", "Advance upstream")
        self.assertEqual(self.call(*self.run_args([repo])), 0)
        self.assertEqual(self.events.read_text(), first_events)
        self.assertEqual(self.state()["repositories"][0]["commit"], original)
        findings = json.loads((self.workspace / "findings.json").read_text())
        checkout = Path(findings[0]["checkout"])
        (checkout / "source.py").write_text("edited working copy\n")
        self.assertIn("RISK", finding_evidence(findings[0])["source_excerpt"])
        self.assertEqual(self.call(*self.run_args([repo])), 2)

    def test_tag_manifest_and_multiple_versions(self):
        repo = self.repo()
        self.git(repo, "tag", "v1")
        original = self.git(repo, "rev-parse", "HEAD")
        (repo / "source.py").write_text("safe=True\n")
        self.git(repo, "commit", "-am", "v2")
        manifest = self.root / "repos.toml"
        manifest.write_text(f'[[repositories]]\npath = "{repo.name}"\nref = "v1"\nusage = "Processes customer data"\ncriticality = "critical"\n\n[[repositories]]\npath = "{repo.name}"\nref = "main"\n')
        self.assertEqual(self.call(*self.run_args([]), "--repos-file", str(manifest)), 0)
        records = self.state()["repositories"]
        self.assertEqual(records[0]["commit"], original)
        self.assertNotEqual(records[0]["commit"], records[1]["commit"])
        self.assertEqual(records[0]["criticality"], "critical")

    def test_wave_batches_and_rolling_concurrency(self):
        repos = [self.repo("tool" + str(i)) for i in range(5)]
        with patch.dict(os.environ, {"FIXTURE_SLEEP": "0.15"}):
            self.assertEqual(self.call(*self.run_args(repos), "--batch-size", "2"), 0)
        events = self.events_list()
        starts = [e for e in events if e["kind"] == "start"]
        ends = {e["repo"]: e["at"] for e in events if e["kind"] == "end"}
        self.assertLess(starts[1]["at"], ends[starts[0]["repo"]])
        self.assertGreater(starts[2]["at"], max(ends[starts[0]["repo"]], ends[starts[1]["repo"]]))

    def test_rolling_pool_starts_next_before_slow_peer_finishes(self):
        repos = [self.repo("slow", "SLOW RISK\n"), self.repo("fast"), self.repo("next")]
        with patch.dict(os.environ, {"FIXTURE_SLEEP": "0.15"}):
            self.assertEqual(self.call(*self.run_args(repos), "--jobs", "2"), 0)
        events = self.events_list()
        starts = {e["repo"]: e["at"] for e in events if e["kind"] == "start"}
        ends = {e["repo"]: e["at"] for e in events if e["kind"] == "end"}
        records = self.state()["repositories"]
        self.assertLess(starts[records[2]["key"]], ends[records[0]["key"]])

    def test_masked_boxed_reviewer_failure_cannot_pass(self):
        self.assertEqual(self.call(*self.run_args([self.repo(body="RISK MASKED\n")])), 2)
        phase = self.state()["repositories"][0]["phases"]["bug"]
        self.assertEqual(phase["status"], "failed")
        self.assertEqual(len(phase["findings"]), 1)
        self.assertIn("boxed reviewer command failed", phase["error"])

    def test_failures_missing_reports_and_partial_coverage_are_visible(self):
        repos = [self.repo("fail", "FAIL\n"), self.repo("missing", "NO_REPORT\n"), self.repo("partial", "PARTIAL\n"), self.repo("good")]
        self.assertEqual(self.call(*self.run_args(repos)), 2)
        self.assertEqual([r["status"] for r in self.state()["repositories"]], ["partial", "partial", "partial", "complete"])
        text = (self.workspace / "AUDIT.md").read_text()
        self.assertIn("partial", text)
        self.assertIn("Evidence gaps", text)
        self.assertEqual(len(json.loads((self.workspace / "findings.json").read_text())), 1)

    def test_focused_names_and_actual_separate_coverage_format(self):
        repo = self.repo(body="RISK PARTIAL SEPARATE\n")
        args = self.run_args([repo])
        args[args.index("--modes") + 1] = "data-safety"
        self.assertEqual(self.call(*args), 2)
        phase = self.state()["repositories"][0]["phases"]["data-safety"]
        self.assertEqual(len(phase["findings"]), 1)
        self.assertEqual(phase["status"], "partial")
        self.assertEqual(phase["diagnostics"][-1]["unread"], {"source.py": "UNEVIDENCED"})
        self.assertIn("DATA_SAFETY", phase["reports"][0])

    def test_ultra_coverage_matrix_records_incomplete_lenses(self):
        repo = self.repo()
        record = {"key": "repo", "name": "owner/repo", "commit": self.git(repo, "rev-parse", "HEAD")}
        text = "# Ultra lens coverage matrix\n| Bundle | Targets | Lens | Status | Reason |\n|---|---|---|---|---|\n| `api` | 5 | `security-review` | partial | 2/5 targets evidenced |\n| `api` | 0 | `sql-review` | not applicable | no route |\n"
        _, diagnostic = parse_report(text, repo=record, mode="ultra", origin="coverage.md", checkout=repo)
        self.assertEqual(diagnostic["coverage"], "partial")
        self.assertEqual(len(diagnostic["unread"]), 1)

    def test_clone_failure_still_produces_portfolio(self):
        empty = self.root / "not-a-repository"
        empty.mkdir()
        self.assertEqual(self.call(*self.run_args([empty, self.repo()])), 2)
        self.assertEqual(self.state()["repositories"][0]["status"], "failed")
        self.assertIn("unresolved", (self.workspace / "AUDIT.md").read_text())

    def test_stale_report_cannot_masquerade_as_a_new_review(self):
        repo = self.repo(body="NO_REPORT\n")
        from pi_dependency_audit.core import now
        date = now()[:10].replace("-", "")
        (repo / f"PI_REVIEW_STUB_{date}.md").write_text("# Old upstream review\n")
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-qm", "Add stale report")
        self.assertEqual(self.call(*self.run_args([repo])), 2)
        self.assertEqual(self.state()["repositories"][0]["phases"]["bug"]["reports"], [])

    def test_retry_preserves_previous_candidates_and_raw_artifacts(self):
        repo = self.repo(body="RISK PARTIAL\n")
        self.assertEqual(self.call(*self.run_args([repo])), 2)
        first = self.state()["repositories"][0]["phases"]["bug"]
        self.executable(self.bot / "pi-fleet", FLEET.replace("if 'FAIL' in source:", "if True:"))
        # Adapt the saved launcher fingerprint to represent an explicit fixture retry.
        from pi_dependency_audit.runner import launcher_fingerprint
        from pi_dependency_audit.core import write_json
        saved = self.state()
        saved["config"]["bot_fingerprint"] = launcher_fingerprint(self.bot)
        write_json(self.workspace / "state.json", saved)
        self.assertEqual(self.call(*self.run_args([repo])), 2)
        phase = self.state()["repositories"][0]["phases"]["bug"]
        self.assertEqual(len(phase["findings"]), 1)
        self.assertEqual(phase["history"][0]["reports"], first["reports"])
        self.assertTrue((self.workspace / first["reports"][0]).is_file())

    def test_ci_fail_on_severity_and_configuration_binding(self):
        repo = self.repo()
        self.assertEqual(self.call(*self.run_args([repo]), "--fail-on", "high"), 1)
        self.assertEqual(self.call(*self.run_args([repo]), "--models", "provider/different"), 2)
        self.assertEqual(self.call(*self.run_args([repo]), "--fail-on", "critical"), 0)

    def test_summary_partial_answers_never_drop_candidates_and_cache_is_resumable(self):
        self.assertEqual(self.call(*self.run_args([self.repo()])), 0)
        args = ["summarize", "--workspace", str(self.workspace), "--model", "fixture/model", "--pi", str(self.pi)]
        with patch.dict(os.environ, {"FIXTURE_BAD_SUMMARY": "1"}):
            self.assertEqual(self.call(*args), 2)
        self.assertEqual(len(json.loads((self.workspace / "findings.json").read_text())), 1)
        self.assertEqual(self.state()["synthesis"]["status"], "partial")
        self.assertEqual(self.call(*args), 0)
        before = self.state()["synthesis"]["finished"]
        self.assertEqual(self.call(*args), 0)
        self.assertEqual(self.state()["synthesis"]["finished"], before)
        self.assertIn("prioritize", (self.workspace / "AUDIT.md").read_text())

    def test_duplicate_missing_and_unknown_verdict_ids_rejected(self):
        good = {"id": "F-1", "status": "needs-context", "severity": "high", "perspectives": ["security"], "confidence": "low", "reason": "Need callers", "action": "Read callers"}
        self.assertEqual(len(verdicts_from_text(json.dumps({"verdicts": [good]}), {"F-1"})), 1)
        for verdicts in [[], [good, good], [dict(good, id="F-2")]]:
            with self.assertRaises(AuditError): verdicts_from_text(json.dumps({"verdicts": verdicts}), {"F-1"})

    def test_unanchored_malformed_refuted_and_symlink_findings(self):
        checkout = self.repo()
        secret = self.root / "outside.txt"
        secret.write_text("private data\n")
        (checkout / "link.py").symlink_to(secret)
        record = {"key": "repo", "name": "owner/repo", "commit": self.git(checkout, "rev-parse", "HEAD")}
        report = "## Findings\n- [high] link.py:1 — secret leak\n- [high] missing.py:1 — crash\n- [high] malformed claim\n## Refuted in triage\n- [high] source.py:1 — refuted injection\n"
        findings, diagnostic = parse_report(report, repo=record, mode="bug", origin="report.md", checkout=checkout)
        self.assertEqual(len(findings), 2)
        self.assertFalse(any(f["anchored"] for f in findings))
        self.assertEqual(len(diagnostic["unparsed_findings"]), 1)

    def test_fix_patch_has_new_tests_and_original_audit_stays_unchanged(self):
        repo = self.repo()
        self.assertEqual(self.call(*self.run_args([repo])), 0)
        finding = json.loads((self.workspace / "findings.json").read_text())[0]
        command = "python3 -c \"from pathlib import Path; assert 'safe = True' in Path('source.py').read_text()\""
        self.assertEqual(self.call("fix", "--workspace", str(self.workspace), "--finding", finding["id"], "--model", "fixture/model", "--pi", str(self.pi), "--verify", command), 0)
        result = json.loads((self.workspace / self.state()["fixes"][-1]).read_text())
        self.assertEqual(result["status"], "verified")
        patchfile = self.workspace / result["patch"]
        self.assertIn("test_regression.py", patchfile.read_text())
        self.assertEqual((repo / "source.py").read_text(), "RISK\n")
        self.assertEqual((Path(finding["checkout"]) / "source.py").read_text(), "RISK\n")
        self.git(Path(finding["checkout"]), "apply", "--check", str(patchfile))

    def test_fix_failure_is_saved_and_check_failures_are_reported(self):
        self.assertEqual(self.call(*self.run_args([self.repo()])), 0)
        finding = json.loads((self.workspace / "findings.json").read_text())[0]
        args = ["fix", "--workspace", str(self.workspace), "--finding", finding["id"], "--model", "fixture/model", "--pi", str(self.pi)]
        self.assertEqual(self.call(*args, "--verify", "exit 4"), 2)
        result = json.loads((self.workspace / self.state()["fixes"][-1]).read_text())
        self.assertEqual(result["status"], "verification-failed")
        with patch.dict(os.environ, {"FIXTURE_BOX_MASK_EXIT": "1"}):
            self.assertEqual(self.call(*args, "--verify", "exit 7"), 2)
        result = json.loads((self.workspace / self.state()["fixes"][-1]).read_text())
        self.assertEqual(result["status"], "verification-failed")
        self.assertIn("exited 7", result["verification"][0]["error"])
        (self.bot / "pi-box").unlink()
        self.assertEqual(self.call(*args), 2)
        result = json.loads((self.workspace / self.state()["fixes"][-1]).read_text())
        self.assertEqual(result["status"], "failed")

    def test_workspace_lock_excludes_second_writer(self):
        with workspace_lock(self.workspace):
            with self.assertRaises(AuditError):
                with workspace_lock(self.workspace): pass

    def test_timeout_reaps_subprocess_tree(self):
        heartbeat = self.root / "child.heartbeat"
        script = self.root / "sleeper.py"
        child = "import time,sys\nfrom pathlib import Path\nwhile True:\n Path(sys.argv[1]).write_text(str(time.monotonic()))\n time.sleep(.01)\n"
        script.write_text("import subprocess,time,sys\nsubprocess.Popen([sys.executable,'-c'," + repr(child) + ",sys.argv[1]])\ntime.sleep(100)\n")
        with self.assertRaises(AuditError):
            ProcessRunner().run([sys.executable, str(script), str(heartbeat)], timeout=0.3)
        last = heartbeat.read_text()
        time.sleep(.15)
        self.assertEqual(heartbeat.read_text(), last, "Child process survived its parent's timeout")


if __name__ == "__main__":
    unittest.main()
