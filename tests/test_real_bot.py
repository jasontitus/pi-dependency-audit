"""Opt-in integration with actual bot launchers and deterministic local models.

PI_AUDIT_INTEGRATION_BOT=/path/to/pi-review-bot python3 -m unittest discover -s tests -v
No hosted model calls. Requires pi-box's real sandbox backend and localhost.
"""
from __future__ import annotations

import http.server
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from pi_dependency_audit.cli import main


PI_STUB = r'''#!/usr/bin/env python3
import json,sys
from pathlib import Path
args=sys.argv[1:]
if args == ['--version']: print('1.0.2'); sys.exit(0)
if args == ['--list-models']:
    print('provider model context output thinking')
    for model in ('stub-a','stub-b','triage-stub'): print('deepinfra',model,'100K','10K','yes')
    sys.exit(0)
if args == ['--help']:
    print('--session-id --no-context-files --no-prompt-templates --no-extensions --tools --no-tools')
    sys.exit(0)
prompt=args[args.index('-p')+1]
if 'EVIDENCE:\n' in prompt:
    evidence=json.loads(prompt.split('EVIDENCE:\n',1)[1])
    response=json.dumps({'verdicts':[{'id':f['id'],'status':'prioritize','severity':'high','perspectives':['security'],'confidence':'high','reason':'Deterministic fixture: untrusted eval.','action':'Replace eval and run the regression test.'} for f in evidence]})
elif 'SELECTED FINDINGS:\n' in prompt:
    Path('bug.py').write_text('def handle(expression):\n    return int(expression)\n')
    Path('test_regression.py').write_text("from bug import handle\nassert handle('42') == 42\n")
    Path('PI_FIX_REPORT.md').write_text('Fixture fix; independent verification pending.\n')
    response='Fixture fix complete.'
else:
    # The real union triage machinery invokes Pi; keep the deterministic report.
    response='Fixture triage complete; candidates retained.'
print(json.dumps({'type':'message_end','message':{'role':'assistant','content':[{'type':'text','text':response}],'stopReason':'stop'}}))
print(json.dumps({'type':'agent_end'}))
'''


@unittest.skipUnless(os.environ.get("PI_AUDIT_INTEGRATION_BOT"), "set PI_AUDIT_INTEGRATION_BOT to test actual launchers")
class RealBotIntegration(unittest.TestCase):
    def test_review_reports_resume_synthesis_and_fix(self):
        bot = Path(os.environ["PI_AUDIT_INTEGRATION_BOT"]).expanduser().resolve()
        requests = []
        request_lock = threading.Lock()

        class Endpoint(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                if self.path != "/v1/chat/completions":
                    self.send_error(404)
                    return
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                user = next(m["content"] for m in body["messages"] if m["role"] == "user")
                recall = user.startswith("AUDIT THESE UNITS:\n")
                if recall:
                    units = json.loads(user.split("\n", 1)[1].split("\n\nSOURCE:", 1)[0])
                    files = list(dict.fromkeys(unit.split(":", 1)[0] for unit in units))
                    findings = [{"function": "handle", "file": name, "line": 2, "severity": "high",
                                 "mechanism": "eval permits code injection", "trigger": "untrusted expression"}
                                for name in files if name == "bug.py"]
                    text = json.dumps({"findings": findings, "audited": units})
                else:
                    match = re.search(r"File list \(\d+ files\):\n(.*?)\n\n", user, re.S)
                    files = match.group(1).splitlines() if match else []
                    text = "\n".join("- [high] bug.py:2 — eval permits code injection from untrusted input"
                                     for name in files if name == "bug.py")
                    text += "\n\n## Coverage\n" + "\n".join(name + " — clean" for name in files)
                with request_lock:
                    requests.append({"model": body["model"], "recall": recall, "files": files})
                reply = {"id": "fixture", "object": "chat.completion", "model": body["model"],
                         "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": text}}],
                         "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150,
                                   "prompt_tokens_details": {"cached_tokens": 50}}}
                payload = json.dumps(reply).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Endpoint)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory(prefix="pi-audit-integration.") as directory:
                root = Path(directory).resolve()
                binaries = root / "bin"
                binaries.mkdir()
                pi = binaries / "pi"
                pi.write_text(PI_STUB)
                pi.chmod(0o755)
                # Exercise the new pi-box Dart shim without a real Flutter SDK.
                flutter_bin = root / "flutter/bin"
                (flutter_bin / "internal").mkdir(parents=True)
                (flutter_bin / "internal/shared.sh").write_text("# Flutter launcher marker\n")
                launcher = flutter_bin / "dart"
                launcher.write_text("#!/bin/sh\necho 'Flutter launcher should have been bypassed' >&2\nexit 17\n")
                launcher.chmod(0o755)
                sdk_dart = flutter_bin / "cache/dart-sdk/bin/dart"
                sdk_dart.parent.mkdir(parents=True)
                sdk_dart.write_text('#!/bin/sh\n[ -n "$FLUTTER_ROOT" ] || exit 18\necho "Fixture Dart SDK: direct executable"\n')
                sdk_dart.chmod(0o755)
                (binaries / "dart").symlink_to(launcher)
                agent = root / "agent"
                agent.mkdir()
                (agent / "models.json").write_text('{"providers":{}}')
                repositories = []
                for name in ("tool-a", "tool-b"):
                    repo = root / name
                    repo.mkdir()
                    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
                    (repo / "bug.py").write_text("def handle(expression):\n    return eval(expression)\n")
                    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
                    subprocess.run(["git", "-C", str(repo), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                                    "commit", "-qm", "Fixture baseline"], check=True)
                    repositories.append(repo)
                workspace = root / "audit"
                args = ["run", "--bot", str(bot), "--workspace", str(workspace), "--models",
                        "deepinfra/stub-a:high,deepinfra/stub-b:high", "--triage-model", "deepinfra/triage-stub:high",
                        "--modes", "bug,security,data-safety,perf", "--transport", "flex", "--batch-size", "2", "--timeout", "120"]
                for repo in repositories:
                    args += ["--local-repo", str(repo)]
                environment = {"PATH": str(binaries) + os.pathsep + os.environ["PATH"],
                               "PI_CODING_AGENT_DIR": str(agent), "PI_BATCH_DEEPINFRA_BASE_URL": f"http://127.0.0.1:{server.server_port}",
                               "DEEPINFRA_API_KEY": "fixture-key", "PI_SWEEP_ARCHIVE": str(root / "archive"),
                               "PI_BATCH_FLEX_MAX_ATTEMPTS": "1", "PI_BATCH_FLEX_ATTEMPT_TIMEOUT": "10"}
                with patch.dict(os.environ, environment):
                    self.assertEqual(main(args), 0, "Actual bot review failed; inspect the preceding logs")
                    state = json.loads((workspace / "state.json").read_text())
                    for record in state["repositories"]:
                        self.assertEqual(record["status"], "complete")
                        for phase in record["phases"].values():
                            self.assertTrue(phase["reports"])
                            self.assertTrue(phase["findings"])
                            self.assertTrue(phase["coverage_reports"])
                    self.assertTrue(any(request["recall"] for request in requests))
                    self.assertTrue(any(not request["recall"] for request in requests))
                    count = len(requests)
                    self.assertEqual(main(args), 0)
                    self.assertEqual(len(requests), count, "Resume repeated model requests")
                    self.assertEqual(main(["summarize", "--workspace", str(workspace), "--model", "deepinfra/triage-stub", "--pi", str(pi)]), 0)
                    finding = json.loads((workspace / "findings.json").read_text())[0]
                    fix_args = ["fix", "--workspace", str(workspace), "--finding", finding["id"],
                                "--model", "deepinfra/stub-a", "--pi", str(pi)]
                    self.assertEqual(main(fix_args + ["--verify", "python3 test_regression.py", "--verify", "dart --version"]), 0)
                    updated = json.loads((workspace / "state.json").read_text())
                    fixed = json.loads((workspace / updated["fixes"][-1]).read_text())
                    dart_log = workspace / fixed["verification"][1]["log"]
                    self.assertIn("Fixture Dart SDK: direct executable", dart_log.read_text())
                    self.assertEqual(main(fix_args + ["--verify", "exit 7"]), 2)
                    state = json.loads((workspace / "state.json").read_text())
                    outcomes = [json.loads((workspace / path).read_text())["status"] for path in state["fixes"]]
                    self.assertEqual(outcomes, ["verified", "verification-failed"])
                for repo in repositories:
                    self.assertIn("eval(expression)", (repo / "bug.py").read_text())
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
