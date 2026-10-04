from __future__ import annotations

import contextlib
import dataclasses
import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import signal
import subprocess
import threading
import time
import tomllib
from pathlib import Path
from urllib.parse import urlsplit


class AuditError(Exception):
    pass


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + f".{os.getpid()}.tmp")
    with temp.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, path)


@contextlib.contextmanager
def workspace_lock(workspace: Path):
    workspace.mkdir(parents=True, exist_ok=True)
    with (workspace / ".lock").open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise AuditError(f"Another command is using {workspace}") from exc
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


@dataclasses.dataclass(frozen=True)
class Repository:
    name: str
    source: str
    ref: str | None = None
    usage: str = ""
    criticality: str = "normal"

    @property
    def key(self) -> str:
        return re.sub(r"[^a-zA-Z0-9_.-]", "-", self.name) + "-" + digest(
            [self.name, self.ref]
        )[:10]

    def as_dict(self) -> dict:
        return dataclasses.asdict(self) | {"key": self.key}


def parse_repository(value: str | dict, base: Path = Path.cwd()) -> Repository:
    entry = {"repo": value} if isinstance(value, str) else dict(value)
    criticality = entry.get("criticality", "normal")
    if criticality not in {"low", "normal", "critical"}:
        raise AuditError("criticality must be low, normal, or critical")
    ref = entry.get("ref")
    if "path" in entry:
        source = (base / entry["path"]).resolve()
        if not source.is_dir():
            raise AuditError(f"Local repository does not exist: {source}")
        name = "local/" + source.name + "-" + digest(str(source))[:8]
        return Repository(name, str(source), validate_ref(ref), str(entry.get("usage", "")), criticality)
    raw = str(entry.get("repo", "")).strip()
    if raw.startswith("git@github.com:"):
        raw = raw[len("git@github.com:"):]
    elif "://" in raw:
        url = urlsplit(raw)
        if url.scheme != "https" or url.netloc.lower() != "github.com" or url.query or url.fragment:
            raise AuditError(f"Use a GitHub HTTPS URL without credentials/query/fragment: {raw}")
        raw = url.path.strip("/")
    if "@" in raw:
        raw, suffix = raw.rsplit("@", 1)
        if ref is not None:
            raise AuditError("Specify a revision once, using @ref or the ref field")
        ref = suffix
    raw = raw.removesuffix(".git").strip("/")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", raw):
        raise AuditError(f"Expected owner/repo, owner/repo@ref, or a GitHub URL: {raw}")
    name = raw.lower()
    return Repository(name, "https://github.com/" + raw + ".git", validate_ref(ref),
                      str(entry.get("usage", "")), criticality)


def validate_ref(ref) -> str | None:
    if ref is None:
        return None
    ref = str(ref)
    if not ref or ref.startswith("-") or re.search(r"[\s\x00-\x1f~^:?*\[\\]", ref) or ".." in ref:
        raise AuditError(f"Invalid branch, tag, or commit: {ref!r}")
    return ref


def load_repositories(items: list[str], files: list[str], locals_: list[str]) -> list[Repository]:
    entries = [parse_repository(item) for item in items]
    entries += [parse_repository({"path": item}) for item in locals_]
    for filename in files:
        path = Path(filename).resolve()
        try:
            if path.suffix == ".json":
                data = json.loads(path.read_text())
                values = data if isinstance(data, list) else data["repositories"]
            elif path.suffix == ".toml":
                values = tomllib.loads(path.read_text())["repositories"]
            else:
                values = [line.split(" #", 1)[0].strip() for line in path.read_text().splitlines()
                          if line.strip() and not line.lstrip().startswith("#")]
            entries += [parse_repository(value, path.parent) for value in values]
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise AuditError(f"Could not read repository list {path}: {exc}") from exc
    unique = {}
    for repo in entries:
        if repo.key in unique and repo != unique[repo.key]:
            raise AuditError(f"Conflicting duplicate entries for {repo.name}@{repo.ref or 'default'}")
        unique[repo.key] = repo
    return list(unique.values())


class ProcessRunner:
    """Bound subprocess trees and terminate descendants on timeout/cancellation."""
    def __init__(self, cancel: threading.Event | None = None):
        self.cancel = cancel or threading.Event()

    def run(self, argv: list[str], *, cwd: Path | None = None, env: dict | None = None,
            log: Path | None = None, timeout: float = 3600, strip_output: bool = True) -> str:
        if self.cancel.is_set():
            raise AuditError("Run interrupted")
        if log:
            log.parent.mkdir(parents=True, exist_ok=True)
            output = log.open("ab")
        else:
            import tempfile
            output = tempfile.TemporaryFile()
        with output:
            proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                    stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
            deadline = time.monotonic() + timeout
            stopped = None
            while proc.poll() is None:
                if self.cancel.is_set() or time.monotonic() >= deadline:
                    stopped = "interrupted" if self.cancel.is_set() else f"timed out after {timeout:g}s"
                    self._kill_group(proc, signal.SIGTERM)
                    try:
                        proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        pass
                    self._kill_group(proc, signal.SIGKILL)
                    proc.wait()
                    break
                time.sleep(0.05)
            # A launcher can exit while leaving children alive.
            self._kill_group(proc, signal.SIGKILL)
            code = proc.wait()
            if stopped or code:
                detail = f"; see {log}" if log else ""
                raise AuditError(f"{Path(argv[0]).name} {stopped or f'exited {code}'}{detail}")
            if log:
                return ""
            output.seek(0)
            value = output.read().decode("utf-8", errors="replace")
            return value.strip() if strip_output else value

    @staticmethod
    def _kill_group(proc: subprocess.Popen, sig: int):
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            pass


def bot_path(value: str | None) -> Path:
    return Path(value or os.environ.get("PI_REVIEW_BOT", "~/experiments/pi-review-bot")).expanduser().resolve()


def model_environment(bot: Path) -> dict:
    """Read literal .env values without executing a shell or printing credentials."""
    env = os.environ.copy()
    if (bot / ".env").is_file():
        for line in (bot / ".env").read_text().splitlines():
            match = re.match(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$", line.strip())
            if match:
                key, value = match.groups()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                    value = value[1:-1]
                env.setdefault(key, value)
    return env
