from __future__ import annotations

import hashlib
import shutil
import threading
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from aegis.discover import ORDER, DiscoverError, risk_of, scan
from aegis.intel import build_paths, picture
from aegis.models import Finding
from aegis.remediate import MANAGED, diff_trees, harden, inject_regression, load_tree, write_tree
from aegis.sandbox import SandboxError, run_audit
from aegis.targets import demo_list, public_target, target_by_id

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "northwind"
WORKSPACE = ROOT / "var" / "workspace" / "northwind"


class EngineError(Exception):
    pass


class Engine:
    def __init__(self, fixture: Path, workspace: Path, target_id: str | None = None):
        self.fixture = fixture
        self.workspace = workspace
        self._workspace_root = workspace.parent
        self.target_id = target_id or fixture.name
        self.lock = threading.Lock()
        self.phase = "ready"
        self.findings: list[Finding] = []
        self.events: list[dict] = []
        self.applied: list[dict] = []
        self.watching = False
        self.last_checked: str | None = None
        self.digest = ""
        self.drift = None
        self._seq = 0

    def state(self) -> dict:
        with self.lock:
            return self._state_locked()

    def scan(self) -> dict:
        with self.lock:
            self.findings = []
            self.events = []
            self.applied = []
            self._copy_fixture_locked()
            self._rescan_locked("scan")
            self.watching = True
            return self._state_locked()

    def remediate(self) -> dict:
        with self.lock:
            self._require_workspace()
            before = load_tree(self.workspace)
            after = harden(before)
            diffs = diff_trees(before, after, self._target().get("summaries"))
            if not diffs:
                risk = self._risk_locked()
                self._event(
                    "remediate",
                    "Nothing to change",
                    "The workspace already matches the hardened files.",
                    risk,
                )
                if self.phase != "ready":
                    self.phase = "verified"
                self.digest = self._digest_locked()
                return self._state_locked()
            write_tree(self.workspace, after)
            self.applied = diffs
            self._rescan_locked("remediate")
            return self._state_locked()

    def inject(self) -> dict:
        with self.lock:
            self._require_workspace()
            compose = self.workspace / "docker-compose.yml"
            if not compose.is_file():
                raise EngineError("docker-compose.yml is not in the workspace.")
            compose.write_text(inject_regression(compose.read_text()))
            self._rescan_locked("watch")
            return self._state_locked()

    def audit(self) -> dict:
        with self.lock:
            self._require_workspace()
            spec = self._target()
            if not spec["drift"]:
                report = {
                    "status": "skipped",
                    "title": "Runtime drift stays on Northwind Checkout",
                    "summary": spec["drift_intro"],
                    "findings": [],
                    "rows": [],
                    "sandbox": None,
                }
                self.drift = report
                self._event("drift", report["title"], report["summary"], self._risk_locked())
                return self._state_locked()
            try:
                report = run_audit(self.workspace)
            except SandboxError as exc:
                raise EngineError(str(exc)) from exc
            self.drift = report
            self._event("drift", report["title"], report["summary"], self._risk_locked())
            return self._state_locked()

    def check(self) -> dict:
        with self.lock:
            self.last_checked = _now()
            if self.phase == "ready" or not self.workspace.exists():
                return self._state_locked()
            digest = self._digest_locked()
            if digest != self.digest:
                self._rescan_locked("watch")
            return self._state_locked()

    def select(self, target_id: str) -> dict:
        with self.lock:
            spec = target_by_id(target_id)
            if spec is None:
                raise EngineError("That demo is not in this list.")
            self.target_id = spec["id"]
            self.fixture = ROOT / "fixtures" / spec["dir"]
            self.workspace = self._workspace_root / spec["dir"]
            self._reset_locked()
            return self._state_locked()

    def reset(self) -> dict:
        with self.lock:
            self._reset_locked()
            return self._state_locked()

    def _reset_locked(self) -> None:
        self._copy_fixture_locked()
        self.phase = "ready"
        self.findings = []
        self.events = []
        self.applied = []
        self.watching = False
        self.last_checked = None
        self.digest = self._digest_locked()
        self.drift = None

    def _require_workspace(self) -> None:
        if self.phase == "ready" or not self.workspace.exists():
            raise EngineError("Scan the deployment first.")

    def _copy_fixture_locked(self) -> None:
        if self.workspace.exists():
            shutil.rmtree(self.workspace)
        shutil.copytree(self.fixture, self.workspace)
        self.digest = self._digest_locked()

    def _rescan_locked(self, kind: str) -> None:
        self.drift = None
        previous_open = {finding.id for finding in self.findings if finding.status == "open"}
        previous_risk = self._risk_locked()
        try:
            current = scan(self.workspace)
        except DiscoverError as exc:
            raise EngineError(str(exc)) from exc
        self.findings = merge_findings(self.findings, current)
        risk = self._risk_locked()
        self.digest = self._digest_locked()
        paths = build_paths(self.findings)
        open_paths = [path for path in paths if path["status"] == "open"]
        open_findings = [finding for finding in self.findings if finding.status == "open"]

        if kind == "scan":
            self.phase = "discovered"
            self._event(
                "scan",
                "Discovery finished",
                f"{len(open_findings)} open findings on the {self._target()['name']} demo. Risk is {risk}.",
                risk,
            )
            self._event(
                "intel",
                "Signals joined into paths",
                f"{len(open_findings)} findings describe {len(open_paths)} attack paths.",
                risk,
            )
            return

        if kind == "remediate":
            self.phase = "verified"
            edited = len(self.applied)
            files = "file" if edited == 1 else "files"
            self._event(
                "remediate",
                "Hardening verified",
                f"Edited {edited} {files}. Open findings: {len(open_findings)}. Risk is {risk}.",
                risk,
            )
            return

        reopened = [finding for finding in open_findings if finding.id not in previous_open]
        if risk > previous_risk:
            self.phase = "regressed"
            titles = ", ".join(finding.title for finding in reopened) or "risk increased"
            path_titles = "; ".join(path["title"] for path in open_paths)
            detail = f"Reopened: {titles}."
            if path_titles:
                detail += f" Open paths: {path_titles}."
            self._event("watch", "Workspace change reopened a path", detail, risk)
        elif risk < previous_risk:
            self.phase = "verified" if risk == 0 else "discovered"
            self._event(
                "watch",
                "Workspace change reduced risk",
                f"Open findings: {len(open_findings)}. Risk is {risk}.",
                risk,
            )

    def _proposed_locked(self) -> list[dict]:
        if self.phase == "ready" or not self.workspace.exists():
            return []
        before = load_tree(self.workspace)
        return diff_trees(before, harden(before), self._target().get("summaries"))

    def _files_locked(self) -> list[dict]:
        root = self.workspace if self.workspace.exists() else self.fixture
        files = []
        for rel in MANAGED:
            path = root / rel
            if path.is_file():
                files.append({"path": rel, "bytes": path.stat().st_size})
        return files

    def _risk_locked(self) -> int:
        return risk_of(self.findings)

    def _digest_locked(self) -> str:
        if not self.workspace.exists():
            return ""
        digest = hashlib.sha256()
        for rel in MANAGED:
            path = self.workspace / rel
            digest.update(rel.encode())
            if path.is_file():
                digest.update(path.read_bytes())
        return digest.hexdigest()

    def _event(self, kind: str, title: str, detail: str, risk: int) -> None:
        self._seq += 1
        self.events.append(
            {
                "id": f"e{self._seq}",
                "at": _now(),
                "kind": kind,
                "title": title,
                "detail": detail,
                "risk": risk,
            }
        )
        if len(self.events) > 40:
            self.events = self.events[-40:]

    def _state_locked(self) -> dict:
        paths = build_paths(self.findings)
        risk = self._risk_locked()
        open_findings = [finding for finding in self.findings if finding.status == "open"]
        fixed_findings = [finding for finding in self.findings if finding.status == "fixed"]
        open_paths = [path for path in paths if path["status"] == "open"]
        return {
            "phase": self.phase,
            "watching": self.watching,
            "last_checked": self.last_checked,
            "risk": risk,
            "target": public_target(self._target()),
            "demos": demo_list(),
            "files": self._files_locked(),
            "findings": [finding.to_dict() for finding in self.findings],
            "paths": paths,
            "picture": picture(paths, self.findings, self.phase),
            "proposed": self._proposed_locked(),
            "applied": self.applied,
            "events": self.events,
            "drift": self.drift,
            "counts": {
                "open": len(open_findings),
                "fixed": len(fixed_findings),
                "paths_open": len(open_paths),
                "paths": len(paths),
            },
        }

    def _target(self) -> dict:
        spec = target_by_id(self.target_id)
        if spec is None:
            raise EngineError("That demo is not in this list.")
        return spec


def merge_findings(old: list[Finding], new: list[Finding]) -> list[Finding]:
    by_id = {finding.id: finding for finding in old}
    new_ids = set()
    for finding in new:
        by_id[finding.id] = replace(finding, status="open")
        new_ids.add(finding.id)
    for finding_id, finding in list(by_id.items()):
        if finding_id not in new_ids:
            by_id[finding_id] = replace(finding, status="fixed")
    ordered = [by_id[item_id] for item_id in ORDER if item_id in by_id]
    for finding_id, finding in by_id.items():
        if finding_id not in ORDER:
            ordered.append(finding)
    return ordered


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


engine = Engine(FIXTURE, WORKSPACE)
