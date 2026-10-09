"""Start the checkout in a short-lived sandbox and snapshot it."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

import yaml

from aegis.drift import baseline, compare, sandbox_manifest

API_PACKAGES = """
import importlib.metadata, json
rows = []
for dist in importlib.metadata.distributions():
    name = dist.metadata["Name"]
    if not name:
        continue
    rows.append({"name": name, "requires": dist.metadata.get_all("Requires-Dist") or []})
print(json.dumps(rows))
""".strip()

READ_ENTRY = "print(open('/app/entrypoint.sh', encoding='utf-8').read())"
READ_CMDLINE = "print(open('/proc/1/cmdline', 'rb').read().replace(bytes([0]), b'\\n').decode())"


class SandboxError(Exception):
    pass


def run_audit(root: Path) -> dict:
    if shutil.which("docker") is None:
        raise SandboxError("Docker is not available, so the sandbox cannot start.")
    manifest = sandbox_manifest(root)
    _assert_manifest(manifest)
    base = baseline(root)
    project = "aegis" + uuid.uuid4().hex[:8]
    image = f"aegis-audit-api:{project}"
    manifest["services"]["api"]["image"] = image
    with tempfile.TemporaryDirectory(prefix="aegis-audit-") as tmp:
        compose_path = Path(tmp) / "compose.yml"
        compose_path.write_text(yaml.safe_dump(manifest, sort_keys=False))
        snapshot = {
            "sandbox": {"host_ports": False, "privileged": False, "egress": False, "removed": False},
            "services": {},
        }
        try:
            _compose(project, compose_path, ["up", "-d", "--build", "--remove-orphans", "api"], timeout=240)
            api_id = _container_id(project, compose_path, "api")
            _wait_attached(api_id)
            _assert_isolated(api_id, drop_all=True)
            _wait_ready(api_id, timeout=30)
            snapshot["services"]["api"] = _capture(api_id, packages=True, entrypoint=True)
            _start_data_stores(project, compose_path, snapshot)
        finally:
            removed = _teardown(project, compose_path, image)
        if not removed:
            raise SandboxError("The sandbox containers could not be removed.")
        snapshot["sandbox"]["removed"] = True
    return compare(base, snapshot)


def _assert_manifest(manifest: dict) -> None:
    network = (manifest.get("networks") or {}).get("sandbox") or {}
    if not network.get("internal"):
        raise SandboxError("The sandbox network must be internal.")
    for name, spec in (manifest.get("services") or {}).items():
        if spec.get("privileged"):
            raise SandboxError(f"The sandbox refused to start {name} in privileged mode.")
        if spec.get("ports"):
            raise SandboxError(f"The sandbox refused to publish a host port for {name}.")
        if spec.get("volumes") or spec.get("network_mode") == "host" or spec.get("pid") == "host":
            raise SandboxError(f"The sandbox refused an unsafe mount for {name}.")


def _start_data_stores(project: str, compose_path: Path, snapshot: dict) -> None:
    try:
        _compose(project, compose_path, ["up", "-d", "--remove-orphans", "db", "cache"], timeout=90)
    except SandboxError:
        for name in ("db", "cache"):
            snapshot["services"].setdefault(name, {"status": "unavailable"})
        return
    for name in ("db", "cache"):
        try:
            container_id = _container_id(project, compose_path, name)
            _wait_attached(container_id)
            _assert_isolated(container_id, drop_all=False)
            if not _running(container_id):
                snapshot["services"][name] = {"status": "exited"}
                continue
            snapshot["services"][name] = _capture(container_id, packages=False, entrypoint=False)
        except SandboxError:
            snapshot["services"][name] = {"status": "unavailable"}


def _capture(container_id: str, packages: bool, entrypoint: bool) -> dict:
    inspected = _inspect(container_id)
    config = inspected.get("Config") or {}
    host = inspected.get("HostConfig") or {}
    if host.get("Privileged") or host.get("PortBindings"):
        raise SandboxError("The sandbox refused a container that was privileged or published a port.")
    env = {}
    for item in config.get("Env") or []:
        key, separator, value = str(item).partition("=")
        if separator:
            env[key] = value
    record = {
        "status": "running",
        "user": config.get("User") or "",
        "command": _cmdline(container_id),
        "env": env,
        "privileged": bool(host.get("Privileged")),
        "packages": _python(container_id, API_PACKAGES) if packages else [],
        "entrypoint_source": _python_text(container_id, READ_ENTRY) if entrypoint else "",
    }
    if not isinstance(record["packages"], list):
        record["packages"] = []
    return record


def _assert_isolated(container_id: str, drop_all: bool) -> None:
    inspected = _inspect(container_id)
    host = inspected.get("HostConfig") or {}
    if host.get("Privileged"):
        raise SandboxError("Sandbox refused to continue: the container was privileged.")
    if host.get("PortBindings"):
        raise SandboxError("Sandbox refused to continue: a host port was published.")
    published = (inspected.get("NetworkSettings") or {}).get("Ports") or {}
    if any(published.values()):
        raise SandboxError("Sandbox refused to continue: a host port was published.")
    options = host.get("SecurityOpt") or []
    if not any("no-new-privileges" in item for item in options):
        raise SandboxError("Sandbox refused to continue: new privileges were not blocked.")
    if drop_all and "ALL" not in (host.get("CapDrop") or []):
        raise SandboxError("Sandbox refused to continue: the API kept capabilities.")
    networks = (inspected.get("NetworkSettings") or {}).get("Networks") or {}
    if not networks:
        raise SandboxError("Sandbox refused to continue: the container has no sandbox network.")
    for attachment in networks.values():
        network = _json(["docker", "network", "inspect", attachment.get("NetworkID", "")])
        if not network or not network[0].get("Internal"):
            raise SandboxError("Sandbox refused to continue: the network allows egress.")


def _wait_attached(container_id: str, timeout: int = 20) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        inspected = _inspect(container_id)
        networks = (inspected.get("NetworkSettings") or {}).get("Networks") or {}
        status = (inspected.get("State") or {}).get("Status")
        if networks and status in {"running", "exited"}:
            return
        time.sleep(0.3)


def _wait_ready(container_id: str, timeout: int) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not _running(container_id):
            time.sleep(0.4)
            continue
        parts = _cmdline(container_id)
        head = parts[0].rsplit("/", 1)[-1] if parts else ""
        if head.startswith("python") and ("http.server" in parts or "server.py" in parts):
            return
        time.sleep(0.4)
    if _running(container_id):
        return
    raise SandboxError("The checkout API stopped before the snapshot.")


def _cmdline(container_id: str) -> list[str]:
    text = _python_text(container_id, READ_CMDLINE)
    if text is None:
        return []
    return [part for part in text.split("\n") if part]


def _python(container_id: str, code: str):
    completed = _run(["docker", "exec", "-i", container_id, "python", "-"], timeout=20, input_text=code + "\n")
    if completed.returncode != 0:
        return []
    try:
        parsed = json.loads(completed.stdout.strip() or "[]")
    except json.JSONDecodeError:
        return []
    return parsed if isinstance(parsed, list) else []


def _python_text(container_id: str, code: str) -> str | None:
    completed = _run(["docker", "exec", "-i", container_id, "python", "-"], timeout=15, input_text=code + "\n")
    if completed.returncode != 0:
        return None
    return completed.stdout


def _running(container_id: str) -> bool:
    inspected = _inspect(container_id)
    return bool((inspected.get("State") or {}).get("Running"))


def _inspect(container_id: str) -> dict:
    payload = _json(["docker", "inspect", container_id])
    if not payload:
        raise SandboxError("The sandbox container disappeared before the snapshot.")
    return payload[0]


def _container_id(project: str, compose_path: Path, service: str) -> str:
    completed = _compose(project, compose_path, ["ps", "-aq", service], timeout=20)
    container_ids = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
    if not container_ids:
        raise SandboxError(f"The sandbox did not create the {service} container.")
    return container_ids[0]


def _compose(project: str, compose_path: Path, args: list[str], timeout: int) -> subprocess.CompletedProcess:
    completed = _run(["docker", "compose", "-p", project, "-f", str(compose_path), *args], timeout=timeout)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip().splitlines()
        tail = detail[-1] if detail else "Docker compose failed."
        raise SandboxError(tail[:300])
    return completed


def _teardown(project: str, compose_path: Path, image: str) -> bool:
    down = _run(
        ["docker", "compose", "-p", project, "-f", str(compose_path), "down", "-v", "--remove-orphans", "--timeout", "5"],
        timeout=40,
    )
    _run(["docker", "rmi", "-f", image], timeout=30)
    return down.returncode == 0


def _json(args: list[str]):
    completed = _run(args, timeout=20)
    if completed.returncode != 0:
        return []
    try:
        return json.loads(completed.stdout or "[]")
    except json.JSONDecodeError:
        return []


def _run(args: list[str], timeout: int, input_text: str | None = None) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["COMPOSE_ANSI"] = "never"
    env["DOCKER_CLI_HINTS"] = "false"
    try:
        return subprocess.run(
            args,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        raise SandboxError("The sandbox did not finish in time and was stopped.") from exc
    except OSError as exc:
        raise SandboxError("Docker could not be started.") from exc
