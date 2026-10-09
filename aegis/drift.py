"""Compare a running checkout with the files that declare it."""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

LABELS = {
    "api": "Checkout API",
    "db": "Order database",
    "cache": "Session cache",
}

IGNORED_PACKAGES = {"pip", "setuptools", "wheel", "pkg-resources"}
SECRET = re.compile(r"(PASSWORD|TOKEN|SECRET|KEY|PASS)", re.I)
PIN = re.compile(r"""(?i)["']([A-Za-z0-9_.-]+)==([^"']+)["']""")


def baseline(root: Path) -> dict:
    compose_text = _read(root / "docker-compose.yml")
    docker_text = _read(root / "Dockerfile")
    requirements_text = _read(root / "requirements.txt")
    entry_text = _read(root / "entrypoint.sh")
    services = _parse_compose(compose_text) if compose_text is not None else {}
    image_user, image_cmd, image_entry = _parse_dockerfile(docker_text or "")
    packages = _parse_requirements(requirements_text or "")
    api = services.setdefault("api", {})
    api["packages"] = packages
    api["entrypoint_source"] = entry_text or ""
    if not api.get("user"):
        api["user"] = image_user
    if not api.get("command"):
        api["command"] = image_cmd
        if image_cmd:
            api["command_from"] = "dockerfile"
    if not api.get("entrypoint"):
        api["entrypoint"] = image_entry
    return {"services": services}


def compare(base: dict, snapshot: dict) -> dict:
    rows: list[dict] = []
    findings: list[dict] = []
    observed = snapshot.get("services") or {}

    for name, declared in base.get("services", {}).items():
        label = LABELS.get(name, name)
        live = observed.get(name) or {"status": "absent"}
        status = live.get("status") or "absent"
        if status != "running":
            rows.append(
                {
                    "service": label,
                    "field": "Container",
                    "baseline": "declared in the deploy file",
                    "observed": "not running in the sandbox",
                    "state": "unavailable",
                }
            )
            continue
        _compare_service(label, name, declared, live, rows, findings)

    findings.sort(key=lambda item: item["id"])
    status = "drift" if findings else "clean"
    narrative = _narrative(findings)
    return {
        "status": status,
        "title": narrative["headline"],
        "summary": narrative["verdict"],
        "headline": narrative["headline"],
        "verdict": narrative["verdict"],
        "why": narrative["why"],
        "sentences": narrative["sentences"],
        "sandbox": {
            "host_ports": bool((snapshot.get("sandbox") or {}).get("host_ports")),
            "privileged": bool((snapshot.get("sandbox") or {}).get("privileged")),
            "egress": bool((snapshot.get("sandbox") or {}).get("egress")),
            "removed": bool((snapshot.get("sandbox") or {}).get("removed")),
        },
        "findings": findings,
        "rows": rows,
    }


def unauthorized_installs(script: str, declared: set[str]) -> list[str]:
    if not script or not re.search(r"(?i)\bpip3?\b", script) or "install" not in script.lower():
        return []
    found = []
    for match in PIN.finditer(script):
        name = _normalize(match.group(1))
        if name and name not in declared and name not in IGNORED_PACKAGES:
            found.append(name)
    return sorted(set(found))


def sandbox_manifest(root: Path) -> dict:
    """Compose file for the audit. It never copies host ports or privileged mode."""
    base = baseline(root)
    services = {}
    for name, declared in base["services"].items():
        if name not in {"api", "db", "cache"}:
            continue
        spec: dict = {
            "privileged": False,
            "networks": ["sandbox"],
            "security_opt": ["no-new-privileges:true"],
            "pids_limit": 64,
        }
        if name == "api":
            spec["build"] = {"context": str(root.resolve()), "dockerfile": "Dockerfile"}
            spec["image"] = "aegis-audit-api:ephemeral"
            spec["cap_drop"] = ["ALL"]
            spec["mem_limit"] = "256m"
        else:
            image = declared.get("image")
            if not image:
                continue
            spec["image"] = image
            spec["pull_policy"] = "missing"
            spec["cap_drop"] = ["NET_ADMIN", "NET_RAW", "SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE"]
            spec["mem_limit"] = "512m"
        env = {key: _compose_escape(value) for key, value in (declared.get("env") or {}).items()}
        if env:
            spec["environment"] = env
        command = declared.get("command")
        if command and name != "api":
            spec["command"] = [_compose_escape(part) for part in command]
        services[name] = spec
    return {
        "networks": {"sandbox": {"internal": True, "driver": "bridge"}},
        "services": services,
    }


def _compare_service(label: str, name: str, declared: dict, live: dict, rows: list[dict], findings: list[dict]) -> None:
    declared_cmd = _command_text(declared.get("command"))
    observed_cmd = _command_text(live.get("command"))
    spoken_declared = " ".join(_normalize_command(declared.get("command")))
    spoken_observed = " ".join(_normalize_command(live.get("command")))
    if declared_cmd:
        command_drift = _normalize_command(declared.get("command")) != _normalize_command(live.get("command"))
        rows.append(
            {
                "service": label,
                "field": "Command",
                "baseline": spoken_declared or declared_cmd,
                "observed": spoken_observed or observed_cmd or "unknown",
                "state": "drift" if command_drift else "match",
            }
        )
        if command_drift:
            source = "Dockerfile" if declared.get("command_from") == "dockerfile" else "file"
            findings.append(
                {
                    "id": f"drift-command-{name}",
                    "severity": "medium",
                    "title": f"The running {label} command is not the command in the files",
                    "detail": (
                        f"The {source} command is {spoken_declared or declared_cmd}. "
                        f"The running process is {spoken_observed or observed_cmd}."
                    ),
                    "service": label,
                    "spoken_baseline": spoken_declared or declared_cmd,
                    "spoken_observed": spoken_observed or observed_cmd,
                }
            )
    elif observed_cmd:
        rows.append(
            {
                "service": label,
                "field": "Command",
                "baseline": "image default",
                "observed": observed_cmd,
                "state": "match",
            }
        )

    if name == "api":
        declared_packages = [_normalize(item) for item in declared.get("packages") or []]
        declared_set = set(declared_packages)
        installed, requires = _installed_packages(live.get("packages") or [])
        allowed = _allowed_packages(declared_set, requires)
        extras = sorted(name for name in installed if name not in allowed and name not in IGNORED_PACKAGES)
        missing = [name for name in declared_packages if name not in installed]
        shown = sorted((set(declared_packages) & installed) | set(extras))
        rows.append(
            {
                "service": label,
                "field": "Packages",
                "baseline": ", ".join(declared_packages) or "none declared",
                "observed": ", ".join(shown) or "none installed",
                "state": "drift" if extras or missing else "match",
            }
        )
        if extras:
            extra_phrase = _english_join(extras, "and")
            declared_phrase = _english_join([_pkg(item) for item in declared_packages], "and")
            declared_or = _english_join([_pkg(item) for item in declared_packages], "or")
            findings.append(
                {
                    "id": "drift-undeclared-package",
                    "severity": "high",
                    "title": "A package is installed that the manifest does not list",
                    "detail": (
                        f"entrypoint.sh installs {extra_phrase}, which requirements.txt does not list "
                        f"and which is not a dependency of {declared_or}."
                    ),
                    "service": label,
                    "extra_phrase": extra_phrase,
                    "declared_phrase": declared_phrase,
                }
            )
        if missing:
            findings.append(
                {
                    "id": "drift-missing-package",
                    "severity": "medium",
                    "title": "A declared package is missing from the running checkout API",
                    "detail": "requirements.txt lists " + ", ".join(missing) + ", and the running API does not have it installed.",
                    "service": label,
                }
            )
        script = live.get("entrypoint_source") or ""
        installs = unauthorized_installs(script, declared_set)
        if installs:
            rows.append(
                {
                    "service": label,
                    "field": "Entrypoint",
                    "baseline": "requirements.txt",
                    "observed": ", ".join(f"pip install {item}" for item in installs),
                    "state": "drift",
                }
            )
            findings.append(
                {
                    "id": "drift-entrypoint-download",
                    "severity": "high",
                    "title": "The entrypoint requests a package the manifest does not list",
                    "detail": (
                        "That script also runs pip install for "
                        + _english_join(installs, "and")
                        + ". The sandbox blocks the download."
                    ),
                    "service": label,
                }
            )

    for key, declared_value in sorted((declared.get("env") or {}).items()):
        observed_value = (live.get("env") or {}).get(key)
        secret = bool(SECRET.search(key))
        if observed_value is None:
            rows.append(
                {
                    "service": label,
                    "field": key,
                    "baseline": _show(key, declared_value),
                    "observed": "missing",
                    "state": "drift",
                }
            )
            findings.append(
                {
                    "id": f"drift-env-{name}-{_normalize(key)}",
                    "severity": "high",
                    "title": f"{key} is missing from the running {label}",
                    "detail": f"{key} is set in the files and absent from the running process.",
                    "service": label,
                }
            )
            continue
        differs = observed_value != declared_value
        rows.append(
            {
                "service": label,
                "field": key,
                "baseline": "set in the file" if secret else _show(key, declared_value),
                "observed": ("differs from the file" if differs else "matches the file") if secret else _show(key, observed_value),
                "state": "drift" if differs else "match",
            }
        )
        if differs:
            if secret:
                detail = f"{key} in the running {label} does not match the file."
            else:
                detail = f"{key} is {declared_value} in the files and {observed_value} in the running {label}."
            findings.append(
                {
                    "id": f"drift-env-{name}-{_normalize(key)}",
                    "severity": "high",
                    "title": f"{key} drifted on {label}",
                    "detail": detail,
                    "service": label,
                }
            )

    if declared.get("privileged"):
        rows.append(
            {
                "service": label,
                "field": "Privileged",
                "baseline": "requested in the deploy file",
                "observed": "not granted",
                "state": "control",
            }
        )
    if declared.get("ports"):
        rows.append(
            {
                "service": label,
                "field": "Host ports",
                "baseline": ", ".join(declared["ports"]),
                "observed": "not published",
                "state": "control",
            }
        )


def _parse_compose(text: str) -> dict:
    document = yaml.safe_load(text) or {}
    parsed = {}
    for name, spec in (document.get("services") or {}).items():
        if not isinstance(spec, dict):
            continue
        parsed[name] = {
            "image": spec.get("image"),
            "user": _as_text(spec.get("user")),
            "command": _as_args(spec.get("command")),
            "entrypoint": _as_args(spec.get("entrypoint")),
            "env": _env_map(spec.get("environment")),
            "ports": [_as_text(item) for item in (spec.get("ports") or [])],
            "privileged": bool(spec.get("privileged")),
        }
    return parsed


def _parse_dockerfile(text: str) -> tuple[str | None, list[str] | None, list[str] | None]:
    user = None
    command = None
    entry = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        key = parts[0].upper()
        rest = parts[1] if len(parts) > 1 else ""
        if key == "USER" and rest:
            user = rest.split()[0]
        elif key == "CMD":
            command = _json_or_shell(rest)
        elif key == "ENTRYPOINT":
            entry = _json_or_shell(rest)
    return user, command, entry


def _parse_requirements(text: str) -> list[str]:
    names = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        name = re.split(r"[<>=\[]", line, maxsplit=1)[0].strip()
        if name:
            names.append(_normalize(name))
    return names


def _env_map(value) -> dict[str, str]:
    if isinstance(value, dict):
        return {str(key): "" if item is None else str(item) for key, item in value.items()}
    mapped = {}
    for item in value or []:
        text = str(item)
        key, separator, rest = text.partition("=")
        if separator:
            mapped[key] = rest
    return mapped


def _json_or_shell(rest: str) -> list[str]:
    rest = rest.strip()
    if rest.startswith("["):
        try:
            parsed = json.loads(rest)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, list):
            return [str(item) for item in parsed]
    return rest.split()


def _as_args(value) -> list[str] | None:
    if value is None:
        return None
    if isinstance(value, list):
        return [str(item) for item in value]
    return str(value).split()


def _as_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True)
    return str(value)


def _command_text(value) -> str:
    if not value:
        return ""
    return " ".join(str(item) for item in value)


def _normalize_command(value) -> list[str]:
    if not value:
        return []
    parts = [str(item) for item in value if str(item)]
    if not parts:
        return []
    head = parts[0].rsplit("/", 1)[-1]
    return [head, *parts[1:]]


def _installed_packages(raw) -> tuple[set[str], dict[str, list[str]]]:
    installed: set[str] = set()
    requires: dict[str, list[str]] = {}
    for entry in raw:
        if isinstance(entry, str):
            name = _normalize(entry)
            specs: list[str] = []
        elif isinstance(entry, dict):
            name = _normalize(str(entry.get("name") or ""))
            specs = [str(item) for item in entry.get("requires") or []]
        else:
            continue
        if not name:
            continue
        installed.add(name)
        requires[name] = specs
    return installed, requires


def _allowed_packages(declared: set[str], requires: dict[str, list[str]]) -> set[str]:
    allowed = set(declared) | set(IGNORED_PACKAGES)
    changed = True
    while changed:
        changed = False
        for name in list(allowed):
            for spec in requires.get(name, []):
                dependency = _requirement_name(spec)
                if dependency and dependency not in allowed:
                    allowed.add(dependency)
                    changed = True
    return allowed


def _requirement_name(spec: str) -> str:
    body = spec.split(";", 1)[0].strip()
    name = re.split(r"[<>=!\s\[]", body, maxsplit=1)[0].strip()
    return _normalize(name)


STORY_ORDER = (
    "drift-undeclared-package",
    "drift-entrypoint-download",
    "drift-command-api",
)


def _narrative(findings: list[dict]) -> dict:
    by_id = {item["id"]: item for item in findings}
    sentences = _ordered_sentences(findings)
    command = by_id.get("drift-command-api")
    package = by_id.get("drift-undeclared-package")
    download = by_id.get("drift-entrypoint-download")
    if not findings:
        headline = "The running checkout matches the files."
        verdict = "The process, the packages, and the settings in the sandbox were the ones the files declared."
        why = "Nothing in the snapshot disagreed with the files."
    elif command and package and download:
        headline = "The container did not run what the files describe."
        verdict = (
            f"The files say the checkout API runs {command['spoken_baseline']} "
            f"and installs only {package['declared_phrase']}. "
            f"The container ran {command['spoken_observed']} instead, and entrypoint.sh tried to add "
            f"{package['extra_phrase']}, a package the manifest never listed."
        )
        why = (
            "What you review in the files is not what the container ran. "
            "The startup script can swap the program and add a package after the image is built."
        )
    else:
        count = len(findings)
        noun = "difference" if count == 1 else "differences"
        headline = f"The sandbox found {count} {noun}."
        verdict = sentences[0] if sentences else headline
        why = "The running process disagreed with the files that declare this deploy."
    return {"headline": headline, "verdict": verdict, "why": why, "sentences": sentences}


def _ordered_sentences(findings: list[dict]) -> list[str]:
    by_id = {item["id"]: item["detail"] for item in findings}
    if all(key in by_id for key in STORY_ORDER):
        ordered = [by_id[key] for key in STORY_ORDER]
        rest = [item["detail"] for item in findings if item["id"] not in STORY_ORDER]
        return ordered + rest
    return [item["detail"] for item in findings]


def _english_join(items: list[str], conj: str) -> str:
    if not items:
        return "the packages in requirements.txt"
    if len(items) == 1:
        return items[0]
    if len(items) == 2:
        return f"{items[0]} {conj} {items[1]}"
    return ", ".join(items[:-1]) + f", {conj} {items[-1]}"


def _pkg(name: str) -> str:
    if name == "flask":
        return "Flask"
    return name


def _normalize(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def _show(key: str, value: str) -> str:
    if SECRET.search(key):
        return "set" if value else "empty"
    return value


def _compose_escape(value: str) -> str:
    return value.replace("$", "$$")


def _read(path: Path) -> str | None:
    if not path.is_file():
        return None
    return path.read_text()
