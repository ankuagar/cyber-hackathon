from __future__ import annotations

import difflib
from pathlib import Path

MANAGED = [
    "docker-compose.yml",
    "Dockerfile",
    "requirements.txt",
    "config/settings.env",
]

SUMMARIES = {
    "docker-compose.yml": "Drop published data-store ports, remove privileged mode, pin the image, and take literals out of the deploy file.",
    "Dockerfile": "Run the image as an unprivileged user.",
    "requirements.txt": "Upgrade Flask to 2.3.2 and requests to 2.31.0.",
    "config/settings.env": "Turn debug off, allowlist the checkout origin, and stop storing the admin token here.",
}


def load_tree(root: Path) -> dict[str, str]:
    files = {}
    for rel in MANAGED:
        path = root / rel
        if path.is_file():
            files[rel] = path.read_text()
    return files


def write_tree(root: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


def harden(files: dict[str, str]) -> dict[str, str]:
    updated = dict(files)
    if "docker-compose.yml" in updated:
        updated["docker-compose.yml"] = harden_compose(updated["docker-compose.yml"])
    if "Dockerfile" in updated:
        updated["Dockerfile"] = harden_dockerfile(updated["Dockerfile"])
    if "requirements.txt" in updated:
        updated["requirements.txt"] = harden_requirements(updated["requirements.txt"])
    if "config/settings.env" in updated:
        updated["config/settings.env"] = harden_dotenv(updated["config/settings.env"])
    return updated


def diff_trees(
    before: dict[str, str],
    after: dict[str, str],
    summaries: dict[str, str] | None = None,
) -> list[dict]:
    labels = summaries or SUMMARIES
    diffs = []
    for rel in MANAGED:
        old = before.get(rel, "")
        new = after.get(rel, "")
        if old == new:
            continue
        lines = difflib.unified_diff(
            old.splitlines(),
            new.splitlines(),
            fromfile=f"a/{rel}",
            tofile=f"b/{rel}",
            lineterm="",
        )
        diffs.append({"path": rel, "summary": labels.get(rel, ""), "diff": "\n".join(lines)})
    return diffs


def harden_compose(text: str) -> str:
    text = remove_privileged(text, "api")
    text = set_user_if_root(text, "api")
    text = pin_latest_image(text, "api", "northwind/checkout-api:1.4.2")
    text = set_env(text, "api", "DEBUG", '"false"')
    text = set_env(text, "api", "ADMIN_TOKEN", '"${ADMIN_TOKEN:?set ADMIN_TOKEN}"')
    text = set_env(text, "api", "CORS_ORIGINS", '"https://checkout.northwind.example"')
    text = remove_key(text, "db", "ports")
    text = set_env(text, "db", "POSTGRES_PASSWORD", '"${POSTGRES_PASSWORD:?set POSTGRES_PASSWORD}"')
    text = remove_key(text, "cache", "ports")
    text = set_service_scalar(
        text,
        "cache",
        "command",
        '["redis-server", "--requirepass", "${REDIS_PASSWORD:?set REDIS_PASSWORD}"]',
    )
    text = drop_network_mode(text, "worker", "host")
    text = remove_matching_volumes(text, "worker", _is_risky_mount)
    text = set_env(text, "worker", "CLOUD_API_KEY", '"${CLOUD_API_KEY:?set CLOUD_API_KEY}"')
    text = set_env(text, "objects", "MINIO_ROOT_PASSWORD", '"${MINIO_ROOT_PASSWORD:?set MINIO_ROOT_PASSWORD}"')
    text = remove_key(text, "admin", "ports")
    return text


def inject_regression(text: str) -> str:
    """Reopen one path: the database on Northwind, or the admin page on Harbor."""
    lines = text.splitlines()
    if service_span(lines, "db") is not None:
        return _inject_database(text)
    if service_span(lines, "admin") is not None:
        return _inject_admin_page(text)
    return text


def _inject_database(text: str) -> str:
    """Reopen the database path: publish Postgres and put the default password back."""
    text = set_env(text, "db", "POSTGRES_PASSWORD", "postgres")
    lines = text.splitlines()
    span = service_span(lines, "db")
    if span is None:
        return text
    start, end = span
    has_ports = any(key_at(lines[index], "ports", 4) for index in range(start + 1, end))
    if has_ports:
        return _join(text, lines) if text != _join(text, lines) else text
    insert_at = start + 1
    for index in range(start + 1, end):
        if key_at(lines[index], "image", 4):
            insert_at = index + 1
            break
    lines.insert(insert_at, "    ports:")
    lines.insert(insert_at + 1, '      - "5432:5432"')
    return _join(text, lines)


def _inject_admin_page(text: str) -> str:
    """Reopen the object-store path: publish the admin page and put the default password back."""
    text = set_env(text, "objects", "MINIO_ROOT_PASSWORD", "minioadmin")
    lines = text.splitlines()
    span = service_span(lines, "admin")
    if span is None:
        return text
    start, end = span
    has_ports = any(key_at(lines[index], "ports", 4) for index in range(start + 1, end))
    if has_ports:
        return _join(text, lines) if text != _join(text, lines) else text
    insert_at = start + 1
    for index in range(start + 1, end):
        if key_at(lines[index], "image", 4):
            insert_at = index + 1
            break
    lines.insert(insert_at, "    ports:")
    lines.insert(insert_at + 1, '      - "9001:9001"')
    return _join(text, lines)


def harden_dockerfile(text: str) -> str:
    lines = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "USER" and parts[1] in {"root", "0", "0:0"}:
            lines.append("USER 65534")
            continue
        if _world_writable_target(line) is not None:
            continue
        lines.append(line)
    return _join(text, lines)


def _world_writable_target(line: str) -> str | None:
    code = line.split("#", 1)[0]
    for chunk in code.replace("&&", "\n").replace(";", "\n").splitlines():
        parts = chunk.split()
        if parts and parts[0] == "RUN":
            parts = parts[1:]
        if not parts or parts[0] != "chmod":
            continue
        args = parts[1:]
        while args and args[0].startswith("-"):
            args = args[1:]
        if len(args) >= 2 and args[0] in {"777", "0777"}:
            return args[1]
    return None


def harden_requirements(text: str) -> str:
    pins = {"flask": "2.3.2", "requests": "2.31.0", "pyyaml": "5.4"}
    lines = text.splitlines()
    for index, line in enumerate(lines):
        raw = line.strip()
        if not raw or raw.startswith("#") or "==" not in raw:
            continue
        name = raw.split("==", 1)[0].strip().split("[")[0].lower()
        if name in pins:
            lines[index] = f"{name}=={pins[name]}"
    return _join(text, lines)


def harden_dotenv(text: str) -> str:
    replacements = {
        "DEBUG": "false",
        "ADMIN_TOKEN": '"${ADMIN_TOKEN:?set ADMIN_TOKEN}"',
        "CORS_ORIGINS": "https://checkout.northwind.example",
        "CLOUD_API_KEY": '"${CLOUD_API_KEY:?set CLOUD_API_KEY}"',
    }
    lines = text.splitlines()
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key = stripped.split("=", 1)[0].strip()
        if key in replacements:
            lines[index] = f"{key}={replacements[key]}"
    return _join(text, lines)


def drop_network_mode(text: str, service: str, mode: str) -> str:
    lines = text.splitlines()
    span = service_span(lines, service)
    if span is None:
        return text
    start, end = span
    for index in range(start + 1, end):
        if not key_at(lines[index], "network_mode", 4):
            continue
        value = lines[index].split(":", 1)[1].strip().strip('"').strip("'")
        if value == mode:
            del lines[index]
            return _join(text, lines)
    return text


def remove_matching_volumes(text: str, service: str, predicate) -> str:
    lines = text.splitlines()
    span = service_span(lines, service)
    if span is None:
        return text
    start, end = span
    key_index = None
    for index in range(start + 1, end):
        if key_at(lines[index], "volumes", 4):
            key_index = index
            break
    if key_index is None:
        return text
    block_end = key_index + 1
    while block_end < len(lines):
        line = lines[block_end]
        if line.strip() == "":
            block_end += 1
            continue
        if _indent(line) <= 4:
            break
        block_end += 1
    while block_end > key_index + 1 and lines[block_end - 1].strip() == "":
        block_end -= 1
    kept = []
    for line in lines[key_index + 1 : block_end]:
        if line.strip() and predicate(line.strip()):
            continue
        kept.append(line)
    while kept and kept[-1].strip() == "":
        kept.pop()
    if not any(item.strip() for item in kept):
        del lines[key_index:block_end]
    else:
        lines[key_index + 1 : block_end] = kept
    return _join(text, lines)


def _is_risky_mount(stripped: str) -> bool:
    body = stripped[1:].strip() if stripped.startswith("-") else stripped
    body = body.strip().strip('"').strip("'")
    if "docker.sock" in body:
        return True
    source = body.split(":", 1)[0]
    read_only = body.endswith(":ro") or "ro" in body.split(":")[2:]
    return source == "/etc" and not read_only


def remove_privileged(text: str, service: str) -> str:
    lines = text.splitlines()
    span = service_span(lines, service)
    if span is None:
        return text
    start, end = span
    for index in range(start + 1, end):
        if not key_at(lines[index], "privileged", 4):
            continue
        value = lines[index].split(":", 1)[1].strip().lower()
        if value == "true":
            del lines[index]
            return _join(text, lines)
    return text


def set_user_if_root(text: str, service: str) -> str:
    lines = text.splitlines()
    span = service_span(lines, service)
    if span is None:
        return text
    start, end = span
    for index in range(start + 1, end):
        if not key_at(lines[index], "user", 4):
            continue
        value = lines[index].split(":", 1)[1].strip().strip('"').strip("'")
        if value in {"root", "0", "0:0"}:
            lines[index] = '    user: "65534:65534"'
            return _join(text, lines)
    return text


def pin_latest_image(text: str, service: str, pinned: str) -> str:
    lines = text.splitlines()
    span = service_span(lines, service)
    if span is None:
        return text
    start, end = span
    for index in range(start + 1, end):
        if key_at(lines[index], "image", 4) and lines[index].rstrip().endswith(":latest"):
            lines[index] = f"    image: {pinned}"
            return _join(text, lines)
    return text


def set_env(text: str, service: str, key: str, value_src: str) -> str:
    lines = text.splitlines()
    span = service_span(lines, service)
    if span is None:
        return text
    start, end = span
    desired = f"      {key}: {value_src}"
    for index in range(start + 1, end):
        if key_at(lines[index], key, 6):
            lines[index] = desired
            return _join(text, lines)
    return text


def remove_key(text: str, service: str, key: str) -> str:
    lines = text.splitlines()
    span = service_span(lines, service)
    if span is None:
        return text
    start, end = span
    target = None
    for index in range(start + 1, end):
        if key_at(lines[index], key, 4):
            target = index
            break
    if target is None:
        return text
    cursor = target + 1
    while cursor < len(lines):
        line = lines[cursor]
        if line.strip() == "":
            cursor += 1
            continue
        if _indent(line) <= 4:
            break
        cursor += 1
    while cursor > target + 1 and lines[cursor - 1].strip() == "":
        cursor -= 1
    del lines[target:cursor]
    return _join(text, lines)


def set_service_scalar(text: str, service: str, key: str, value_src: str) -> str:
    lines = text.splitlines()
    span = service_span(lines, service)
    if span is None:
        return text
    start, end = span
    desired = f"    {key}: {value_src}"
    for index in range(start + 1, end):
        if not key_at(lines[index], key, 4):
            continue
        lines[index] = desired
        cursor = index + 1
        while cursor < len(lines) and lines[cursor].strip() and _indent(lines[cursor]) > 4:
            del lines[cursor]
        return _join(text, lines)
    insert_at = start + 1
    for index in range(start + 1, end):
        if key_at(lines[index], "image", 4):
            insert_at = index + 1
            break
    lines.insert(insert_at, desired)
    return _join(text, lines)


def service_span(lines: list[str], service: str) -> tuple[int, int] | None:
    header = f"  {service}:"
    start = None
    for index, line in enumerate(lines):
        if line.split("#", 1)[0].rstrip() == header:
            start = index
            break
    if start is None:
        return None
    end = len(lines)
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" ") or (_indent(line) == 2 and not line.startswith("   ")):
            end = index
            break
    return start, end


def key_at(line: str, key: str, indent: int) -> bool:
    if _indent(line) != indent:
        return False
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or ":" not in stripped:
        return False
    name = stripped.split(":", 1)[0].strip()
    return name == key


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _join(original: str, lines: list[str]) -> str:
    body = "\n".join(lines)
    if original.endswith("\n"):
        body += "\n"
    return body
