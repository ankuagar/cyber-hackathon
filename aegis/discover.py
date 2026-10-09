from __future__ import annotations

from pathlib import Path

import yaml

from aegis.models import Finding, Location

ORDER = [
    "db-published",
    "db-default-password",
    "redis-published",
    "redis-no-auth",
    "admin-token-hardcoded",
    "privileged-container",
    "runs-as-root",
    "debug-enabled",
    "cors-wildcard",
    "floating-image-tag",
    "dep-flask",
    "dep-requests",
    "socket-mounted",
    "host-network",
    "writable-host-etc",
    "archive-world-writable",
    "object-default-password",
    "admin-published",
    "cloud-key-committed",
    "dep-pyyaml",
]

WEIGHTS = {"critical": 16, "high": 9, "medium": 4, "low": 2}

WEAK_PASSWORDS = {
    "postgres",
    "password",
    "admin",
    "admin123",
    "root",
    "changeme",
    "secret",
    "redis",
}


class DiscoverError(Exception):
    pass


def risk_of(findings: list[Finding]) -> int:
    return sum(WEIGHTS.get(f.severity, 0) for f in findings if f.status == "open")


def scan(root: Path) -> list[Finding]:
    found: dict[str, Finding] = {}
    compose_text = _read(root, "docker-compose.yml")
    docker_text = _read(root, "Dockerfile")
    req_text = _read(root, "requirements.txt")
    settings_text = _read(root, "config/settings.env")

    compose_env: dict[str, str] = {}
    services: dict = {}
    if compose_text is not None:
        try:
            doc = yaml.safe_load(compose_text) or {}
        except yaml.YAMLError as exc:
            raise DiscoverError(f"docker-compose.yml could not be parsed: {exc}") from exc
        services = doc.get("services") or {}
        api = services.get("api") or {}
        compose_env = _env_map(api)
        _compose_findings(found, services, compose_text, compose_env)
        _harbor_findings(found, services, compose_text)

    if docker_text is not None:
        root_line = _dockerfile_root_line(docker_text)
        if root_line is not None:
            _add_root(found, Location("Dockerfile", root_line))
        if "worker" in services:
            writable = _dockerfile_world_writable(docker_text)
            if writable is not None:
                line, target = writable
                found["archive-world-writable"] = Finding(
                    id="archive-world-writable",
                    severity="medium",
                    title="Archive directory is world-writable",
                    detail=(
                        f"The image sets {target} to mode 777, so any account in the container "
                        "can change the customer files stored there."
                    ),
                    asset="archive-worker",
                    recommendation=(
                        "Remove the world-writable mode and keep the archive directory "
                        "writable only by the worker user."
                    ),
                    locations=(Location("Dockerfile", line),),
                )

    if settings_text is not None:
        settings = _parse_env_file(settings_text)
        _settings_findings(found, settings)

    if req_text is not None:
        _dependency_findings(found, req_text)

    return [found[item_id] for item_id in ORDER if item_id in found]


def _compose_findings(found: dict[str, Finding], services: dict, text: str, api_env: dict[str, str]) -> None:
    api = services.get("api") or {}
    db = services.get("db") or {}
    cache = services.get("cache") or {}

    if _published(db) and _image_name(str(db.get("image") or "")) == "postgres":
        line = _line_of(text, "5432:5432") or 1
        found["db-published"] = Finding(
            id="db-published",
            severity="critical",
            title="Postgres is published on the host",
            detail="The database port is mapped in the deploy file, so Postgres is reachable beyond the application network.",
            asset="checkout-db",
            recommendation="Remove the host port mapping and keep Postgres on the internal network.",
            locations=(Location("docker-compose.yml", line),),
        )

    db_env = _env_map(db)
    password = db_env.get("POSTGRES_PASSWORD", "")
    user = db_env.get("POSTGRES_USER", "postgres")
    if password and not _is_secret_ref(password) and (
        password.lower() in WEAK_PASSWORDS or password.lower() == user.lower()
    ):
        line = _line_of(text, "POSTGRES_PASSWORD") or 1
        found["db-default-password"] = Finding(
            id="db-default-password",
            severity="critical",
            title="Postgres uses a default password",
            detail=f"POSTGRES_PASSWORD is set to the default value {password}, and that value is committed in the deploy file.",
            asset="checkout-db",
            recommendation="Read the database password from the runtime environment and rotate the current one.",
            locations=(Location("docker-compose.yml", line),),
        )

    if _published(cache) and _image_name(str(cache.get("image") or "")) == "redis":
        line = _line_of(text, "6379:6379") or 1
        found["redis-published"] = Finding(
            id="redis-published",
            severity="high",
            title="Redis is published on the host",
            detail="The cache port is mapped in the deploy file, so Redis is reachable beyond the application network.",
            asset="checkout-cache",
            recommendation="Remove the host port mapping and keep Redis on the internal network.",
            locations=(Location("docker-compose.yml", line),),
        )

    if _image_name(str(cache.get("image") or "")) == "redis" and not _redis_requires_auth(cache):
        line = _line_of(text, "image: redis") or 1
        found["redis-no-auth"] = Finding(
            id="redis-no-auth",
            severity="medium",
            title="Redis does not require a password",
            detail="The Redis process is started without requirepass, so any client that can reach it can read the cache.",
            asset="checkout-cache",
            recommendation="Start Redis with a password supplied from the runtime environment.",
            locations=(Location("docker-compose.yml", line),),
        )

    token = api_env.get("ADMIN_TOKEN", "")
    if token and not _is_secret_ref(token):
        line = _line_of(text, "ADMIN_TOKEN") or 1
        found["admin-token-hardcoded"] = _admin_finding((Location("docker-compose.yml", line),), token)

    if api.get("privileged") is True:
        line = _line_of(text, "privileged:") or 1
        found["privileged-container"] = Finding(
            id="privileged-container",
            severity="high",
            title="API container is privileged",
            detail="privileged mode drops the usual isolation boundary around the checkout API.",
            asset="checkout-api",
            recommendation="Remove privileged mode from the API service.",
            locations=(Location("docker-compose.yml", line),),
        )

    user_value = str(api.get("user") or "")
    if user_value.strip().strip('"').strip("'") in {"root", "0", "0:0"}:
        line = _line_of(text, "user:") or 1
        _add_root(found, Location("docker-compose.yml", line))

    if _is_true(api_env.get("DEBUG", "")):
        line = _line_of(text, "DEBUG") or 1
        found["debug-enabled"] = _debug_finding((Location("docker-compose.yml", line),))

    if _is_wildcard(api_env.get("CORS_ORIGINS", "")):
        line = _line_of(text, "CORS_ORIGINS") or 1
        found["cors-wildcard"] = _cors_finding((Location("docker-compose.yml", line),))

    image = str(api.get("image") or "")
    if image.rsplit(":", 1)[-1] == "latest":
        line = _line_of(text, "image: northwind/checkout-api") or _line_of(text, ":latest") or 1
        found["floating-image-tag"] = Finding(
            id="floating-image-tag",
            severity="medium",
            title="API image uses the latest tag",
            detail="northwind/checkout-api is set to latest, so a later push can change what this deploy runs without a change in git.",
            asset="checkout-api",
            recommendation="Pin the checkout image to a specific tag.",
            locations=(Location("docker-compose.yml", line),),
        )


def _settings_findings(found: dict[str, Finding], settings: dict[str, tuple[str, int]]) -> None:
    token_row = settings.get("ADMIN_TOKEN")
    if token_row and not _is_secret_ref(token_row[0]):
        extra = Location("config/settings.env", token_row[1])
        existing = found.get("admin-token-hardcoded")
        locations = (existing.locations if existing else ()) + (extra,)
        sample = token_row[0]
        found["admin-token-hardcoded"] = _admin_finding(locations, sample)

    debug_row = settings.get("DEBUG")
    if debug_row and _is_true(debug_row[0]):
        extra = Location("config/settings.env", debug_row[1])
        existing = found.get("debug-enabled")
        locations = (existing.locations if existing else ()) + (extra,)
        found["debug-enabled"] = _debug_finding(locations)

    cors_row = settings.get("CORS_ORIGINS")
    if cors_row and _is_wildcard(cors_row[0]):
        extra = Location("config/settings.env", cors_row[1])
        existing = found.get("cors-wildcard")
        locations = (existing.locations if existing else ()) + (extra,)
        found["cors-wildcard"] = _cors_finding(locations)

    cloud_row = settings.get("CLOUD_API_KEY")
    if cloud_row and not _is_secret_ref(cloud_row[0]):
        extra = Location("config/settings.env", cloud_row[1])
        existing = found.get("cloud-key-committed")
        locations = (existing.locations if existing else ()) + (extra,)
        found["cloud-key-committed"] = _cloud_finding(locations, cloud_row[0])


def _dependency_findings(found: dict[str, Finding], text: str) -> None:
    for name, version, line in _parse_requirements(text):
        if name == "flask" and _flask_affected(version):
            found["dep-flask"] = Finding(
                id="dep-flask",
                severity="high",
                title=f"Flask {version} is missing a published fix",
                detail=(
                    "CVE-2023-30861 affects Flask before 2.2.5 and Flask 2.3 before 2.3.2. "
                    "Impact: a shared cache can disclose a permanent session cookie to the wrong client. "
                    "Fixed in 2.3.2."
                ),
                asset="Python dependencies",
                recommendation="Upgrade Flask to 2.3.2 or later.",
                locations=(Location("requirements.txt", line),),
            )
        if name == "requests" and _requests_affected(version):
            found["dep-requests"] = Finding(
                id="dep-requests",
                severity="medium",
                title=f"requests {version} is missing a published fix",
                detail=(
                    "CVE-2023-32681 affects requests 2.3.0 through 2.30.0. "
                    "Impact: proxy credentials embedded in a proxy URL can be forwarded to the destination on an HTTPS redirect. "
                    "Fixed in 2.31.0."
                ),
                asset="Python dependencies",
                recommendation="Upgrade requests to 2.31.0 or later.",
                locations=(Location("requirements.txt", line),),
            )
        if name == "pyyaml" and _pyyaml_affected(version):
            found["dep-pyyaml"] = Finding(
                id="dep-pyyaml",
                severity="high",
                title=f"PyYAML {version} is missing a published fix",
                detail=(
                    "CVE-2020-14343 affects PyYAML before 5.4. "
                    "Impact: a YAML document from an untrusted source can cause the loader to run code. "
                    "Fixed in 5.4."
                ),
                asset="Python dependencies",
                recommendation="Upgrade PyYAML to 5.4 or later.",
                locations=(Location("requirements.txt", line),),
            )


def _harbor_findings(found: dict[str, Finding], services: dict, text: str) -> None:
    worker = services.get("worker") or {}
    objects = services.get("objects") or {}
    admin = services.get("admin") or {}
    volumes = _volume_lines(worker)

    if any("docker.sock" in item for item in volumes):
        line = _line_of(text, "docker.sock") or 1
        found["socket-mounted"] = Finding(
            id="socket-mounted",
            severity="critical",
            title="Archive worker mounts the Docker socket",
            detail="The worker mounts /var/run/docker.sock, so it can talk to the Docker daemon on the host.",
            asset="archive-worker",
            recommendation="Remove the Docker socket mount from the worker.",
            locations=(Location("docker-compose.yml", line),),
        )

    mode = str(worker.get("network_mode") or "").strip().strip('"').strip("'")
    if mode == "host":
        line = _line_of(text, "network_mode:") or 1
        found["host-network"] = Finding(
            id="host-network",
            severity="high",
            title="Archive worker uses the host network",
            detail="network_mode is host, so the worker shares the machine's network instead of an isolated one.",
            asset="archive-worker",
            recommendation="Put the worker on the application network.",
            locations=(Location("docker-compose.yml", line),),
        )

    if any(_is_writable_host_etc(item) for item in volumes):
        line = _line_of(text, "/etc:/host-etc") or _line_of(text, "/etc:") or 1
        found["writable-host-etc"] = Finding(
            id="writable-host-etc",
            severity="high",
            title="Host system directory is mounted writable",
            detail=(
                "The host /etc directory is mounted into the worker without a read-only flag, "
                "so the container can change host configuration files."
            ),
            asset="archive-worker",
            recommendation="Remove the /etc mount from the worker.",
            locations=(Location("docker-compose.yml", line),),
        )

    if _image_name(str(objects.get("image") or "")) == "minio":
        object_env = _env_map(objects)
        password = object_env.get("MINIO_ROOT_PASSWORD", "")
        user = object_env.get("MINIO_ROOT_USER", "minioadmin")
        if password and not _is_secret_ref(password) and (
            password.lower() in (WEAK_PASSWORDS | {"minioadmin"}) or password.lower() == user.lower()
        ):
            line = _line_of(text, "MINIO_ROOT_PASSWORD") or 1
            found["object-default-password"] = Finding(
                id="object-default-password",
                severity="critical",
                title="Object store uses a default password",
                detail=(
                    f"MINIO_ROOT_PASSWORD is set to the default value {password}, "
                    "and that value is committed in the deploy file."
                ),
                asset="object-store",
                recommendation="Read the object store password from the runtime environment and rotate the current one.",
                locations=(Location("docker-compose.yml", line),),
            )

    if _published(admin):
        line = _line_of(text, "9001:9001") or 1
        found["admin-published"] = Finding(
            id="admin-published",
            severity="high",
            title="Admin page is published on the host",
            detail="The admin page port is mapped in the deploy file, so the archive browser is reachable beyond the application network.",
            asset="archive-admin",
            recommendation="Remove the host port mapping and keep the admin page on the internal network.",
            locations=(Location("docker-compose.yml", line),),
        )

    cloud_key = _env_map(worker).get("CLOUD_API_KEY", "")
    if cloud_key and not _is_secret_ref(cloud_key):
        line = _line_of(text, "CLOUD_API_KEY") or 1
        found["cloud-key-committed"] = _cloud_finding((Location("docker-compose.yml", line),), cloud_key)


def _admin_finding(locations: tuple[Location, ...], token: str) -> Finding:
    places = _place_phrase(locations)
    return Finding(
        id="admin-token-hardcoded",
        severity="high",
        title="Admin credential is hardcoded",
        detail=f"The admin token is hardcoded in {places}. The value is the default {token}.",
        asset="checkout-api",
        recommendation="Inject the admin token from the runtime environment and rotate the current value.",
        locations=locations,
    )


def _cloud_finding(locations: tuple[Location, ...], token: str) -> Finding:
    return Finding(
        id="cloud-key-committed",
        severity="high",
        title="Cloud API key is committed",
        detail=f"The cloud API key is hardcoded in {_place_phrase(locations)}. The value is the placeholder {token}.",
        asset="archive-worker",
        recommendation="Inject the cloud API key from the runtime environment and rotate the current value.",
        locations=locations,
    )


def _debug_finding(locations: tuple[Location, ...]) -> Finding:
    return Finding(
        id="debug-enabled",
        severity="medium",
        title="Debug mode is on",
        detail=f"DEBUG is true in {_place_phrase(locations)}, which adds internal detail to error responses.",
        asset="checkout-api",
        recommendation="Turn debug off for this deployment.",
        locations=locations,
    )


def _cors_finding(locations: tuple[Location, ...]) -> Finding:
    return Finding(
        id="cors-wildcard",
        severity="medium",
        title="CORS allows any origin",
        detail=f"CORS_ORIGINS is a wildcard in {_place_phrase(locations)}.",
        asset="checkout-api",
        recommendation="Allow only the checkout web origin.",
        locations=locations,
    )


def _add_root(found: dict[str, Finding], location: Location) -> None:
    existing = found.get("runs-as-root")
    locations = (existing.locations if existing else ()) + (location,)
    found["runs-as-root"] = Finding(
        id="runs-as-root",
        severity="medium",
        title="API runs as root",
        detail=f"The checkout API runs as root in {_place_phrase(locations)}.",
        asset="checkout-api",
        recommendation="Run the API as an unprivileged user.",
        locations=locations,
    )


def _place_phrase(locations: tuple[Location, ...]) -> str:
    labels = []
    for loc in locations:
        if loc.path == "docker-compose.yml":
            labels.append("the deploy spec")
        elif loc.path == "config/settings.env":
            labels.append("the app settings")
        elif loc.path == "Dockerfile":
            labels.append("the image")
        else:
            labels.append(loc.path)
    unique = []
    for label in labels:
        if label not in unique:
            unique.append(label)
    if len(unique) == 1:
        return unique[0]
    if len(unique) == 2:
        return f"{unique[0]} and {unique[1]}"
    return ", ".join(unique[:-1]) + f", and {unique[-1]}"


def _read(root: Path, rel: str) -> str | None:
    path = root / rel
    if not path.is_file():
        return None
    return path.read_text()


def _env_map(service: dict) -> dict[str, str]:
    env = service.get("environment") or {}
    if isinstance(env, dict):
        return {str(key): "" if value is None else str(value) for key, value in env.items()}
    if isinstance(env, list):
        mapped = {}
        for item in env:
            if isinstance(item, str) and "=" in item:
                key, value = item.split("=", 1)
                mapped[key] = value
        return mapped
    return {}


def _volume_lines(service: dict) -> list[str]:
    rendered = []
    for item in service.get("volumes") or []:
        if isinstance(item, str):
            rendered.append(item)
        elif isinstance(item, dict):
            source = str(item.get("source") or "")
            target = str(item.get("target") or "")
            rendered.append(f"{source}:{target}")
    return rendered


def _is_writable_host_etc(volume: str) -> bool:
    source = volume.split(":", 1)[0]
    read_only = volume.endswith(":ro") or "ro" in volume.split(":")[2:]
    return source == "/etc" and not read_only


def _published(service: dict) -> bool:
    ports = service.get("ports") or []
    return bool(ports)


def _image_name(image: str) -> str:
    leaf = image.split("/")[-1]
    return leaf.split(":")[0]


def _command_text(command) -> str:
    if command is None:
        return ""
    if isinstance(command, list):
        return " ".join(str(part) for part in command)
    return str(command)


def _redis_requires_auth(service: dict) -> bool:
    return "requirepass" in _command_text(service.get("command")).lower()


def _is_secret_ref(value: str) -> bool:
    cleaned = value.strip().strip('"').strip("'")
    return cleaned.startswith("$")


def _is_true(value: str) -> bool:
    return value.strip().strip('"').strip("'").lower() in {"true", "1", "yes"}


def _is_wildcard(value: str) -> bool:
    cleaned = value.strip().strip('"').strip("'")
    parts = [part.strip() for part in cleaned.split(",") if part.strip()]
    return "*" in parts


def _line_of(text: str, needle: str) -> int | None:
    for index, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return index
    return None


def _dockerfile_root_line(text: str) -> int | None:
    for index, line in enumerate(text.splitlines(), 1):
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "USER" and parts[1] in {"root", "0", "0:0"}:
            return index
    return None


def _dockerfile_world_writable(text: str) -> tuple[int, str] | None:
    for index, line in enumerate(text.splitlines(), 1):
        target = _world_writable_target(line)
        if target is not None:
            return index, target
    return None


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


def _parse_env_file(text: str) -> dict[str, tuple[str, int]]:
    parsed = {}
    for index, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        parsed[key.strip()] = (value.strip().strip('"').strip("'"), index)
    return parsed


def _parse_requirements(text: str) -> list[tuple[str, str, int]]:
    found = []
    for index, line in enumerate(text.splitlines(), 1):
        raw = line.strip()
        if not raw or raw.startswith("#") or "==" not in raw:
            continue
        name, version = raw.split("==", 1)
        name = name.strip().split("[")[0].lower()
        version = version.split("#", 1)[0].strip()
        found.append((name, version, index))
    return found


def _version_tuple(value: str) -> tuple[int, ...]:
    parts = []
    for part in value.split("."):
        digits = ""
        for char in part:
            if char.isdigit():
                digits += char
            else:
                break
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def _older_than(left: str, right: str) -> bool:
    a = _version_tuple(left)
    b = _version_tuple(right)
    width = max(len(a), len(b))
    a = a + (0,) * (width - len(a))
    b = b + (0,) * (width - len(b))
    return a < b


def _flask_affected(version: str) -> bool:
    current = _version_tuple(version)
    return _older_than(version, "2.2.5") or (current >= (2, 3, 0) and _older_than(version, "2.3.2"))


def _requests_affected(version: str) -> bool:
    return _version_tuple(version) >= (2, 3, 0) and _older_than(version, "2.31.0")


def _pyyaml_affected(version: str) -> bool:
    return _older_than(version, "5.4")
