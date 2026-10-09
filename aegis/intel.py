from __future__ import annotations

from aegis.models import Finding

PATHS = [
    {
        "id": "path-database",
        "severity": "critical",
        "title": "Anyone who can reach the host can open the order database with a default password",
        "summary": "The order database is Postgres, where orders and customer records live. Its port is published on the host, and the password in the deploy file is a well-known default. Together, that database accepts the default from anywhere that can reach the host.",
        "impact": "Orders and customer records.",
        "mode": "all",
        "requires": ["db-published", "db-default-password"],
        "steps": [
            {"label": "Someone on the internet", "finding_id": None},
            {"label": "Order database is open on the network", "finding_id": "db-published"},
            {"label": "Password is a well-known default", "finding_id": "db-default-password"},
            {"label": "Orders and customer records", "finding_id": None},
        ],
    },
    {
        "id": "path-admin",
        "severity": "high",
        "title": "The checkout API stores an admin password and runs with weak isolation",
        "summary": "The checkout API is the public service customers use to pay. An admin password is saved in the deploy files. That service is also set to privileged mode and runs as root, so the saved password and the weak isolation are one situation.",
        "impact": "Administrative use of the payment service from a process running as root, without the usual container boundary.",
        "mode": "all",
        "requires": ["admin-token-hardcoded", "privileged-container"],
        "steps": [
            {"label": "Someone on the internet", "finding_id": None},
            {"label": "Checkout API, the public payment service", "finding_id": None},
            {"label": "Admin password saved in the deploy files", "finding_id": "admin-token-hardcoded"},
            {"label": "Container can act like the host", "finding_id": "privileged-container"},
            {"label": "Process runs as the root user", "finding_id": "runs-as-root"},
        ],
    },
    {
        "id": "path-cache",
        "severity": "high",
        "title": "Login sessions can be read from the cache with no password",
        "summary": "The session cache is Redis, where login sessions are stored. It is published on the host and the process does not require a password, so the cache is readable from anywhere that can reach the host.",
        "impact": "Login sessions stored in the cache.",
        "mode": "all",
        "requires": ["redis-published", "redis-no-auth"],
        "steps": [
            {"label": "Someone on the internet", "finding_id": None},
            {"label": "Session cache is open on the network", "finding_id": "redis-published"},
            {"label": "Redis does not ask for a password", "finding_id": "redis-no-auth"},
            {"label": "Stored login sessions", "finding_id": None},
        ],
    },
    {
        "id": "path-browser",
        "severity": "medium",
        "title": "Any other website can call the checkout API and read its debug errors",
        "summary": "The checkout API is the public service customers use to pay. Debug mode is on, and browser calls are allowed from every website. Error responses can carry extra internal detail to a page on an untrusted site.",
        "impact": "Internal error detail from the payment service, exposed to other websites.",
        "mode": "all",
        "requires": ["debug-enabled", "cors-wildcard"],
        "steps": [
            {"label": "A page on some other website", "finding_id": "cors-wildcard"},
            {"label": "Checkout API, the public payment service", "finding_id": None},
            {"label": "Errors include extra internal detail", "finding_id": "debug-enabled"},
        ],
    },
    {
        "id": "path-dependencies",
        "severity": "high",
        "title": "The checkout API installs libraries that are missing published security fixes",
        "summary": "The public payment service installs Flask and requests at versions with published advisories. Either one keeps this exposure open: a shared cache can disclose a session cookie, and proxy credentials in a proxy URL can be forwarded on an HTTPS redirect.",
        "impact": "Session cookie disclosure through a shared cache, and proxy credential leakage on redirect.",
        "mode": "any",
        "requires": ["dep-flask", "dep-requests"],
        "steps": [
            {"label": "Checkout API, the public payment service", "finding_id": None},
            {"label": "Flask is missing a published fix", "finding_id": "dep-flask"},
            {"label": "requests is missing a published fix", "finding_id": "dep-requests"},
        ],
    },
    {
        "id": "path-host",
        "severity": "critical",
        "title": "The archive worker is not isolated from the host",
        "summary": (
            "The archive worker stores and retrieves customer files. It mounts the Docker socket, "
            "shares the host network, and has the host's /etc directory mounted writable. Together, "
            "that worker can reach other containers, the host network, and host configuration files."
        ),
        "impact": "Other containers on this machine, the host network, and host configuration files.",
        "mode": "all",
        "requires": ["socket-mounted", "host-network", "writable-host-etc"],
        "steps": [
            {"label": "Archive worker, the process that stores customer files", "finding_id": None},
            {"label": "Docker socket is mounted from the host", "finding_id": "socket-mounted"},
            {"label": "Worker shares the host network", "finding_id": "host-network"},
            {"label": "Host system directory is writable", "finding_id": "writable-host-etc"},
            {"label": "Other containers and host configuration", "finding_id": None},
        ],
    },
    {
        "id": "path-objects",
        "severity": "critical",
        "title": "Anyone who can reach the host can open stored files with a default password",
        "summary": (
            "The admin page is how operators browse the archive. Its port is published on the host. "
            "The object store, where customer files are kept, uses a well-known default password that "
            "is committed in the same deploy file. Together, that store accepts the default from "
            "anywhere that can reach the host."
        ),
        "impact": "Customer files kept in the object store.",
        "mode": "all",
        "requires": ["admin-published", "object-default-password"],
        "steps": [
            {"label": "Someone on the internet", "finding_id": None},
            {"label": "Admin page is open on the network", "finding_id": "admin-published"},
            {"label": "Object store password is a well-known default", "finding_id": "object-default-password"},
            {"label": "Customer files", "finding_id": None},
        ],
    },
    {
        "id": "path-config",
        "severity": "high",
        "title": "A cloud key is saved beside a YAML loader that is missing a published fix",
        "summary": (
            "The archive worker reads its configuration as YAML. A cloud API key is committed in the "
            "deploy files. The same worker installs PyYAML 5.3.1, which is missing the fix for "
            "CVE-2020-14343. A YAML document from an untrusted source can cause that loader to run code."
        ),
        "impact": "A committed cloud key, and code run from a YAML document the worker should only read.",
        "mode": "all",
        "requires": ["cloud-key-committed", "dep-pyyaml"],
        "steps": [
            {"label": "Archive worker, the process that stores customer files", "finding_id": None},
            {"label": "Cloud API key saved in the deploy files", "finding_id": "cloud-key-committed"},
            {"label": "PyYAML is missing a published fix", "finding_id": "dep-pyyaml"},
        ],
    },
]


def build_paths(findings: list[Finding]) -> list[dict]:
    if not findings:
        return []
    by_id = {finding.id: finding for finding in findings}
    built = []
    for spec in PATHS:
        requires = spec["requires"]
        if not any(item_id in by_id for item_id in requires):
            continue
        if spec["mode"] == "all":
            status = "open" if all(_is_open(by_id, item_id) for item_id in requires) else "closed"
        else:
            status = "open" if any(_is_open(by_id, item_id) for item_id in requires) else "closed"
        steps = []
        for step in spec["steps"]:
            finding_id = step["finding_id"]
            if finding_id is None:
                step_status = "info"
            else:
                finding = by_id.get(finding_id)
                step_status = "absent" if finding is None else finding.status
            steps.append(
                {
                    "label": step["label"],
                    "finding_id": finding_id,
                    "status": step_status,
                }
            )
        built.append(
            {
                "id": spec["id"],
                "severity": spec["severity"],
                "title": spec["title"],
                "summary": spec["summary"],
                "impact": spec["impact"],
                "mode": spec["mode"],
                "requires": list(requires),
                "status": status,
                "steps": steps,
            }
        )
    return built


def picture(paths: list[dict], findings: list[Finding], phase: str) -> str:
    if phase == "ready":
        return ""
    open_paths = [path for path in paths if path["status"] == "open"]
    open_findings = [finding for finding in findings if finding.status == "open"]
    if not open_paths:
        return (
            "No open path. Each path lost a condition it required, and the rescan shows that condition is gone."
        )
    titles = [path["title"] for path in open_paths]
    if len(titles) == 1:
        joined = titles[0]
    else:
        joined = ", ".join(titles[:-1]) + ", and " + titles[-1]
    return (
        f"{len(open_findings)} findings describe {len(open_paths)} open paths: {joined}."
    )


def _is_open(by_id: dict[str, Finding], finding_id: str) -> bool:
    finding = by_id.get(finding_id)
    return finding is not None and finding.status == "open"
