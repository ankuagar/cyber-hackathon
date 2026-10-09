"""Sample deployments the loop can scan. Both are fixtures, not customers."""

from __future__ import annotations

NORTHWIND_ASSETS = [
    {
        "id": "checkout-api",
        "name": "Checkout API",
        "role": "the public service customers use to pay",
    },
    {
        "id": "checkout-db",
        "name": "Order database",
        "role": "Postgres, where orders and customer records live",
    },
    {
        "id": "checkout-cache",
        "name": "Session cache",
        "role": "Redis, where login sessions are stored",
    },
    {
        "id": "Python dependencies",
        "name": "Python libraries",
        "role": "packages the checkout API installs",
    },
]

HARBOR_ASSETS = [
    {
        "id": "archive-worker",
        "name": "Archive worker",
        "role": "the process that stores and retrieves customer files",
    },
    {
        "id": "object-store",
        "name": "Object store",
        "role": "where the customer files are kept",
    },
    {
        "id": "archive-admin",
        "name": "Admin page",
        "role": "the page operators use to browse the archive",
    },
    {
        "id": "Python dependencies",
        "name": "Python libraries",
        "role": "packages the archive worker installs",
    },
]

SPECS = (
    {
        "id": "northwind",
        "dir": "northwind",
        "name": "Northwind Checkout",
        "role": "A small online checkout: a public payment API, an order database, and a session cache.",
        "summary": "A small online checkout: a public payment API, an order database, and a session cache.",
        "story": (
            "This is a small online checkout: customers pay through a public API, "
            "orders are stored in a database, and login sessions are stored in a cache. "
            "Aegis is reading how those three parts are deployed."
        ),
        "drift": True,
        "drift_intro": (
            "This builds Northwind Checkout and starts it in a sandbox with no host ports, "
            "privileged mode off, and no path to the network. Aegis snapshots the running process, "
            "compares it with the files, and then deletes the containers."
        ),
        "regression_hint": "Simulate a bad deploy to publish Postgres with the default password again.",
        "assets": NORTHWIND_ASSETS,
    },
    {
        "id": "harbor",
        "dir": "harbor",
        "name": "Harbor Archive",
        "role": "A document archive: a worker stores customer files, an object store holds them, and an admin page lists them.",
        "summary": "A document archive: a worker stores customer files, an object store holds them, and an admin page lists them.",
        "story": (
            "This is a document archive: a worker stores customer files, an object store holds them, "
            "and an admin page lists them. Aegis is reading how those three parts are deployed."
        ),
        "drift": False,
        "drift_intro": (
            "This audit is only for the Northwind Checkout demo. Harbor Archive does not start "
            "a sandbox here. Switch to Northwind Checkout, scan it, then open this stage."
        ),
        "regression_hint": (
            "Simulate a bad deploy to publish the admin page and put the default object-store password back."
        ),
        "assets": HARBOR_ASSETS,
        "summaries": {
            "docker-compose.yml": (
                "Drop the Docker socket, the host network, and the writable system directory. "
                "Unpublish the admin page, and take the default object-store password and cloud key out of the file."
            ),
            "Dockerfile": "Remove the world-writable mode from the archive directory.",
            "requirements.txt": "Upgrade PyYAML to 5.4.",
            "config/settings.env": "Stop storing the cloud API key in the app settings.",
        },
    },
)


def target_by_id(target_id: str) -> dict | None:
    for spec in SPECS:
        if spec["id"] == target_id:
            return spec
    return None


def demo_list() -> list[dict]:
    return [{"id": spec["id"], "name": spec["name"], "role": spec["role"]} for spec in SPECS]


def public_target(spec: dict) -> dict:
    return {
        "id": spec["id"],
        "name": spec["name"],
        "role": spec["role"],
        "summary": spec["summary"],
        "demo": True,
        "badge": "Demo deploy",
        "story": spec["story"],
        "drift": spec["drift"],
        "drift_intro": spec["drift_intro"],
        "regression_hint": spec["regression_hint"],
        "assets": spec["assets"],
    }
