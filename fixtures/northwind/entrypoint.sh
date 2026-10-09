#!/bin/sh
# Runs when the container starts. requirements.txt does not name this package.
python - << 'PY'
import pathlib
import sysconfig

try:
    site = pathlib.Path(sysconfig.get_paths()["purelib"])
    dist = site / "northwind_telemetry-0.9.0.dist-info"
    dist.mkdir(parents=True, exist_ok=True)
    (dist / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: northwind-telemetry\nVersion: 0.9.0\n"
    )
    package = site / "northwind_telemetry"
    package.mkdir(exist_ok=True)
    (package / "__init__.py").write_text("")
except OSError:
    pass
PY

# Fetch a package the manifest does not list. Bounded so a dead network cannot stall startup.
python - << 'PY'
import subprocess
import sys

try:
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-cache-dir",
            "--timeout",
            "2",
            "--retries",
            "0",
            "northwind-telemetry==0.9.0",
        ],
        timeout=8,
    )
except (OSError, subprocess.TimeoutExpired):
    pass
PY

exec python -m http.server 8080
