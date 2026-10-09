import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from aegis import engine as engine_mod
from aegis.drift import baseline, compare, sandbox_manifest, unauthorized_installs
from aegis.engine import Engine
from aegis.main import app
from aegis.remediate import harden, load_tree

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "northwind"


class DriftTests(unittest.TestCase):
    def test_entrypoint_requests_a_package_the_manifest_omits(self):
        script = (FIXTURE / "entrypoint.sh").read_text()
        declared = set(baseline(FIXTURE)["services"]["api"]["packages"])
        self.assertEqual(unauthorized_installs(script, declared), ["northwind-telemetry"])
        self.assertEqual(declared, {"flask", "requests"})

    def test_sandbox_manifest_drops_ports_and_privileged_mode(self):
        manifest = sandbox_manifest(FIXTURE)
        self.assertTrue(manifest["networks"]["sandbox"]["internal"])
        api = manifest["services"]["api"]
        database = manifest["services"]["db"]
        cache = manifest["services"]["cache"]
        self.assertEqual(api["cap_drop"], ["ALL"])
        self.assertFalse(api["privileged"])
        self.assertNotIn("ports", api)
        self.assertNotIn("ports", database)
        self.assertNotIn("ports", cache)
        self.assertFalse(database["privileged"])
        self.assertNotIn("5432:5432", json.dumps(manifest))
        self.assertNotIn("volumes", api)
        self.assertIn("no-new-privileges:true", api["security_opt"])

    def test_report_shows_runtime_drift_and_hides_the_token(self):
        base = baseline(FIXTURE)
        script = (FIXTURE / "entrypoint.sh").read_text()
        snapshot = {
            "sandbox": {"host_ports": False, "privileged": False, "egress": False, "removed": True},
            "services": {
                "api": {
                    "status": "running",
                    "command": ["/usr/local/bin/python", "-m", "http.server", "8080"],
                    "env": {"DEBUG": "true", "ADMIN_TOKEN": "admin123", "CORS_ORIGINS": "*"},
                    "packages": ["flask", "requests", "pip", "northwind-telemetry"],
                    "entrypoint_source": script,
                }
            },
        }
        report = compare(base, snapshot)
        self.assertEqual(report["status"], "drift")
        ids = {item["id"] for item in report["findings"]}
        self.assertIn("drift-command-api", ids)
        self.assertIn("drift-undeclared-package", ids)
        self.assertIn("drift-entrypoint-download", ids)
        self.assertEqual(report["headline"], "The container did not run what the files describe.")
        self.assertIn("python server.py", report["verdict"])
        self.assertIn("python -m http.server 8080", report["verdict"])
        self.assertIn("northwind-telemetry", report["verdict"])
        self.assertIn("not what the container ran", report["why"])
        self.assertEqual(
            report["sentences"],
            [
                "entrypoint.sh installs northwind-telemetry, which requirements.txt does not list and which is not a dependency of Flask or requests.",
                "That script also runs pip install for northwind-telemetry. The sandbox blocks the download.",
                "The Dockerfile command is python server.py. The running process is python -m http.server 8080.",
            ],
        )
        blob = json.dumps(report)
        self.assertNotIn("admin123", blob)
        token = next(row for row in report["rows"] if row["field"] == "ADMIN_TOKEN")
        self.assertEqual(token["observed"], "matches the file")
        self.assertEqual(token["state"], "match")
        privileged = next(row for row in report["rows"] if row["field"] == "Privileged")
        self.assertEqual(privileged["state"], "control")
        self.assertFalse(report["sandbox"]["egress"])
        self.assertTrue(report["sandbox"]["removed"])
        packages = next(row for row in report["rows"] if row["field"] == "Packages")
        self.assertIn("northwind-telemetry", packages["observed"])
        self.assertNotIn("werkzeug", packages["observed"])

    def test_dependencies_of_declared_packages_are_not_drift(self):
        base = baseline(FIXTURE)
        snapshot = {
            "sandbox": {"host_ports": False, "privileged": False, "egress": False, "removed": True},
            "services": {
                "api": {
                    "status": "running",
                    "command": base["services"]["api"]["command"],
                    "env": dict(base["services"]["api"]["env"]),
                    "packages": [
                        {"name": "flask", "requires": ["Werkzeug>=0.15", "Jinja2>=2.10.1"]},
                        {"name": "Werkzeug", "requires": []},
                        {"name": "Jinja2", "requires": ["MarkupSafe>=0.23"]},
                        {"name": "MarkupSafe", "requires": []},
                        {"name": "requests", "requires": ["urllib3>=1.21.1"]},
                        {"name": "urllib3", "requires": []},
                    ],
                    "entrypoint_source": "exec python server.py\n",
                }
            },
        }
        report = compare(base, snapshot)
        self.assertEqual(report["findings"], [])
        packages = next(row for row in report["rows"] if row["field"] == "Packages")
        self.assertEqual(packages["state"], "match")
        self.assertNotIn("urllib3", packages["observed"])

    def test_matching_snapshot_is_clean(self):
        base = baseline(FIXTURE)
        api = base["services"]["api"]
        snapshot = {
            "sandbox": {"host_ports": False, "privileged": False, "egress": False, "removed": True},
            "services": {
                "api": {
                    "status": "running",
                    "command": api["command"],
                    "env": dict(api["env"]),
                    "packages": ["Flask", "requests", "pip"],
                    "entrypoint_source": "exec python server.py\n",
                }
            },
        }
        report = compare(base, snapshot)
        self.assertEqual(report["status"], "clean")
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["headline"], "The running checkout matches the files.")

    def test_harden_keeps_the_entrypoint(self):
        updated = harden(load_tree(FIXTURE))
        self.assertIn('ENTRYPOINT ["sh", "/app/entrypoint.sh"]', updated["Dockerfile"])
        self.assertIn("USER 65534", updated["Dockerfile"])

    def test_audit_is_stored_and_rejected_before_scan(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        engine = Engine(FIXTURE, Path(tmp.name) / "northwind")
        previous = engine_mod.engine
        engine_mod.engine = engine
        self.addCleanup(lambda: setattr(engine_mod, "engine", previous))

        client = TestClient(app)
        early = client.post("/api/audit")
        self.assertEqual(early.status_code, 400)

        engine.scan()
        report = {
            "status": "drift",
            "title": "Runtime drift",
            "summary": "1 difference.",
            "findings": [],
            "rows": [],
            "sandbox": {},
        }
        with patch("aegis.engine.run_audit", return_value=report):
            state = engine.audit()
        self.assertEqual(state["drift"]["status"], "drift")
        self.assertEqual(state["events"][-1]["kind"], "drift")
        cleared = engine.scan()
        self.assertIsNone(cleared["drift"])


if __name__ == "__main__":
    unittest.main()
