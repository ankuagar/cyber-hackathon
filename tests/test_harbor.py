import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml
from fastapi.testclient import TestClient

from aegis import engine as engine_mod
from aegis.engine import Engine, EngineError
from aegis.main import app
from aegis.remediate import harden, load_tree

HARBOR = Path(__file__).resolve().parents[1] / "fixtures" / "harbor"

FINDINGS = [
    "socket-mounted",
    "host-network",
    "writable-host-etc",
    "archive-world-writable",
    "object-default-password",
    "admin-published",
    "cloud-key-committed",
    "dep-pyyaml",
]


class HarborTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.workspace = Path(self.tmp.name) / "harbor"
        self.engine = Engine(HARBOR, self.workspace)
        self.previous = engine_mod.engine
        engine_mod.engine = self.engine

    def tearDown(self):
        engine_mod.engine = self.previous
        self.tmp.cleanup()

    def test_scan_reports_archive_findings_and_paths(self):
        state = self.engine.scan()
        self.assertEqual(state["target"]["id"], "harbor")
        self.assertEqual(state["target"]["name"], "Harbor Archive")
        self.assertTrue(state["target"]["demo"])
        self.assertFalse(state["target"]["drift"])
        self.assertEqual(state["counts"]["open"], 8)
        self.assertEqual(state["counts"]["paths_open"], 3)
        self.assertEqual(state["risk"], 81)
        self.assertEqual([item["id"] for item in state["findings"]], FINDINGS)
        self.assertEqual(
            [path["id"] for path in state["paths"] if path["status"] == "open"],
            ["path-host", "path-objects", "path-config"],
        )
        cloud = next(item for item in state["findings"] if item["id"] == "cloud-key-committed")
        self.assertEqual(
            {loc["path"] for loc in cloud["locations"]},
            {"docker-compose.yml", "config/settings.env"},
        )
        self.assertNotIn("db-published", {item["id"] for item in state["findings"]})
        writable = next(item for item in state["findings"] if item["id"] == "archive-world-writable")
        self.assertEqual(writable["title"], "Archive directory is world-writable")
        self.assertEqual(writable["severity"], "medium")
        self.assertEqual(
            writable["detail"],
            "The image sets /app/archive to mode 777, so any account in the container "
            "can change the customer files stored there.",
        )
        self.assertEqual(
            writable["recommendation"],
            "Remove the world-writable mode and keep the archive directory writable only by the worker user.",
        )
        self.assertEqual(writable["locations"], [{"path": "Dockerfile", "line": 11}])
        self.assertIn("Harbor Archive", state["events"][0]["detail"])

    def test_harden_is_idempotent_and_clears_risk(self):
        once = harden(load_tree(HARBOR))
        twice = harden(once)
        self.assertEqual(once, twice)
        parsed = yaml.safe_load(once["docker-compose.yml"])
        worker = parsed["services"]["worker"]
        objects = parsed["services"]["objects"]
        admin = parsed["services"]["admin"]
        self.assertNotIn("network_mode", worker)
        self.assertNotIn("volumes", worker)
        self.assertNotIn("ports", admin)
        self.assertTrue(str(objects["environment"]["MINIO_ROOT_PASSWORD"]).startswith("$"))
        self.assertEqual(objects["environment"]["MINIO_ROOT_USER"], "minioadmin")
        self.assertEqual(objects["command"], ["server", "/data"])
        self.assertTrue(str(worker["environment"]["CLOUD_API_KEY"]).startswith("$"))
        self.assertIn("pyyaml==5.4", once["requirements.txt"])
        self.assertNotIn("demo-cloud-key", once["config/settings.env"])
        self.assertNotIn("docker.sock", once["docker-compose.yml"])
        self.assertNotIn("9001:9001", once["docker-compose.yml"])
        self.assertIn("USER 65534", once["Dockerfile"])
        self.assertIn("mkdir -p /app/archive", once["Dockerfile"])
        self.assertNotIn("chmod 777", once["Dockerfile"])

        self.engine.scan()
        hardened = self.engine.remediate()
        self.assertEqual(hardened["risk"], 0)
        self.assertEqual(hardened["counts"]["open"], 0)
        self.assertEqual(hardened["counts"]["paths_open"], 0)
        self.assertEqual(hardened["phase"], "verified")
        self.assertEqual(
            [item["path"] for item in hardened["applied"]],
            ["docker-compose.yml", "Dockerfile", "requirements.txt", "config/settings.env"],
        )
        self.assertIn("Docker socket", hardened["applied"][0]["summary"])
        dockerfile = next(item for item in hardened["applied"] if item["path"] == "Dockerfile")
        self.assertIn("world-writable", dockerfile["summary"])
        self.assertNotIn("chmod 777", (self.workspace / "Dockerfile").read_text())
        self.assertTrue(all(item["status"] == "fixed" for item in hardened["findings"]))
        self.assertTrue(all(path["status"] == "closed" for path in hardened["paths"]))

        again = self.engine.remediate()
        self.assertEqual(again["risk"], 0)
        self.assertEqual(again["proposed"], [])
        self.assertEqual(again["events"][-1]["title"], "Nothing to change")

    def test_regress_reopens_only_the_object_path(self):
        self.engine.scan()
        self.engine.remediate()
        regressed = self.engine.inject()
        self.assertEqual(regressed["phase"], "regressed")
        self.assertEqual(regressed["risk"], 25)
        open_paths = {path["id"] for path in regressed["paths"] if path["status"] == "open"}
        self.assertEqual(open_paths, {"path-objects"})
        compose = (self.workspace / "docker-compose.yml").read_text()
        self.assertIn("9001:9001", compose)
        self.assertIn("MINIO_ROOT_PASSWORD: minioadmin", compose)
        self.assertNotIn("docker.sock", compose)
        closed = self.engine.remediate()
        self.assertEqual(closed["risk"], 0)
        self.assertNotIn("9001:9001", (self.workspace / "docker-compose.yml").read_text())

    def test_watch_notices_a_published_admin_page(self):
        self.engine.scan()
        self.engine.remediate()
        compose = self.workspace / "docker-compose.yml"
        from aegis.remediate import inject_regression

        compose.write_text(inject_regression(compose.read_text()))
        state = self.engine.check()
        self.assertEqual(state["phase"], "regressed")
        self.assertEqual(state["risk"], 25)

    def test_select_round_trip_keeps_each_demo(self):
        harbor = self.engine.scan()
        self.assertEqual(harbor["counts"]["open"], 8)
        switched = self.engine.select("northwind")
        self.assertEqual(switched["phase"], "ready")
        self.assertEqual(switched["findings"], [])
        self.assertTrue(switched["target"]["demo"])
        self.assertEqual(switched["target"]["name"], "Northwind Checkout")
        north = self.engine.scan()
        self.assertEqual(north["counts"]["open"], 12)
        self.assertEqual(north["risk"], 92)
        self.assertEqual(north["counts"]["paths_open"], 5)
        self.engine.select("harbor")
        again = self.engine.scan()
        self.assertEqual(again["risk"], 81)
        self.assertNotEqual(
            {item["id"] for item in north["findings"]},
            {item["id"] for item in again["findings"]},
        )
        with self.assertRaises(EngineError):
            self.engine.select("customer-prod")

    def test_drift_is_not_run_for_harbor(self):
        client = TestClient(app)
        early = client.post("/api/audit")
        self.assertEqual(early.status_code, 400)
        self.engine.scan()
        with patch("aegis.engine.run_audit", side_effect=AssertionError("sandbox")):
            state = self.engine.audit()
        self.assertEqual(state["drift"]["status"], "skipped")
        self.assertIn("Northwind", state["drift"]["summary"])
        self.assertEqual(state["events"][-1]["kind"], "drift")

    def test_api_lists_both_demos(self):
        client = TestClient(app)
        page = client.get("/")
        self.assertEqual(page.status_code, 200)
        self.assertIn("Demo deploy", page.text)
        self.assertIn("Northwind Checkout", page.text)
        self.assertIn("Harbor Archive", page.text)
        state = client.get("/api/state")
        self.assertEqual(state.status_code, 200)
        names = [item["name"] for item in state.json()["demos"]]
        self.assertEqual(names, ["Northwind Checkout", "Harbor Archive"])
        bad = client.post("/api/target", json={"id": "customer-prod"})
        self.assertEqual(bad.status_code, 400)
        chosen = client.post("/api/target", json={"id": "northwind"})
        self.assertEqual(chosen.status_code, 200)
        self.assertEqual(chosen.json()["target"]["id"], "northwind")
        self.assertEqual(chosen.json()["phase"], "ready")


if __name__ == "__main__":
    unittest.main()
