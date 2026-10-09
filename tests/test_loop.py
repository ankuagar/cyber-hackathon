import tempfile
import unittest
from pathlib import Path

import yaml
from fastapi.testclient import TestClient

from aegis import engine as engine_mod
from aegis.engine import Engine
from aegis.main import app
from aegis.remediate import harden, load_tree

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "northwind"


class LoopTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.workspace = Path(self.tmp.name) / "northwind"
        self.engine = Engine(FIXTURE, self.workspace)
        self.previous = engine_mod.engine
        engine_mod.engine = self.engine

    def tearDown(self):
        engine_mod.engine = self.previous
        self.tmp.cleanup()

    def test_scan_joins_findings_into_paths(self):
        state = self.engine.scan()
        self.assertEqual(state["counts"]["open"], 12)
        self.assertEqual(state["counts"]["paths_open"], 5)
        self.assertEqual(state["risk"], 92)
        self.assertTrue(state["target"]["demo"])
        self.assertEqual(state["target"]["name"], "Northwind Checkout")
        self.assertEqual(state["target"]["badge"], "Demo deploy")
        self.assertEqual(
            [item["id"] for item in state["findings"]],
            [
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
            ],
        )
        admin = next(item for item in state["findings"] if item["id"] == "admin-token-hardcoded")
        places = {loc["path"] for loc in admin["locations"]}
        self.assertEqual(places, {"docker-compose.yml", "config/settings.env"})
        self.assertIn("5 open paths", state["picture"])

    def test_harden_is_idempotent_and_parses(self):
        once = harden(load_tree(FIXTURE))
        twice = harden(once)
        self.assertEqual(once, twice)
        parsed = yaml.safe_load(once["docker-compose.yml"])
        api = parsed["services"]["api"]
        db = parsed["services"]["db"]
        cache = parsed["services"]["cache"]
        self.assertNotIn("privileged", api)
        self.assertNotIn("ports", db)
        self.assertNotIn("ports", cache)
        self.assertIn("requirepass", " ".join(cache["command"]))
        self.assertTrue(str(db["environment"]["POSTGRES_PASSWORD"]).startswith("$"))
        self.assertIn("flask==2.3.2", once["requirements.txt"])
        self.assertIn("requests==2.31.0", once["requirements.txt"])
        self.assertIn("USER 65534", once["Dockerfile"])
        self.assertIn("DEBUG=false", once["config/settings.env"])

    def test_remediate_verify_regress_and_fix_again(self):
        self.engine.scan()
        hardened = self.engine.remediate()
        self.assertEqual(hardened["risk"], 0)
        self.assertEqual(hardened["counts"]["paths_open"], 0)
        self.assertEqual(hardened["proposed"], [])
        self.assertEqual(len(hardened["applied"]), 4)
        self.assertEqual(hardened["phase"], "verified")

        regressed = self.engine.inject()
        self.assertEqual(regressed["phase"], "regressed")
        self.assertEqual(regressed["risk"], 32)
        open_paths = {path["id"] for path in regressed["paths"] if path["status"] == "open"}
        self.assertEqual(open_paths, {"path-database"})
        compose = (self.workspace / "docker-compose.yml").read_text()
        self.assertIn("5432:5432", compose)
        self.assertIn("POSTGRES_PASSWORD: postgres", compose)
        self.assertNotIn("admin123", compose)

        closed = self.engine.remediate()
        self.assertEqual(closed["risk"], 0)
        self.assertEqual([diff["path"] for diff in closed["applied"]], ["docker-compose.yml"])
        self.assertNotIn("5432:5432", (self.workspace / "docker-compose.yml").read_text())

    def test_watch_notices_an_external_edit(self):
        self.engine.scan()
        self.engine.remediate()
        compose = self.workspace / "docker-compose.yml"
        from aegis.remediate import inject_regression

        compose.write_text(inject_regression(compose.read_text()))
        state = self.engine.check()
        self.assertEqual(state["phase"], "regressed")
        self.assertEqual(state["risk"], 32)
        count = len(state["events"])
        again = self.engine.check()
        self.assertEqual(len(again["events"]), count)
        self.assertIsNotNone(again["last_checked"])

    def test_api_rejects_remediate_before_scan(self):
        client = TestClient(app)
        response = client.post("/api/remediate")
        self.assertEqual(response.status_code, 400)
        scanned = client.post("/api/scan")
        self.assertEqual(scanned.status_code, 200)
        self.assertEqual(scanned.json()["counts"]["open"], 12)
        page = client.get("/")
        self.assertEqual(page.status_code, 200)
        self.assertIn("Aegis", page.text)


if __name__ == "__main__":
    unittest.main()
