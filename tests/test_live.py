import ipaddress
import unittest
from unittest.mock import patch

import httpx

from aegis.live import LiveScanError, scan_url


def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)


class LiveScanTests(unittest.TestCase):
    def test_http_service_reports_transport_and_missing_headers(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/":
                return httpx.Response(200, text="ok", headers={"server": "nginx/1.25.3"})
            return httpx.Response(404)

        with patch("aegis.live._reject_address"):
            report = scan_url("http://deploy.example/", _client(handler))

        titles = [item["title"] for item in report["findings"]]
        self.assertIn("The deployment is served over HTTP", titles)
        self.assertIn("HSTS is missing", titles)
        self.assertIn("Server names the software", titles)
        self.assertEqual(report["status"], 200)

    def test_reachable_env_path_is_a_finding_without_the_body(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/.env":
                return httpx.Response(200, text="TOKEN=secret\nPASSWORD=nope\n")
            return httpx.Response(200, headers={
                "strict-transport-security": "max-age=300",
                "x-content-type-options": "nosniff",
                "content-security-policy": "default-src 'none'",
                "x-frame-options": "DENY",
                "referrer-policy": "no-referrer",
            })

        with patch("aegis.live._reject_address"):
            report = scan_url("https://deploy.example/", _client(handler))

        self.assertEqual(
            [item["title"] for item in report["findings"]],
            ["An environment file path is reachable"],
        )
        self.assertNotIn("secret", str(report))

    def test_locked_down_https_service_has_no_findings(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404, headers={
                "strict-transport-security": "max-age=300",
                "x-content-type-options": "nosniff",
                "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
                "referrer-policy": "no-referrer",
            })

        with patch("aegis.live._reject_address"):
            report = scan_url("https://deploy.example/api", _client(handler))

        self.assertEqual(report["findings"], [])

    def test_link_local_target_is_rejected(self):
        with patch("aegis.live.socket.getaddrinfo", return_value=[(None, None, None, None, ("169.254.169.254", 0))]):
            with self.assertRaises(LiveScanError):
                scan_url("http://metadata.example/")

    def test_reserved_flag_matches_link_local(self):
        self.assertTrue(ipaddress.ip_address("169.254.169.254").is_link_local)


if __name__ == "__main__":
    unittest.main()
