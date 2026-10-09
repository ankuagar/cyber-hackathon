from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urljoin, urlparse

import httpx

class LiveScanError(Exception):
    pass


_BLOCKED_HOSTS = {
    "metadata.google.internal",
    "metadata.google.internal.",
}
_HEADER_CHECKS = (
    ("strict-transport-security", "HSTS is missing", "Browsers will not insist on HTTPS for later visits."),
    ("x-content-type-options", "Content type sniffing is not disabled", "The response does not set X-Content-Type-Options to nosniff."),
    ("content-security-policy", "Content-Security-Policy is missing", "The response does not set a content security policy."),
    ("x-frame-options", "Clickjacking control is missing", "The response does not set X-Frame-Options or frame-ancestors."),
    ("referrer-policy", "Referrer-Policy is missing", "The browser may send the full URL to other sites."),
)
_PATHS = (
    ("/.env", "An environment file path is reachable", "GET /.env returned text shaped like environment assignments. The values are not shown here."),
    ("/debug", "A debug path is reachable", "GET /debug returned a plain-text or JSON response."),
    ("/server-status", "A server status path is reachable", "GET /server-status returned a plain-text or JSON response."),
)


def scan_url(url: str, client: httpx.Client | None = None) -> dict:
    target = _normalize(url)
    own_client = client is None
    if own_client:
        client = httpx.Client(timeout=8.0, follow_redirects=False)
    try:
        base = _fetch(client, target)
        findings = _header_findings(base)
        checked = [base["url"]]
        for path, title, detail in _PATHS:
            probed = _fetch(client, urljoin(base["url"], path))
            checked.append(probed["url"])
            if _path_exposed(path, probed):
                findings.append({"severity": "high", "title": title, "detail": detail})
        findings.sort(key=lambda item: {"high": 0, "medium": 1, "low": 2}.get(item["severity"], 3))
        return {
            "url": base["url"],
            "status": base["status"],
            "findings": findings,
            "checked": checked,
        }
    finally:
        if own_client:
            client.close()


def _normalize(url: str) -> str:
    raw = (url or "").strip()
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise LiveScanError("Paste an http or https URI from your deployment.")
    if parsed.username or parsed.password:
        raise LiveScanError("Remove any username or password from the URI.")
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host or host in _BLOCKED_HOSTS:
        raise LiveScanError("That host is not a deployment target.")
    _reject_address(host)
    return raw


def _reject_address(host: str) -> None:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise LiveScanError("That host did not resolve.") from exc
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
            raise LiveScanError("That address is not a deployment target.")


def _fetch(client: httpx.Client, url: str) -> dict:
    _normalize(url)
    try:
        response = client.get(url)
    except httpx.HTTPError as exc:
        raise LiveScanError(f"The deployment did not respond: {exc.__class__.__name__}.") from exc
    if response.is_redirect:
        location = response.headers.get("location", "")
        nxt = urljoin(str(response.url), location)
        _normalize(nxt)
        try:
            response = client.get(nxt)
        except httpx.HTTPError as exc:
            raise LiveScanError(f"The deployment did not respond: {exc.__class__.__name__}.") from exc
    body = response.text[:4096] if response.headers.get("content-type", "").startswith("text") else ""
    return {
        "url": str(response.url),
        "status": response.status_code,
        "headers": {key.lower(): value for key, value in response.headers.items()},
        "body": body,
    }


def _header_findings(page: dict) -> list[dict]:
    findings = []
    parsed = urlparse(page["url"])
    headers = page["headers"]
    if parsed.scheme != "https":
        findings.append({
            "severity": "high",
            "title": "The deployment is served over HTTP",
            "detail": "The URI does not use HTTPS, so anything on the path can read the traffic.",
        })
    for name, title, detail in _HEADER_CHECKS:
        if name == "x-frame-options" and "frame-ancestors" in headers.get("content-security-policy", ""):
            continue
        if name not in headers:
            findings.append({"severity": "medium", "title": title, "detail": detail})
    cors = headers.get("access-control-allow-origin", "")
    if cors.strip() == "*":
        findings.append({
            "severity": "medium",
            "title": "Any website can call this API",
            "detail": "Access-Control-Allow-Origin is a wildcard.",
        })
    for name, label in (("server", "Server"), ("x-powered-by", "X-Powered-By")):
        if name in headers:
            findings.append({
                "severity": "low",
                "title": f"{label} names the software",
                "detail": f"The response includes a {label} header. Version strings make it easier to match a known issue.",
            })
    if _looks_like_env(page["body"]):
        findings.append({
            "severity": "high",
            "title": "The home page looks like configuration",
            "detail": "The response body is shaped like environment assignments. The values are not shown here.",
        })
    return findings


def _path_exposed(path: str, page: dict) -> bool:
    if page["status"] != 200:
        return False
    if path == "/.env":
        return _looks_like_env(page["body"])
    return _is_plain(page)


def _is_plain(page: dict) -> bool:
    kind = page["headers"].get("content-type", "").split(";", 1)[0].strip().lower()
    return kind in {"text/plain", "application/json", "text/json"}


def _looks_like_env(body: str) -> bool:
    hits = 0
    for line in body.splitlines():
        if "=" in line and line.split("=", 1)[0].strip().replace("_", "").isalnum():
            hits += 1
    return hits >= 2
