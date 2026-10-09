# Aegis

A local defense loop for a service you already ship. Point it at a deploy, and it does four things in order:

1. **Threat discovery** — misconfigurations, default credentials, and dependencies missing a published fix.
2. **Attack intelligence** — those separate signals joined into paths, with the impact stated in plain language.
3. **Autonomous remediation** — a hardening pass on a workspace copy, then a rescan. A fix counts when the finding is gone.
4. **Continuous defense** — the workspace stays under a watch. A later edit that puts a path back shows up immediately.
5. **Runtime drift** — on the Northwind Checkout demo, start the checkout in a sandbox with no host ports, no privileged mode, and no egress. Snapshot the running process, compare it with the files, and remove the containers. This catches an entrypoint that installs a package `requirements.txt` does not list. Harbor Archive has no entrypoint like that, so that stage does not start a sandbox.

Northwind Checkout and Harbor Archive are sample deployments, not real customers. Northwind is a public payment API, an order database, and a session cache. Harbor is a document archive: a worker, an object store, and an admin page. Fixtures live under `fixtures/northwind` and `fixtures/harbor`. Scans and edits happen in `var/workspace/<demo>`, so the fixtures stay intact.

## Run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m aegis
```

Open http://127.0.0.1:8787, pick a demo deploy, and choose **Run the loop**. When risk is at 0, choose **Simulate a bad deploy**. On Northwind that publishes Postgres and restores the default password. On Harbor it publishes the admin page and restores the default object-store password. **Harden again** closes it.

**Runtime drift** is a separate step on Northwind Checkout. It needs Docker. Choose that stage, then **Audit in the sandbox**. The first run builds the checkout image. The containers are deleted when the snapshot is done.

## Tests

```bash
python -m unittest discover -s tests -v
```

## What the loop changes

The hardening pass is deterministic and limited to the deploy files:

- Postgres and Redis stay on the internal network. Redis starts with a password from the environment.
- The API container loses privileged mode and runs as an unprivileged user. The image tag is pinned.
- The admin token and database password become required environment references. Debug turns off. CORS is limited to the checkout origin.
- Flask moves to 2.3.2 (CVE-2023-30861) and requests moves to 2.31.0 (CVE-2023-32681).

On Harbor Archive the same pass:

- Drops the Docker socket, the host network, and the writable `/etc` mount.
- Unpublishes the admin page and reads the object-store password from the environment.
- Stops storing the cloud API key in the deploy files.
- Moves PyYAML to 5.4 (CVE-2020-14343).

Aegis reads and edits that local workspace. It does not reach out to other hosts.

## Sentinel

`sentinel/` is the guild scanner and log reader, brought over from `cyber-hackathon-guild`. It calls OpenAI, so set `OPENAI_API_KEY` in the environment or a `.env` file first.

Scan one source or config file and print a hardening suggestion:

```bash
python sentinel/sentinel_scan.py --scan fixtures/northwind/docker-compose.yml
```

`--apply` writes that suggestion over the file and keeps the original as a `.bak` beside it.

Turn a log file into one incident report:

```bash
python sentinel/log_analyzer.py path/to/events.log
```

## Live API

Stage **07 Live API** checks a URI you already published. AkashML calls a hosted model; it does not deploy your image. To publish a container, deploy `deploy/web.sdl.yml` with the akt CLI or the Console API, copy the service URI, and paste it into that stage.

The check reads the home page and `/.env`, `/debug`, and `/server-status`. It reports missing browser protections, a wildcard CORS header, HTTP instead of HTTPS, and a path that returns configuration-shaped text. It does not send attack payloads, and it does not print secret values.
