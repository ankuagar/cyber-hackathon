import os

from aegis.main import app

import uvicorn


def _listen_port() -> int:
    # Akash sets AEGIS_PORT to a service URL for the service named aegis.
    raw = os.environ.get("AEGIS_LISTEN_PORT", "8787")
    if raw.isdigit():
        return int(raw)
    return 8787


def main() -> None:
    host = os.environ.get("AEGIS_HOST", "127.0.0.1")
    uvicorn.run(app, host=host, port=_listen_port())


if __name__ == "__main__":
    main()
