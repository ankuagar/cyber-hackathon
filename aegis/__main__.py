from aegis.main import app

import uvicorn


def main() -> None:
    uvicorn.run(app, host="127.0.0.1", port=8787)


if __name__ == "__main__":
    main()
