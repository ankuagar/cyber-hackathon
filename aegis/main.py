from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from aegis import engine as engine_mod
from aegis.engine import EngineError

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "web"

app = FastAPI(title="Aegis")


class TargetRequest(BaseModel):
    id: str


def _run(method: str):
    try:
        return getattr(engine_mod.engine, method)()
    except EngineError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/state")
def get_state():
    return engine_mod.engine.state()


@app.post("/api/scan")
def scan():
    return _run("scan")


@app.post("/api/remediate")
def remediate():
    return _run("remediate")


@app.post("/api/inject")
def inject():
    return _run("inject")


@app.post("/api/check")
def check():
    return _run("check")


@app.post("/api/audit")
def audit():
    return _run("audit")


@app.post("/api/reset")
def reset():
    return _run("reset")


@app.post("/api/target")
def select_target(body: TargetRequest):
    try:
        return engine_mod.engine.select(body.id)
    except EngineError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


app.mount("/", StaticFiles(directory=WEB, html=True), name="web")
