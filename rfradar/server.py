"""The local web dashboard: a tiny FastAPI app over the engine.

It binds to 127.0.0.1 only — the dashboard is for you, on this laptop, and is
never reachable from the network you're sitting on.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .engine import Engine

WEB = Path(__file__).parent / "web"


class Mine(BaseModel):
    mine: bool


class Label(BaseModel):
    label: str


class Trust(BaseModel):
    ssid: str


def create_app(engine: Engine) -> FastAPI:
    app = FastAPI(title="RF Radar", docs_url=None, redoc_url=None)

    @app.get("/")
    def index():
        return FileResponse(WEB / "index.html")

    @app.get("/api/state")
    def state():
        return engine.snapshot()

    @app.post("/api/devices/{kind}/{mac}/mine")
    def mine(kind: str, mac: str, body: Mine):
        if not engine.set_mine(f"{kind}/{mac.lower()}", body.mine):
            raise HTTPException(404, "unknown device")
        return {"ok": True}

    @app.post("/api/places/{place_id}/label")
    def label(place_id: int, body: Label):
        if not engine.label_place(place_id, body.label):
            raise HTTPException(404, "unknown place")
        return {"ok": True}

    @app.post("/api/trust")
    def trust(body: Trust):
        return {"ok": True, "bssids": engine.trust_ssid(body.ssid)}

    @app.post("/api/alerts/{key:path}/dismiss")
    def dismiss(key: str):
        engine.dismiss(key)
        return {"ok": True}

    app.mount("/static", StaticFiles(directory=WEB), name="static")
    return app
