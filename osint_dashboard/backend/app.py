from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from backend.osint.web_osint import analyze_domain
from backend.osint.username_osint import analyze_username
from backend.osint.email_osint import analyze_email
from backend.osint.phone_osint import analyze_phone
from backend.osint.ai_osint import analyze_intel, ai_backend_status

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"

app = FastAPI(title="OSINT Dashboard", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class WebReq(BaseModel):
    target: str


class UserReq(BaseModel):
    username: str


class EmailReq(BaseModel):
    email: str


class PhoneReq(BaseModel):
    number: str
    region: str | None = None


class AiReq(BaseModel):
    data: str
    prompt: str | None = None
    web: bool | None = None


@app.post("/api/web")
async def api_web(req: WebReq):
    return await analyze_domain(req.target)


@app.post("/api/username")
async def api_username(req: UserReq):
    return await analyze_username(req.username)


@app.post("/api/email")
async def api_email(req: EmailReq):
    return await analyze_email(req.email)


@app.post("/api/phone")
async def api_phone(req: PhoneReq):
    return analyze_phone(req.number, req.region)


@app.post("/api/ai")
async def api_ai(req: AiReq):
    return await analyze_intel(req.data, req.prompt, req.web)


@app.get("/api/ai/status")
async def api_ai_status():
    return await ai_backend_status()


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "osint-dashboard"}


@app.get("/")
async def index():
    return FileResponse(FRONTEND_DIR / "index.html")


app.mount("/", StaticFiles(directory=FRONTEND_DIR), name="static")
