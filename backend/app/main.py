from __future__ import annotations

import logging
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .api import admin as admin_api
from .api import auth as auth_api
from .api import research as research_api
from .api import settings as settings_api
from .auth import get_optional_user
from .config import get_settings
from .database import init_db
from .llm.providers import PROVIDERS


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

settings = get_settings()
APP_DIR = Path(__file__).resolve().parent

app = FastAPI(title="OSINT Research App", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.cors_origins] if settings.cors_origins != "*" else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=str(APP_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(APP_DIR / "templates"))

app.include_router(auth_api.router)
app.include_router(settings_api.router)
app.include_router(research_api.router)
app.include_router(admin_api.router)


@app.on_event("startup")
def _startup():
    init_db()


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def home(request: Request, user=Depends(get_optional_user)):
    if user is None:
        return templates.TemplateResponse(
            "index.html", {"request": request, "user": None}
        )
    return RedirectResponse(url="/dashboard", status_code=302)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse(
        "register.html",
        {"request": request, "registration_open": settings.allow_registration},
    )


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard_page(request: Request, user=Depends(get_optional_user)):
    if user is None:
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "user": user, "providers": list(PROVIDERS.values())},
    )


@app.get("/research/{job_id}", response_class=HTMLResponse)
def research_page(job_id: int, request: Request, user=Depends(get_optional_user)):
    if user is None:
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse(
        "report.html", {"request": request, "user": user, "job_id": job_id}
    )


@app.get("/history", response_class=HTMLResponse)
def history_page(request: Request, user=Depends(get_optional_user)):
    if user is None:
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse("history.html", {"request": request, "user": user})


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, user=Depends(get_optional_user)):
    if user is None:
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse(
        "settings.html",
        {"request": request, "user": user, "providers": list(PROVIDERS.values())},
    )


@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request, user=Depends(get_optional_user)):
    if user is None:
        return RedirectResponse(url="/login", status_code=302)
    if not user.is_admin:
        return RedirectResponse(url="/dashboard", status_code=302)
    return templates.TemplateResponse(
        "admin.html",
        {"request": request, "user": user, "providers": list(PROVIDERS.values())},
    )
