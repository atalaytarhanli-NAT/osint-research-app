from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

import os

from ..auth import get_current_user
from ..crypto import decrypt
from ..database import SessionLocal, get_db
from ..llm.analyzer import build_report
from ..llm.intelligence_brief import build_intelligence_brief
from ..llm.providers import PROVIDERS
from ..models import ApiKey, ResearchJob, SystemApiKey, User
from ..osint.pipeline import run_pipeline


log = logging.getLogger("research")

router = APIRouter(prefix="/api/research", tags=["research"])


class StartIn(BaseModel):
    target: str = Field(min_length=2, max_length=500)
    kind: str = Field(default="auto")  # auto/person/organization/url/keyword/social
    intensity: str = Field(default="deep")  # quick | deep (2-pass)
    scope: str = Field(default="all")  # web | social | all
    provider: Optional[str] = None
    model: Optional[str] = None
    options: dict = Field(default_factory=dict)


class JobOut(BaseModel):
    id: int
    target: str
    kind: str
    intensity: Optional[str] = None
    scope: Optional[str] = None
    status: str
    used_llm: Optional[str]
    created_at: datetime
    finished_at: Optional[datetime]


class JobDetailOut(JobOut):
    result: Optional[dict] = None
    error: Optional[str] = None


def _serialize(job: ResearchJob) -> JobDetailOut:
    return JobDetailOut(
        id=job.id,
        target=job.target,
        kind=job.kind,
        status=job.status,
        used_llm=job.used_llm,
        created_at=job.created_at,
        finished_at=job.finished_at,
        result=json.loads(job.result_json) if job.result_json else None,
        error=job.error,
    )


def _select_provider(user_id: int, requested: Optional[str], db: Session):
    """Return (provider_id, key, model) for LLM, or (None, None, None) for rule-based.

    Order: user's requested → user's keys (preference order) → system-wide admin
    keys (preference order). Open-source / free providers preferred."""
    user_keys = {
        k.provider: (decrypt(k.encrypted_value), k.model)
        for k in db.scalars(select(ApiKey).where(ApiKey.user_id == user_id)).all()
    }
    sys_keys_rows = db.scalars(
        select(SystemApiKey).where(SystemApiKey.enabled == True)  # noqa
    ).all()
    sys_keys = {r.provider: (decrypt(r.encrypted_value), r.model) for r in sys_keys_rows}

    def pick(provider: str):
        # Search engines (brave) shouldn't be picked as LLM
        spec = PROVIDERS.get(provider)
        if spec and getattr(spec, "kind", "llm") == "search":
            return None
        if provider in user_keys and user_keys[provider][0]:
            p, m = user_keys[provider]
            return provider, p, m
        if provider in sys_keys and sys_keys[provider][0]:
            p, m = sys_keys[provider]
            return provider, p, m
        return None

    if requested:
        result = pick(requested)
        if result:
            return result

    preference = ["groq", "huggingface", "openrouter", "google", "anthropic", "openai"]
    for pid in preference:
        result = pick(pid)
        if result:
            return result
    return None, None, None


def _get_search_key(user_id: int, provider: str, db: Session) -> str:
    """Get a search engine API key. Order: user's key → system key → env var."""
    uk = db.scalar(
        select(ApiKey).where(ApiKey.user_id == user_id, ApiKey.provider == provider)
    )
    if uk:
        plain = decrypt(uk.encrypted_value)
        if plain:
            return plain
    sk = db.scalar(
        select(SystemApiKey).where(SystemApiKey.provider == provider, SystemApiKey.enabled == True)  # noqa
    )
    if sk:
        plain = decrypt(sk.encrypted_value)
        if plain:
            return plain
    return os.environ.get(f"APP_{provider.upper()}_API_KEY", "") or ""


def _run_job(job_id: int) -> None:
    db = SessionLocal()
    try:
        job = db.get(ResearchJob, job_id)
        if job is None:
            return
        job.status = "running"
        db.commit()

        provider_id, key, model = _select_provider(job.user_id, job.used_llm, db)
        search_keys = {
            "brave": _get_search_key(job.user_id, "brave", db),
            "tavily": _get_search_key(job.user_id, "tavily", db),
            "serper": _get_search_key(job.user_id, "serper", db),
        }
        try:
            sources = asyncio.run(
                run_pipeline(
                    job.target,
                    job.kind,
                    intensity=job.intensity or "deep",
                    scope=job.scope or "all",
                    search_keys=search_keys,
                )
            )
            report = asyncio.run(
                build_report(
                    target=job.target,
                    kind=job.kind,
                    sources=sources,
                    provider_id=provider_id,
                    api_key=key,
                    model=model,
                )
            )
            # NATO/IC standardı kapsamlı Markdown brief — yapılandırılmış JSON
            # raporun YANINDA, LLM varsa üretilir, UI'da ayrı bölümde gösterilir.
            intelligence_brief = asyncio.run(
                build_intelligence_brief(
                    target=job.target,
                    kind=job.kind,
                    scope=job.scope or "all",
                    intensity=job.intensity or "deep",
                    sources=sources,
                    provider_id=provider_id,
                    api_key=key,
                    model=model,
                )
            )
            job.result_json = json.dumps(
                {
                    "sources": sources,
                    "report": report,
                    "intelligence_brief": intelligence_brief,
                },
                ensure_ascii=False,
                default=str,
            )
            job.used_llm = report.get("used_llm") or "rule-based"
            job.status = "done"
        except Exception as exc:  # pragma: no cover
            log.exception("Research job failed")
            job.status = "error"
            job.error = str(exc)[:2000]
        finally:
            job.finished_at = datetime.now(timezone.utc)
            db.commit()
    finally:
        db.close()


@router.post("", response_model=JobOut)
def start_research(
    data: StartIn,
    background: BackgroundTasks,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if data.provider and data.provider not in PROVIDERS:
        raise HTTPException(status_code=400, detail="Unknown provider")
    job = ResearchJob(
        user_id=user.id,
        target=data.target.strip(),
        kind=data.kind,
        intensity=data.intensity if data.intensity in ("quick", "deep") else "deep",
        scope=data.scope if data.scope in ("web", "social", "all") else "all",
        status="pending",
        used_llm=data.provider,
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    background.add_task(_run_job, job.id)

    return JobOut(
        id=job.id,
        target=job.target,
        kind=job.kind,
        intensity=job.intensity,
        scope=job.scope,
        status=job.status,
        used_llm=job.used_llm,
        created_at=job.created_at,
        finished_at=job.finished_at,
    )


@router.get("", response_model=list[JobOut])
def list_jobs(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    limit: int = 50,
):
    rows = db.scalars(
        select(ResearchJob)
        .where(ResearchJob.user_id == user.id)
        .order_by(desc(ResearchJob.created_at))
        .limit(limit)
    ).all()
    return [
        JobOut(
            id=r.id,
            target=r.target,
            kind=r.kind,
            intensity=r.intensity,
            scope=r.scope,
            status=r.status,
            used_llm=r.used_llm,
            created_at=r.created_at,
            finished_at=r.finished_at,
        )
        for r in rows
    ]


@router.get("/{job_id}", response_model=JobDetailOut)
def get_job(
    job_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    job = db.get(ResearchJob, job_id)
    if job is None or job.user_id != user.id:
        raise HTTPException(status_code=404, detail="Job not found")
    return _serialize(job)


@router.delete("/{job_id}", status_code=204)
def delete_job(
    job_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    job = db.get(ResearchJob, job_id)
    if job is None or job.user_id != user.id:
        raise HTTPException(status_code=404, detail="Job not found")
    db.delete(job)
    db.commit()
