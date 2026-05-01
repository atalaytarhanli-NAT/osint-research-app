from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Optional


@dataclass
class SourceResult:
    """A single piece of evidence collected from an OSINT source."""

    source: str
    url: str
    title: str = ""
    snippet: str = ""
    published_at: Optional[str] = None  # ISO date string if known
    confidence: float = 0.5  # 0.0–1.0
    raw: dict[str, Any] = field(default_factory=dict)
    kind: str = "web"  # web/news/social/archive/code/wiki/profile

    def to_dict(self) -> dict:
        return asdict(self)


def safe_truncate(text: str, limit: int = 280) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"
