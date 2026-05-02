"""LLM provider abstraction.

Tüm sağlayıcılar tek bir async fonksiyon üzerinden çağrılır:
    `await call_llm(provider_id, api_key, model, system, user) -> str`

Açık kaynak / ücretsiz tier öncelikli sıra: Groq, HuggingFace, OpenRouter, Google,
sonra ticari (Anthropic, OpenAI). Hiçbiri yoksa rapor sentezi `analyzer.py` içinde
kuralsal modda üretilir."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

import httpx


log = logging.getLogger("llm")


@dataclass
class ProviderSpec:
    id: str
    name: str
    open_source: bool  # the *models* the provider hosts are open source by default
    free_tier: bool
    default_model: str
    models: list[str]
    docs_url: str
    key_hint: str
    base_url: str
    style: str  # "openai" | "anthropic" | "gemini" | "hf" | "search"
    kind: str = "llm"  # "llm" | "search"


PROVIDERS: dict[str, ProviderSpec] = {
    "groq": ProviderSpec(
        id="groq",
        name="Groq Cloud",
        open_source=True,
        free_tier=True,
        default_model="llama-3.3-70b-versatile",
        models=[
            "llama-3.3-70b-versatile",
            "llama-3.1-8b-instant",
            "mixtral-8x7b-32768",
            "gemma2-9b-it",
            "deepseek-r1-distill-llama-70b",
        ],
        docs_url="https://console.groq.com/keys",
        key_hint="gsk_…",
        base_url="https://api.groq.com/openai/v1",
        style="openai",
    ),
    "huggingface": ProviderSpec(
        id="huggingface",
        name="HuggingFace Inference",
        open_source=True,
        free_tier=True,
        default_model="meta-llama/Llama-3.3-70B-Instruct",
        models=[
            "meta-llama/Llama-3.3-70B-Instruct",
            "Qwen/Qwen2.5-72B-Instruct",
            "deepseek-ai/DeepSeek-V3",
            "mistralai/Mistral-7B-Instruct-v0.3",
        ],
        docs_url="https://huggingface.co/settings/tokens",
        key_hint="hf_…",
        base_url="https://router.huggingface.co/v1",
        style="openai",
    ),
    "openrouter": ProviderSpec(
        id="openrouter",
        name="OpenRouter",
        open_source=True,
        free_tier=True,
        default_model="meta-llama/llama-3.3-70b-instruct:free",
        models=[
            "meta-llama/llama-3.3-70b-instruct:free",
            "qwen/qwen-2.5-72b-instruct:free",
            "deepseek/deepseek-r1:free",
            "google/gemini-2.0-flash-exp:free",
        ],
        docs_url="https://openrouter.ai/keys",
        key_hint="sk-or-…",
        base_url="https://openrouter.ai/api/v1",
        style="openai",
    ),
    "google": ProviderSpec(
        id="google",
        name="Google Gemini",
        open_source=False,
        free_tier=True,
        default_model="gemini-2.0-flash-exp",
        models=["gemini-2.0-flash-exp", "gemini-1.5-flash", "gemini-1.5-pro"],
        docs_url="https://aistudio.google.com/apikey",
        key_hint="AIza…",
        base_url="https://generativelanguage.googleapis.com/v1beta",
        style="gemini",
    ),
    "anthropic": ProviderSpec(
        id="anthropic",
        name="Anthropic Claude",
        open_source=False,
        free_tier=False,
        default_model="claude-haiku-4-5-20251001",
        models=[
            "claude-haiku-4-5-20251001",
            "claude-sonnet-4-6",
            "claude-opus-4-7",
        ],
        docs_url="https://console.anthropic.com/settings/keys",
        key_hint="sk-ant-…",
        base_url="https://api.anthropic.com/v1",
        style="anthropic",
    ),
    "openai": ProviderSpec(
        id="openai",
        name="OpenAI",
        open_source=False,
        free_tier=False,
        default_model="gpt-4o-mini",
        models=["gpt-4o-mini", "gpt-4o", "o1-mini"],
        docs_url="https://platform.openai.com/api-keys",
        key_hint="sk-…",
        base_url="https://api.openai.com/v1",
        style="openai",
    ),
    # ---- Search engines (kind="search") ----
    # LLM seçim listesinde gözükmez ama admin sistem-key'lerinde yönetilebilir.
    "brave": ProviderSpec(
        id="brave",
        name="Brave Search",
        open_source=False,
        free_tier=True,
        default_model="",
        models=[],
        docs_url="https://brave.com/search/api/",
        key_hint="BSA…",
        base_url="https://api.search.brave.com/res/v1",
        style="search",
        kind="search",
    ),
    "tavily": ProviderSpec(
        id="tavily",
        name="Tavily",
        open_source=False,
        free_tier=True,
        default_model="",
        models=[],
        docs_url="https://app.tavily.com/",
        key_hint="tvly-…",
        base_url="https://api.tavily.com",
        style="search",
        kind="search",
    ),
    "serper": ProviderSpec(
        id="serper",
        name="Serper.dev (Google)",
        open_source=False,
        free_tier=True,
        default_model="",
        models=[],
        docs_url="https://serper.dev/",
        key_hint="…",
        base_url="https://google.serper.dev",
        style="search",
        kind="search",
    ),
}


def llm_providers() -> list[ProviderSpec]:
    return [p for p in PROVIDERS.values() if p.kind == "llm"]


def search_providers() -> list[ProviderSpec]:
    return [p for p in PROVIDERS.values() if p.kind == "search"]


def default_model_for(provider_id: str) -> str:
    p = PROVIDERS.get(provider_id)
    return p.default_model if p else ""


async def call_llm(
    provider_id: str,
    api_key: str,
    model: str | None,
    system: str,
    user: str,
    max_tokens: int = 2200,
) -> str:
    spec = PROVIDERS.get(provider_id)
    if spec is None:
        raise ValueError(f"Unknown provider {provider_id}")
    model = model or spec.default_model

    if spec.style == "openai":
        return await _call_openai_compat(spec, api_key, model, system, user, max_tokens)
    if spec.style == "anthropic":
        return await _call_anthropic(spec, api_key, model, system, user, max_tokens)
    if spec.style == "gemini":
        return await _call_gemini(spec, api_key, model, system, user, max_tokens)
    raise ValueError(f"Unsupported style: {spec.style}")


async def _call_openai_compat(
    spec: ProviderSpec, api_key: str, model: str, system: str, user: str, max_tokens: int
) -> str:
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "max_tokens": max_tokens,
        "temperature": 0.4,
    }
    async with httpx.AsyncClient(timeout=60.0) as c:
        r = await c.post(f"{spec.base_url}/chat/completions", headers=headers, json=body)
        r.raise_for_status()
        data = r.json()
        return data["choices"][0]["message"]["content"]


async def _call_anthropic(
    spec: ProviderSpec, api_key: str, model: str, system: str, user: str, max_tokens: int
) -> str:
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    body = {
        "model": model,
        "max_tokens": max_tokens,
        "system": system,
        "messages": [{"role": "user", "content": user}],
    }
    async with httpx.AsyncClient(timeout=60.0) as c:
        r = await c.post(f"{spec.base_url}/messages", headers=headers, json=body)
        r.raise_for_status()
        data = r.json()
        parts = data.get("content", [])
        return "".join(p.get("text", "") for p in parts if p.get("type") == "text")


async def _call_gemini(
    spec: ProviderSpec, api_key: str, model: str, system: str, user: str, max_tokens: int
) -> str:
    url = f"{spec.base_url}/models/{model}:generateContent?key={api_key}"
    body = {
        "system_instruction": {"parts": [{"text": system}]},
        "contents": [{"role": "user", "parts": [{"text": user}]}],
        "generationConfig": {"maxOutputTokens": max_tokens, "temperature": 0.4},
    }
    async with httpx.AsyncClient(timeout=60.0) as c:
        r = await c.post(url, headers={"Content-Type": "application/json"}, json=body)
        r.raise_for_status()
        data = r.json()
        candidates = data.get("candidates", [])
        if not candidates:
            return ""
        parts = candidates[0].get("content", {}).get("parts", [])
        return "".join(p.get("text", "") for p in parts)
