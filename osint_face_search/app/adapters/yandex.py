"""Yandex Images reverse search adaptörü (scraper).

Resmi public API yok. Playwright ile headless Chromium kullanarak
Yandex'in reverse image search özelliğini taklit eder.

UYARI:
- Yandex'in TOS'una göre otomasyon kısıtlanmış olabilir
- Sık kullanımda CAPTCHA çıkar; proxy/residential IP gerekebilir
- Yapı kırılgandır — Yandex UI değişirse adaptör bozulur
- Veri lokasyonu: Rusya — KVKK için yurt dışı aktarım, KVK Kurulu yeterli
  koruma kararı bulunan ülkeler arasında DEĞİL. Hukuki risk yüksek.

Kurulum: pip install playwright && playwright install chromium
"""
from __future__ import annotations

import time
import asyncio
from urllib.parse import urlparse

from app.adapters.base import (
    FaceSearchAdapter, AdapterResponse, ExternalMatch,
    MatchConfidence, AdapterTier, AdapterCategory,
)


class YandexImagesAdapter(FaceSearchAdapter):
    name = "yandex"
    tier = AdapterTier.TIER_3_SCRAPER
    category = AdapterCategory.REVERSE_IMAGE
    requires_api_key = False
    data_residency = "RU"

    SEARCH_URL = "https://yandex.com/images/search?rpt=imageview"

    def __init__(self, api_key: str | None = None) -> None:
        super().__init__(api_key)
        self._enabled = True   # API key gerekmez

    async def search(
        self,
        image_bytes: bytes,
        max_results: int = 20,
        **kwargs,
    ) -> AdapterResponse:
        started = time.time()
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return AdapterResponse(
                source=self.name, success=False,
                error="playwright kurulu değil — `pip install playwright && playwright install chromium`",
            )

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,
                    args=["--disable-blink-features=AutomationControlled"],
                )
                context = await browser.new_context(
                    user_agent=(
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/130.0.0.0 Safari/537.36"
                    ),
                    locale="en-US",
                )
                page = await context.new_page()

                # Yandex Images ana sayfasına git
                await page.goto("https://yandex.com/images/", timeout=30000)

                # Reverse search butonuna tıkla (kamera ikonu)
                await page.click("button[aria-label*='image']", timeout=10000)

                # Dosyayı yükle (file input genelde gizli)
                async with page.expect_file_chooser() as fc_info:
                    await page.click("text=/Select.*file/i")
                file_chooser = await fc_info.value
                # Geçici dosya yaz
                import tempfile
                with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as tmp:
                    tmp.write(image_bytes)
                    tmp_path = tmp.name
                await file_chooser.set_files(tmp_path)

                # Sonuçların yüklenmesini bekle
                await page.wait_for_selector(".CbirSites-Item", timeout=20000)
                await asyncio.sleep(2)

                # Sonuçları DOM'dan parse et
                items = await page.query_selector_all(".CbirSites-Item")
                matches: list[ExternalMatch] = []
                for item in items[:max_results]:
                    title_el = await item.query_selector(".CbirSites-ItemTitle")
                    link_el = await item.query_selector("a")
                    if not link_el:
                        continue
                    url = await link_el.get_attribute("href") or ""
                    title = await title_el.inner_text() if title_el else None
                    matches.append(
                        ExternalMatch(
                            source=self.name,
                            url=url,
                            score=70,   # Yandex skor vermez
                            confidence=MatchConfidence.UNCERTAIN,
                            title=title,
                            domain=urlparse(url).netloc if url else None,
                            raw={"title": title, "url": url},
                        )
                    )

                await browser.close()

                return AdapterResponse(
                    source=self.name, success=True,
                    matches=matches,
                    elapsed_ms=int((time.time() - started) * 1000),
                )

        except Exception as e:
            return AdapterResponse(
                source=self.name, success=False,
                error=f"Yandex scraper hatası: {e}",
                elapsed_ms=int((time.time() - started) * 1000),
            )
