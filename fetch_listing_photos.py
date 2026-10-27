#!/usr/bin/env python3
"""Fetch public listing photos for an AST quote; never bypass access controls."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import socket
import sys
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright


MAX_BYTES = 25 * 1024 * 1024
IMAGE_TYPES = {
    "image/jpeg": (".jpg", b"\xff\xd8\xff"),
    "image/png": (".png", b"\x89PNG\r\n\x1a\n"),
    "image/gif": (".gif", b"GIF8"),
    "image/webp": (".webp", b"RIFF"),
    "image/avif": (".avif", b"\x00\x00\x00"),
    "image/heic": (".heic", b"\x00\x00\x00"),
}
DENIED_TEXT = re.compile(
    r"captcha|verify you are human|access denied|доступ ограничен|подтвердите,? что вы не робот",
    re.IGNORECASE,
)


def validate_public_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"Только публичные HTTP(S)-ссылки: {url}")
    if parsed.username or parsed.password:
        raise ValueError("Ссылки с логином или паролем запрещены")
    host = parsed.hostname.rstrip(".").lower()
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
        raise ValueError(f"Локальные адреса запрещены: {host}")
    try:
        addresses = {ipaddress.ip_address(host)}
    except ValueError:
        try:
            addresses = {
                ipaddress.ip_address(item[4][0])
                for item in socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80))
            }
        except OSError as exc:
            raise ValueError(f"Не удалось проверить адрес {host}: {exc}") from exc
    if not addresses or any(not address.is_global for address in addresses):
        raise ValueError(f"Непубличный IP-адрес запрещён: {host}")
    return url


class SafeRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_public_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def image_urls_from_page(page) -> list[dict]:
    return page.evaluate(
        """() => {
          const out = [];
          const add = (url, source, width = 0, height = 0) => {
            if (!url || /^(data:|blob:|javascript:)/i.test(url)) return;
            try { out.push({url: new URL(url, location.href).href, source, width, height}); } catch (_) {}
          };
          document.querySelectorAll('img').forEach(img => {
            const r = img.getBoundingClientRect();
            add(img.currentSrc || img.src, 'img', img.naturalWidth || r.width, img.naturalHeight || r.height);
            for (const name of ['data-src', 'data-original', 'data-lazy-src', 'data-image'])
              add(img.getAttribute(name), name, img.naturalWidth || r.width, img.naturalHeight || r.height);
            for (const s of (img.getAttribute('srcset') || '').split(',')) add(s.trim().split(/\\s+/)[0], 'srcset');
          });
          document.querySelectorAll('source[srcset]').forEach(el => {
            for (const s of el.getAttribute('srcset').split(',')) add(s.trim().split(/\\s+/)[0], 'source[srcset]');
          });
          document.querySelectorAll('meta[property="og:image"],meta[name="twitter:image"],meta[property="og:image:url"]').forEach(el => add(el.content, 'meta'));
          document.querySelectorAll('script[type="application/ld+json"]').forEach(el => {
            try {
              const walk = value => {
                if (!value) return;
                if (Array.isArray(value)) return value.forEach(walk);
                if (typeof value === 'object') {
                  const image = value.image;
                  if (typeof image === 'string') add(image, 'jsonld');
                  else if (Array.isArray(image)) image.forEach(x => add(typeof x === 'string' ? x : x?.url, 'jsonld'));
                  else if (image?.url) add(image.url, 'jsonld');
                  Object.values(value).forEach(walk);
                }
              };
              walk(JSON.parse(el.textContent));
            } catch (_) {}
          });
          document.querySelectorAll('[style*="background-image"]').forEach(el => {
            const r = el.getBoundingClientRect();
            if (r.width < 100 || r.height < 80) return;
            const m = getComputedStyle(el).backgroundImage.match(/url\\(["']?(.*?)["']?\\)/);
            if (m) add(m[1], 'background', r.width, r.height);
          });
          const seen = new Set();
          return out.filter(x => {
            if (x.width && x.height && (x.width < 100 || x.height < 80)) return false;
            if (seen.has(x.url)) return false;
            seen.add(x.url); return true;
          });
        }"""
    )


def download_image(url: str, timeout: float) -> tuple[bytes, str, str]:
    validate_public_url(url)
    request = Request(url, headers={"User-Agent": "AST-Quote-Photo-Importer/1.0", "Accept": "image/*"})
    opener = build_opener(SafeRedirectHandler())
    with opener.open(request, timeout=timeout) as response:
        final_url = validate_public_url(response.geturl())
        content_type = response.headers.get_content_type().lower()
        if content_type not in IMAGE_TYPES:
            raise ValueError(f"Источник вернул не поддерживаемое изображение ({content_type})")
        length = response.headers.get("Content-Length")
        if length and int(length) > MAX_BYTES:
            raise ValueError("Изображение превышает лимит 25 МБ")
        data = response.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise ValueError("Изображение превышает лимит 25 МБ")
        ext, signature = IMAGE_TYPES[content_type]
        if not data.startswith(signature):
            raise ValueError("Содержимое не совпадает с заявленным типом изображения")
        if content_type == "image/webp" and data[8:12] != b"WEBP":
            raise ValueError("Некорректный файл WebP")
        return data, ext, final_url


def main() -> int:
    parser = argparse.ArgumentParser(description="Загрузить доступные фотографии автомобиля из публичного объявления")
    parser.add_argument("url", help="Публичная ссылка на объявление")
    parser.add_argument("--out", type=Path, default=Path("listing-photos"), help="Каталог результата")
    parser.add_argument("--max-images", type=int, default=12, choices=range(1, 31), metavar="1..30")
    parser.add_argument("--timeout", type=float, default=20, help="Тайм-аут загрузки изображений, секунд")
    args = parser.parse_args()

    try:
        listing_url = validate_public_url(args.url)
        args.out.mkdir(parents=True, exist_ok=True)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=False)
            page = context.new_page()

            def guard(route):
                try:
                    validate_public_url(route.request.url)
                    route.continue_()
                except Exception:
                    route.abort()

            page.route("**/*", guard)
            try:
                page.goto(listing_url, wait_until="domcontentloaded", timeout=45000)
            except PlaywrightTimeoutError:
                if not page.url or page.url == "about:blank":
                    raise
            page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            page.wait_for_timeout(1500)
            page.evaluate("window.scrollTo(0, 0)")
            if DENIED_TEXT.search((page.title() + " " + page.locator("body").inner_text(timeout=5000))[:10000]):
                raise RuntimeError("Площадка запросила CAPTCHA, авторизацию или ограничила доступ. Обход не выполнялся; приложите фото вручную.")
            candidates = image_urls_from_page(page)
            browser.close()

        if not candidates:
            raise RuntimeError("Фотографии не найдены. Для динамической или закрытой галереи приложите фото вручную.")
        manifest = {
            "listing_url": listing_url,
            "retrieved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "identity_verified": False,
            "notice": "Проверьте вручную, что каждый снимок относится к нужному автомобилю.",
            "photos": [],
        }
        for i, candidate in enumerate(candidates[: args.max_images], start=1):
            try:
                data, ext, final_url = download_image(candidate["url"], args.timeout)
                digest = hashlib.sha256(data).hexdigest()
                name = f"{i:02d}-{digest[:10]}{ext}"
                (args.out / name).write_bytes(data)
                manifest["photos"].append(
                    {
                        "file": name,
                        "source_url": final_url,
                        "discovered_by": candidate["source"],
                        "bytes": len(data),
                        "sha256": digest,
                    }
                )
            except Exception as exc:
                print(f"Пропущено фото {candidate['url']}: {exc}", file=sys.stderr)
        (args.out / "photos.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        if not manifest["photos"]:
            raise RuntimeError("Не удалось скачать ни одного изображения; приложите фото вручную.")
        print(f"Скачано фотографий: {len(manifest['photos'])}. Каталог: {args.out.resolve()}")
        print("Перед использованием в КП проверьте принадлежность каждого фото автомобилю.")
        print(f"Источники и контрольные суммы: {(args.out / 'photos.json').resolve()}")
        return 0
    except Exception as exc:
        print(f"Импорт остановлен: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
