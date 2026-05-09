from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse, Response, RedirectResponse, FileResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path

from app.cache_assets import build_asset_map, make_asset_url

router = APIRouter()
APP_DIR = Path(__file__).parent.parent
templates = Jinja2Templates(directory=APP_DIR / "templates")

_asset_map = build_asset_map(APP_DIR / "static")
templates.env.globals["asset"] = lambda path: make_asset_url(_asset_map, path)

SITE_URL = "https://941ki.com"


@router.get("/robots.txt", response_class=PlainTextResponse)
async def robots_txt():
    """Welcome to all search engines and AI crawlers."""
    content = """# 941ki.com robots.txt
# Welcome to all search engines and AI crawlers

User-agent: *
Allow: /

# AI Context Files (per llmstxt.org specification)
# Summary: https://941ki.com/llms.txt
# Full: https://941ki.com/llms-full.txt

# Search Engines
User-agent: Googlebot
Allow: /

User-agent: Bingbot
Allow: /

User-agent: DuckDuckBot
Allow: /

User-agent: Slurp
Allow: /

User-agent: Baiduspider
Allow: /

User-agent: YandexBot
Allow: /

User-agent: Applebot
Allow: /

# AI Crawlers
User-agent: GPTBot
Allow: /

User-agent: ChatGPT-User
Allow: /

User-agent: Google-Extended
Allow: /

User-agent: ClaudeBot
Allow: /

User-agent: Claude-Web
Allow: /

User-agent: anthropic-ai
Allow: /

User-agent: PerplexityBot
Allow: /

User-agent: Bytespider
Allow: /

User-agent: CCBot
Allow: /

User-agent: cohere-ai
Allow: /

User-agent: meta-externalagent
Allow: /

User-agent: Amazonbot
Allow: /

User-agent: Applebot-Extended
Allow: /

Sitemap: https://941ki.com/sitemap.xml
"""
    return PlainTextResponse(content=content)


@router.get("/sitemap.xml")
async def sitemap():
    """Sitemap for search engines."""
    from datetime import datetime

    lastmod = datetime.now().strftime("%Y-%m-%d")

    sitemap_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <url>
        <loc>{SITE_URL}/</loc>
        <lastmod>{lastmod}</lastmod>
        <changefreq>weekly</changefreq>
        <priority>1.0</priority>
    </url>
    <url>
        <loc>{SITE_URL}/privacy</loc>
        <lastmod>{lastmod}</lastmod>
        <changefreq>monthly</changefreq>
        <priority>0.5</priority>
    </url>
    <url>
        <loc>{SITE_URL}/support</loc>
        <lastmod>{lastmod}</lastmod>
        <changefreq>monthly</changefreq>
        <priority>0.5</priority>
    </url>
</urlset>"""

    return Response(content=sitemap_xml, media_type="application/xml")


@router.get("/")
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@router.get("/privacy")
async def privacy(request: Request):
    return templates.TemplateResponse("privacy.html", {"request": request})


@router.get("/support")
async def support(request: Request):
    return templates.TemplateResponse("support.html", {"request": request})


@router.get("/llms.txt")
async def llms_txt():
    """AI context file per llmstxt.org specification."""
    static_file = APP_DIR / "static" / "llms.txt"
    return FileResponse(static_file, media_type="text/plain")


@router.get("/llms-full.txt")
async def llms_full_txt():
    """Extended AI context file."""
    static_file = APP_DIR / "static" / "llms-full.txt"
    return FileResponse(static_file, media_type="text/plain")


@router.get("/.well-known/llms.txt")
async def well_known_llms_txt():
    """Redirect .well-known/llms.txt to /llms.txt per spec."""
    return RedirectResponse(url="/llms.txt", status_code=301)


@router.get("/humans.txt", response_class=PlainTextResponse)
async def humans_txt():
    content = """/* TEAM */
Developer: Blake Crosley
Site: https://blakecrosley.com

/* COMPANY */
Name: 941 Apps, LLC
Site: https://941apps.com
Contact: blake@941apps.com

/* SITE */
Last update: 2026-05-08
Language: English
Standards: HTML5, CSS3
Platform: FastAPI, Jinja2, Bootstrap 5
Hosting: Railway
"""
    return PlainTextResponse(content=content.strip())


@router.get("/.well-known/security.txt", response_class=PlainTextResponse)
async def security_txt():
    content = """# Security Policy for Ki Browser
# https://941ki.com

Contact: mailto:blake@941apps.com
Expires: 2026-12-31T23:59:59.000Z
Preferred-Languages: en
Canonical: https://941ki.com/.well-known/security.txt

# Policy
# If you discover a security vulnerability in Ki, please report it
# responsibly to blake@941apps.com. We aim to respond within 48 hours.
"""
    return PlainTextResponse(content=content.strip())
