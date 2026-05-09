from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path
from starlette.middleware.base import BaseHTTPMiddleware

from app.routes import pages
from app.security.headers import SecurityHeadersMiddleware
from app.security.logging import SecurityLogMiddleware
from app.security.rate_limit import RateLimitMiddleware
from app.cache_assets import build_asset_map, make_asset_url


class HeadRequestMiddleware(BaseHTTPMiddleware):
    """Convert HEAD requests to GET internally and strip the body so SEO
    crawlers like Googlebot and Bingbot get a 200 instead of 405."""

    async def dispatch(self, request, call_next):
        if request.method == "HEAD":
            request.scope["method"] = "GET"
            response = await call_next(request)
            response.body = b""
            return response
        return await call_next(request)


app = FastAPI(
    title="Ki Browser",
    description="A private web browser for iPhone.",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(HeadRequestMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(SecurityLogMiddleware, site_name="kibrowser.com")

app.mount(
    "/static",
    StaticFiles(directory=Path(__file__).parent / "static"),
    name="static",
)

templates = Jinja2Templates(directory=Path(__file__).parent / "templates")

_static_dir = Path(__file__).parent / "static"
_asset_map = build_asset_map(_static_dir)
templates.env.globals["asset"] = lambda path: make_asset_url(_asset_map, path)

app.state.preload_links = [
    f'<{make_asset_url(_asset_map, "css/custom.css")}>; rel=preload; as=style',
]

app.include_router(pages.router)
