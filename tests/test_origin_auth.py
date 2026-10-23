"""Origin auth: the shared middleware is exercised on a bare Starlette app so the test needs no site config."""
from __future__ import annotations

from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from app.security.origin_auth import ENV_VAR, HEADER, OriginAuthMiddleware

BYPASS = "/health"


def _client(monkeypatch, secret: str | None) -> TestClient:
    if secret is None:
        monkeypatch.delenv(ENV_VAR, raising=False)
    else:
        monkeypatch.setenv(ENV_VAR, secret)

    async def ok(request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/", ok), Route(BYPASS, ok)])
    app.add_middleware(OriginAuthMiddleware, bypass_paths=(BYPASS,))
    return TestClient(app)


def test_missing_header_is_rejected_when_enforced(monkeypatch):
    assert _client(monkeypatch, "s3cret").get("/").status_code == 401


def test_wrong_header_is_rejected(monkeypatch):
    assert _client(monkeypatch, "s3cret").get("/", headers={HEADER: "nope"}).status_code == 401


def test_correct_header_passes(monkeypatch):
    assert _client(monkeypatch, "s3cret").get("/", headers={HEADER: "s3cret"}).status_code == 200


def test_health_bypasses_without_header(monkeypatch):
    assert _client(monkeypatch, "s3cret").get(BYPASS).status_code == 200


def test_unset_secret_means_open(monkeypatch):
    assert _client(monkeypatch, None).get("/").status_code == 200
