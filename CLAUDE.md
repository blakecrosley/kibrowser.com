# Ki Browser — Marketing Site

Marketing + privacy/support site for Ki, a private web browser for iPhone. Sibling project to the iOS app at `~/Projects/Shikigami`.

## Stack

- FastAPI (Python 3.11+)
- HTMX + Alpine.js + Bootstrap 5
- Jinja2 templates
- Plain CSS (no Tailwind, no Sass)
- Railway deployment via GitHub
- Cloudflare DNS

## Routes

- `/` — landing page (hero + features + CTA)
- `/privacy` — Privacy Policy (mirrors `~/Projects/Shikigami/AppStore/policy/privacy-policy.md`)
- `/support` — Support page (mirrors `~/Projects/Shikigami/AppStore/policy/support.md`)
- `/llms.txt`, `/llms-full.txt` — AIO context files
- `/robots.txt`, `/sitemap.xml`, `/humans.txt`, `/.well-known/security.txt`

## Commands

- `./run.sh` — start dev server on port 8300
- `pip install -r requirements.txt` — install dependencies

## Deployment

- Platform: Railway (git-push deploy from `main`)
- Config: `railway.toml`, `Procfile`
- DNS: Cloudflare CNAME → Railway custom domain target

## Related Projects

- `~/Projects/Shikigami/` — Ki iOS app (Swift, SwiftUI, WKWebView)
- `~/Projects/Shikigami/AppStore/policy/` — source of truth for privacy/support content
- `~/Projects/941return.com/` — sibling site (same template lineage)
- `~/Projects/941getbananas.com/` — sibling site (this project's structural parent)

## Source-of-truth rule

If `AppStore/policy/privacy-policy.md` or `support.md` change in the Shikigami repo, mirror the changes here in `app/templates/privacy.html` and `support.html`. The on-device app uses URLs at this domain; reviewer-checked URLs and the live page must match what App Privacy declares.
