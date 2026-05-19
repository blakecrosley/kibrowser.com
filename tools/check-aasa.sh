#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${KI_AASA_BASE_URL:-https://941ki.com}"
EXPECTED_APP_ID="${KI_AASA_APP_ID:-M4WTLM6RAQ.com.941apps.Ki}"
PATHS=(
  "/.well-known/apple-app-site-association"
  "/apple-app-site-association"
)
TEST_PAGE_PATH="/apple-passwords-test"

failures=0
tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

pass() {
  printf 'PASS %s\n' "$*"
}

fail() {
  printf 'FAIL %s\n' "$*"
  failures=1
}

check_path() {
  local path="$1"
  local url="${BASE_URL%/}${path}"
  local headers="${tmpdir}/headers-${path//\//_}"
  local body="${tmpdir}/body-${path//\//_}.json"
  local status

  status="$(curl -sS -D "${headers}" -o "${body}" -w '%{http_code}' "${url}" || true)"
  if [[ -z "${status}" || "${status}" == "000" ]]; then
    fail "${url} could not be fetched"
    return
  fi
  if [[ "${status}" == "200" ]]; then
    pass "${url} returned HTTP 200"
  else
    fail "${url} returned HTTP ${status}"
    return
  fi

  if awk 'tolower($1) == "content-type:" {print tolower($0)}' "${headers}" |
    tail -n 1 |
    grep -q 'application/json'; then
    pass "${url} uses application/json"
  else
    fail "${url} is not application/json"
  fi

  if /usr/bin/python3 - "${body}" "${EXPECTED_APP_ID}" <<'PY'
import json
import sys

path, expected = sys.argv[1], sys.argv[2]
with open(path, "r", encoding="utf-8") as handle:
    data = json.load(handle)
apps = data.get("webcredentials", {}).get("apps", [])
if expected not in apps:
    raise SystemExit(1)
PY
  then
    pass "${url} webcredentials includes ${EXPECTED_APP_ID}"
  else
    fail "${url} webcredentials does not include ${EXPECTED_APP_ID}"
  fi
}

for path in "${PATHS[@]}"; do
  check_path "${path}"
done

test_page_url="${BASE_URL%/}${TEST_PAGE_PATH}"
test_page_body="${tmpdir}/apple-passwords-test.html"
test_page_status="$(curl -sS -o "${test_page_body}" -w '%{http_code}' "${test_page_url}" || true)"
if [[ "${test_page_status}" == "200" ]]; then
  pass "${test_page_url} returned HTTP 200"
else
  fail "${test_page_url} returned HTTP ${test_page_status:-000}"
fi

if grep -q '<meta name="robots" content="noindex, nofollow">' "${test_page_body}" &&
  grep -q 'autocomplete="username"' "${test_page_body}" &&
  grep -q 'autocomplete="current-password"' "${test_page_body}"; then
  pass "${test_page_url} exposes noindex Apple Passwords test form"
else
  fail "${test_page_url} does not expose the expected noindex test form"
fi

if [[ "${failures}" == 0 ]]; then
  printf 'Apple app site association and password test page are ready at %s.\n' "${BASE_URL}"
else
  printf 'Apple app site association or password test page is not ready at %s.\n' "${BASE_URL}"
fi
exit "${failures}"
