#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${KI_AASA_BASE_URL:-https://941ki.com}"
EXPECTED_APP_ID="${KI_AASA_APP_ID:-M4WTLM6RAQ.com.941apps.Ki}"
PATHS=(
  "/.well-known/apple-app-site-association"
  "/apple-app-site-association"
)

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

if [[ "${failures}" == 0 ]]; then
  printf 'Apple app site association is ready at %s.\n' "${BASE_URL}"
else
  printf 'Apple app site association is not ready at %s.\n' "${BASE_URL}"
fi
exit "${failures}"
