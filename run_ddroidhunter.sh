#!/usr/bin/env bash
# D-DroidHunter runner with MobSF Docker (API key aware)
# Usage:
#   ./run_ddroidhunter.sh -v <VT_API_KEY> [-m <MOBSF_API_KEY>] [-p 8000] [-n mobsf_droidhunter] [--no-pull]

set -Eeuo pipefail

# Defaults
PORT="${PORT:-8000}"
CONTAINER_NAME="${CONTAINER_NAME:-mobsf_ddroidhunter}"
IMAGE="opensecurity/mobile-security-framework-mobsf:latest"
MOBSF_DATA_DIR="${MOBSF_DATA_DIR:-$PWD/.mobsf_data}"   # persisted MobSF home
DO_PULL=1
DATA_DIR="${PWD}/data"
JSON_DIR="${DATA_DIR}/json_reports"
PDFS_DIR="${DATA_DIR}/pdfs_reports"
SAMPLES_DIR="${DATA_DIR}/samples"
DB_DIR="${DATA_DIR}/database"

usage(){
  cat <<EOF
Usage: $0 -v <VT_API_KEY> [-m <MOBSF_API_KEY>] [-p <port>] [-n <container_name>] [--no-pull]
If -m is omitted, a secure key is generated and injected via MOBSF_API_KEY.
EOF
}

die(){ echo "[-] $*" >&2; exit 1; }
note(){ echo "[*] $*"; }
ok(){ echo "[+] $*"; }

# Create Directories
mkd() {
    local rc=0 d
    for d in "$@"; do
        if [ -e "$d" ] && [ ! -d "$d" ]; then
            printf 'error: "%s" exists and is not a directory.\n' "$d" >&2
            rc=1
            continue
        fi
        if ! mkdir -p -- "$d"; then
            printf 'error: failed to create "%s"\n' "$d" >&2
            rc=1
        fi
    done
    return "$rc"
}

# Cleanup on exit
cleanup(){
  if docker ps --format '{{.Names}}' | grep -qx "$CONTAINER_NAME"; then
    note "Stopping container '$CONTAINER_NAME'…"
    docker stop "$CONTAINER_NAME" >/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

mkd $DATA_DIR $JSON_DIR $PDFS_DIR $SAMPLES_DIR $DB_DIR

VT_KEY=""
MOBSF_KEY=""
while (( "$#" )); do
  case "$1" in
    -v) VT_KEY="${2:-}"; shift 2;;
    -m) MOBSF_KEY="${2:-}"; shift 2;;
    -p) PORT="${2:-}"; shift 2;;
    -n) CONTAINER_NAME="${2:-}"; shift 2;;
    --no-pull) DO_PULL=0; shift;;
    -h|--help) usage; exit 0;;
    *) die "Unknown argument: $1";;
  esac
done

[[ -n "$VT_KEY" ]] || { usage; die "Missing -v <VT_API_KEY>"; }

# Tools
command -v docker >/dev/null || die "docker not found"
command -v python3 >/dev/null || die "python3 not found"

# Docker daemon
# docker info >/dev/null 2>&1 || die "docker daemon not running or insufficient permissions."

# Project check
[[ -f "ddroidhunter/ddroidhunter.py" ]] || die "ddroidhunter.py not found."


# Port check (optional)
# if command -v lsof >/dev/null 2>&1 && lsof -Pi :"$PORT" -sTCP:LISTEN -t >/dev/null 2>&1; then
#   die "Port $PORT is in use. Pick another with -p."
# fi

# Prepare data dir for persistence
mkdir -p "$MOBSF_DATA_DIR"
# MobSF container user is commonly 9901; ensure readable/writable
if command -v sudo >/dev/null 2>&1; then
  sudo chown -R 9901:9901 "$MOBSF_DATA_DIR" || true
fi

# Pull image (optional)
if [[ "$DO_PULL" -eq 1 ]]; then
  note "Pulling $IMAGE…"
  docker pull "$IMAGE" >/dev/null
fi

# Stop any existing container with same name
if docker ps -a --format '{{.Names}}' | grep -qx "$CONTAINER_NAME"; then
  note "Removing existing container $CONTAINER_NAME…"
  docker rm -f "$CONTAINER_NAME" >/dev/null || true
fi

# Ensure MobSF API key
if [[ -z "$MOBSF_KEY" ]]; then
  # generate 64-hex chars
  if command -v openssl >/dev/null 2>&1; then
    MOBSF_KEY="$(openssl rand -hex 32)"
  else
    MOBSF_KEY="$(python3 - <<'PY'
import os, binascii
print(binascii.hexlify(os.urandom(32)).decode())
PY
)"
  fi
  ok "Generated MobSF API key (not printed for safety)."
else
  ok "Using provided MobSF API key."
fi

# Start MobSF (with fixed API key + persistent data)
note "Starting MobSF container on :$PORT…"
docker run -d --rm \
  --name "$CONTAINER_NAME" \
  -e MOBSF_API_KEY="$MOBSF_KEY" \
  -p "${PORT}:8000" \
  -v "${MOBSF_DATA_DIR}:/home/mobsf/.MobSF" \
  "$IMAGE" >/dev/null

ok "MobSF container started as $CONTAINER_NAME."

# Wait for readiness (up to 120s)
MOBSF_URL="http://127.0.0.1:${PORT}/"
note "Waiting for MobSF at ${MOBSF_URL}..."
python3 - <<'PY' "$MOBSF_URL"
import sys, time, urllib.request
url = sys.argv[1]
deadline = time.time() + 120
while time.time() < deadline:
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            if 200 <= r.status < 400:
                sys.exit(0)
    except Exception:
        pass
    time.sleep(3)
raise SystemExit("MobSF did not become ready within 120s.")
PY
ok "MobSF is reachable."

# Run D-DroidHunter
note "Launching D-DroidHunter…"
python3 ddroidhunter/ddroidhunter.py \
  --vtkey "${VT_KEY}" \
  --mobsfkey "${MOBSF_KEY}" \
  --url "${MOBSF_URL}" \
  --samples-dir "${SAMPLES_DIR}" \
  --json "${JSON_DIR}" \
  --pdf "${PDFS_DIR}" \
  --db "${DB_DIR}"
RET=$?

[[ $RET -eq 0 ]] && ok "D-DroidHunter finished." || die "D-DroidHunter exited with code $RET."