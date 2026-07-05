#!/usr/bin/env bash
#
# quick_start.sh — Automate the MemDBG host Quick Start in under 5 minutes.
#
# Usage:
#   ./tools/quick_start.sh              # full build + launch
#   ./tools/quick_start.sh --no-build   # skip build, only launch
#   ./tools/quick_start.sh --host-only  # only build & run the payload, no frontend
#
# Prerequisites: cc, cmake, tmux

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SESSION_NAME="memdbg-quickstart"

# ---- Defaults ----
DO_BUILD=true
DO_FRONTEND=true
DEBUG_PORT=9020
UDP_PORT=9023
DATA_ROOT="/tmp/MemDBG"
BIND_HOST="127.0.0.1"

# ---- Colors (ANSI-C quoting for real ESC bytes) ----
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
CYAN=$'\033[0;36m'
NC=$'\033[0m' # No Color

say()  { printf "${GREEN}[quick_start]${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}[quick_start]${NC} %s\n" "$*"; }
err()  { printf "${RED}[quick_start]${NC} %s\n" "$*"; exit 1; }

# ---- Parse args ----
usage() {
  cat <<'EOF'
Usage: ./tools/quick_start.sh [flags]

Automates the MemDBG host Quick Start: builds the payload and frontend,
then launches both in a tmux session with two panes.

Flags:
  --no-build     Skip build; launch existing binaries
  --host-only    Only build & run the host payload (skip frontend)
  --port=N       Override debug port (default 9020)
  -h, --help     Show this help

After launch:
  Ctrl-B ←/→    Switch between panes
  Ctrl-B D       Detach (session keeps running)
  tmux attach -t memdbg-quickstart   Reattach later
  tmux kill-session -t memdbg-quickstart   Stop everything
EOF
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-build)    DO_BUILD=false; shift ;;
    --host-only)   DO_FRONTEND=false; shift ;;
    --port=*)      DEBUG_PORT="${1#*=}"; shift ;;
    -h|--help)     usage ;;
    *)             err "Unknown option: $1. Use --help for usage." ;;
  esac
done

# ---- Check prerequisites ----
say "Checking prerequisites..."

command -v cc >/dev/null 2>&1   || err "cc not found — install a C11 compiler (clang / gcc)"
command -v cmake >/dev/null 2>&1 || err "cmake not found — install CMake 3.24+"
command -v tmux >/dev/null 2>&1 || err "tmux not found — install tmux (brew install tmux / apt install tmux)"

if $DO_FRONTEND; then
  # macOS needs 'open', Linux just runs the binary directly
  if [[ "$(uname)" == "Darwin" ]]; then
    : # 'open' is built-in on macOS
  fi
fi

say "All prerequisites met."

# ---- Step 1: Build host payload ----
if $DO_BUILD; then
  say "Building host payload..."
  cd "$PROJECT_DIR"
  make host || err "Host build failed. Check the output above for errors."
  say "Host payload ready: build/MemDBG-host"
else
  if [[ ! -x "$PROJECT_DIR/build/MemDBG-host" ]]; then
    warn "Host binary not found at build/MemDBG-host. Forcing build."
    cd "$PROJECT_DIR"
    make host || err "Host build failed."
  else
    say "Skipping host build (--no-build). Using existing binary."
  fi
fi

# ---- Step 2: Build frontend ----
if $DO_FRONTEND && $DO_BUILD; then
  say "Building frontend..."
  cd "$PROJECT_DIR"
  make frontend || err "Frontend build failed. Check the output above for errors."

  if [[ "$(uname)" == "Darwin" ]]; then
    FRONTEND_BIN="$PROJECT_DIR/build/frontend/bin/MemDBG.app"
    if [[ ! -d "$FRONTEND_BIN" ]]; then
      err "Frontend .app not found at $FRONTEND_BIN"
    fi
    say "Frontend ready: build/frontend/bin/MemDBG.app"
  else
    FRONTEND_BIN="$PROJECT_DIR/build/frontend/bin/memdbg_frontend"
    if [[ ! -x "$FRONTEND_BIN" ]]; then
      err "Frontend binary not found at $FRONTEND_BIN"
    fi
    say "Frontend ready: build/frontend/bin/memdbg_frontend"
  fi
elif $DO_FRONTEND; then
  if [[ "$(uname)" == "Darwin" ]]; then
    FRONTEND_BIN="$PROJECT_DIR/build/frontend/bin/MemDBG.app"
    if [[ ! -d "$FRONTEND_BIN" ]]; then
      warn "Frontend .app not found. Forcing build."
      cd "$PROJECT_DIR" && make frontend
    fi
  else
    FRONTEND_BIN="$PROJECT_DIR/build/frontend/bin/memdbg_frontend"
    if [[ ! -x "$FRONTEND_BIN" ]]; then
      warn "Frontend binary not found. Forcing build."
      cd "$PROJECT_DIR" && make frontend
    fi
  fi
fi

# ---- Step 3: Kill any previous session ----
if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
  say "Killing previous tmux session: $SESSION_NAME"
  tmux kill-session -t "$SESSION_NAME" || true
  sleep 0.5
fi

# ---- Step 4: Create tmux session ----
say "Starting tmux session: $SESSION_NAME"

PAYLOAD_CMD="./build/MemDBG-host --bind=$BIND_HOST --debug-port=$DEBUG_PORT --udp-port=$UDP_PORT --data-root=$DATA_ROOT"

# Create detached session with the payload running in the first window
tmux new-session -d -s "$SESSION_NAME" -n payload -c "$PROJECT_DIR" \
  "echo '${CYAN}=== MemDBG Host Payload ===${NC}'; echo ''; $PAYLOAD_CMD; echo ''; echo '${RED}Payload stopped.${NC}'; read -p 'Press Enter to close...'"

# Rename the first window
tmux rename-window -t "$SESSION_NAME:0" "payload"

if $DO_FRONTEND; then
  # Split the window horizontally for the frontend
  tmux split-window -h -t "$SESSION_NAME:0" -c "$PROJECT_DIR"

  # Select the right pane and launch the frontend there
  if [[ "$(uname)" == "Darwin" ]]; then
    tmux send-keys -t "$SESSION_NAME:0.1" \
      "echo '${CYAN}=== MemDBG Frontend ===${NC}'; echo ''; echo 'Starting frontend...'; open '$FRONTEND_BIN'" C-m
  else
    tmux send-keys -t "$SESSION_NAME:0.1" \
      "echo '${CYAN}=== MemDBG Frontend ===${NC}'; echo ''; echo 'Starting frontend...'; $FRONTEND_BIN" C-m
  fi

  # Rename the right pane
  tmux select-pane -t "$SESSION_NAME:0.1" -T "frontend"

  # Adjust layout
  tmux select-layout -t "$SESSION_NAME:0" main-horizontal
fi

# Select the payload pane (left)
tmux select-pane -t "$SESSION_NAME:0.0"

# ---- Step 5: Attach ----
say ""
say "╔══════════════════════════════════════════════════════════╗"
say "║  MemDBG Quick Start is running!                         ║"
say "╠══════════════════════════════════════════════════════════╣"
say "║  Left pane  — Host payload (TCP $DEBUG_PORT, UDP $UDP_PORT)   ║"
if $DO_FRONTEND; then
  say "║  Right pane — Frontend                                ║"
fi
say "╠══════════════════════════════════════════════════════════╣"
say "║  Keys:                                                 ║"
say "║    Ctrl-B then ←/→  — Switch panes                     ║"
say "║    Ctrl-B then D     — Detach (session keeps running)   ║"
say "║    Ctrl-B then X     — Close current pane               ║"
say "╠══════════════════════════════════════════════════════════╣"
say "║  Reattach:  tmux attach -t $SESSION_NAME                 ║"
say "║  Stop:      tmux kill-session -t $SESSION_NAME           ║"
say "╚══════════════════════════════════════════════════════════╝"
say ""

tmux attach-session -t "$SESSION_NAME"
