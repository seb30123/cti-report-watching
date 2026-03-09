#!/usr/bin/env bash
# setup.sh — one-shot setup for cti-watch
# Usage: bash setup.sh

set -e

echo "=== CTI Watch — Setup ==="

# Python version check
python3 -c "import sys; assert sys.version_info >= (3,11), 'Python 3.11+ required'" \
  && echo "[OK] Python version OK" \
  || { echo "[ERROR] Python 3.11+ is required"; exit 1; }

# Virtual environment
if [ ! -d ".venv" ]; then
  echo "[*] Creating virtual environment..."
  python3 -m venv .venv
fi

source .venv/bin/activate

# Dependencies
echo "[*] Installing dependencies..."
pip install --upgrade pip -q
pip install -r requirements.txt -q
echo "[OK] Dependencies installed"

# sources.yaml
if [ ! -f "sources.yaml" ]; then
  cp sources.yaml.example sources.yaml
  echo "[OK] sources.yaml created from example"
else
  echo "[OK] sources.yaml already exists"
fi

# Directories
mkdir -p logs reports
echo "[OK] logs/ and reports/ directories ready"

echo ""
echo "=== Setup complete ==="
echo ""
echo "Next steps:"
echo "  source .venv/bin/activate"
echo "  python main.py          # collect feeds"
echo "  python app/run_all.py   # full pipeline"
