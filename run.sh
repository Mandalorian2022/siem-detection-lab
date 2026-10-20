#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
python3 generate_events.py
python3 detect.py
python3 evaluate.py
echo "report: data/report.md and data/report.html"
