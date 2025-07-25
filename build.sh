#!/usr/bin/env bash
set -euo pipefail

# Clear pip cache
python -m pip cache purge

# Force clean installation
python -m pip install --upgrade pip
pip install --no-cache-dir -r requirements.txt
