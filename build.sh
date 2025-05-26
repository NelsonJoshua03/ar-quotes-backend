#!/usr/bin/env bash
set -euo pipefail

# Install system dependencies
apt-get update
apt-get install -y python3-dev python3-pip

# Install Python dependencies
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt