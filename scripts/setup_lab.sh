#!/usr/bin/env bash
# Bootstrap a fresh Ubuntu VM for SentinelShield development.
# Run this INSIDE your isolated lab VM only.
#
# TODO: fill in each section as you reach the relevant build stage.

set -euo pipefail

echo "== SentinelShield lab setup =="

echo "--> Updating system packages"
sudo apt-get update
sudo apt-get upgrade -y

echo "--> Installing base dependencies"
sudo apt-get install -y python3 python3-pip python3-venv git nginx sqlite3

echo "--> (TODO) Install Suricata when you reach Stage 13:"
echo "      sudo apt-get install -y suricata"

echo "--> Creating Python virtual environment"
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

echo "--> Initializing SentinelShield database"
python -m app.core.database

echo "Done. Activate the venv with: source .venv/bin/activate"
