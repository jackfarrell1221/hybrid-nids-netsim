#!/bin/bash
# render-build.sh — Cloud build script for Render / Railway / Heroku

set -e

echo "[1/3] Installing Python dependencies..."
pip install -r requirements.txt

echo "[2/3] Building React TypeScript Frontend..."
cd frontend
npm install
npm run build
cd ..

echo "[3/3] Build complete. Ready for production Gunicorn service."
