#!/usr/bin/env bash
# =======================================================
#   NEXUS NIDS — Hybrid Network Intrusion Detection
# =======================================================

set -e

# 1. Check Python
if ! command -v python3 &> /dev/null && ! command -v python &> /dev/null; then
    echo "[ERROR] Python was not found. Please install Python 3.9+."
    exit 1
fi
PYTHON_CMD=$(command -v python3 || command -v python)

# 2. Check npm
if ! command -v npm &> /dev/null; then
    echo "[ERROR] npm was not found. Please install Node.js 18+."
    exit 1
fi

echo "[1/3] Verifying Python dependencies..."
$PYTHON_CMD -m pip install -r requirements.txt --quiet

echo "[2/3] Verifying Frontend dependencies..."
cd frontend
if [ ! -d "node_modules" ]; then
    echo "Installing npm packages..."
    npm install
fi
cd ..

echo "[3/3] Launching Backend (Port 5001) and Frontend (Port 5174)..."
$PYTHON_CMD backend/app.py &
BACKEND_PID=$!

cd frontend && npm run dev &
FRONTEND_PID=$!

echo ""
echo "======================================================="
echo "  System operational!"
echo "  Frontend: http://localhost:5174"
echo "  Backend:  http://127.0.0.1:5001"
echo "  Press Ctrl+C to terminate both servers."
echo "======================================================="
echo ""

# Auto open browser
if command -v xdg-open &> /dev/null; then
    sleep 2 && xdg-open http://localhost:5174 &
elif command -v open &> /dev/null; then
    sleep 2 && open http://localhost:5174 &
fi

trap "echo 'Shutting down...'; kill $BACKEND_PID $FRONTEND_PID 2>/dev/null || true" SIGINT SIGTERM EXIT
wait
