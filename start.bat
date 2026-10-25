@echo off
setlocal
echo =======================================================
echo   NEXUS NIDS — Hybrid Network Intrusion Detection
echo =======================================================
echo.

:: 1. Check Python
where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Python was not found in your PATH.
    echo Please install Python 3.9+ from https://www.python.org/
    pause
    exit /b 1
)

:: 2. Check Node
where npm >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] npm was not found in your PATH.
    echo Please install Node.js 18+ from https://nodejs.org/
    pause
    exit /b 1
)

echo [1/3] Verifying Python dependencies...
python -m pip install -r requirements.txt --quiet

echo [2/3] Verifying Frontend dependencies...
cd frontend
if not exist node_modules (
    echo Installing npm dependencies...
    call npm install
)
cd ..

echo [3/3] Starting Backend (Port 5001) and Frontend (Port 5174)...
start "NEXUS NIDS Backend" cmd /k "python backend/app.py"
start "NEXUS NIDS Frontend" cmd /k "cd frontend && npm run dev"

echo.
echo =======================================================
echo   System operational! Opening dashboard in browser...
echo   Frontend: http://localhost:5174
echo   Backend:  http://127.0.0.1:5001
echo =======================================================
echo.

timeout /t 3 >nul
start http://localhost:5174
exit /b 0
