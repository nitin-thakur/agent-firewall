@echo off
REM One-time setup: creates .venv and installs the (free) libraries. No PowerShell policy changes needed.
where py >nul 2>nul
if %errorlevel%==0 (py -3 -m venv .venv) else (python -m venv .venv)
if not exist .venv\Scripts\python.exe (
  echo Could not create the virtual environment. Install Python 3.11/3.12 from python.org and tick "Add Python to PATH".
  pause
  exit /b 1
)
.venv\Scripts\python.exe -m pip install --upgrade pip
.venv\Scripts\python.exe -m pip install -r requirements.txt
echo.
echo Setup complete. Now run: run_all_demos.bat
pause
