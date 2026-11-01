@echo off
where py >nul 2>nul
if %errorlevel% equ 0 (
  py -3 "%~dp0setup.py" %*
) else (
  python "%~dp0setup.py" %*
)
if errorlevel 1 pause
