@echo off
setlocal
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0fail2ban.ps1" uninstall
exit /b %errorlevel%
