@echo off
setlocal
cd /d "%~dp0"
where javac >nul 2>nul
if errorlevel 1 (
  echo Java JDK is not installed or javac is not in PATH.
  echo Install JDK 17+ and reopen VS Code.
  pause
  exit /b 1
)
echo Compiling FindoraBackend.java...
javac FindoraBackend.java
if errorlevel 1 (
  echo.
  echo Compilation failed. Read the error above.
  pause
  exit /b 1
)
echo.
echo Findora is starting at http://localhost:8080
java FindoraBackend
pause
