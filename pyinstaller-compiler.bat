@echo off
setlocal enabledelayedexpansion

:: Check for argument
if "%~1"=="" (
    echo Error: Define name fot Python-file for compilation.
    echo Example: pyinstaller-compiler.bat myscript.py
    pause
    exit /b 1
)

:: Source file (first argument)
set "PYTHON_SCRIPT=%~1"

:: Checking for file exists
if not exist "%PYTHON_SCRIPT%" (
    echo Error: File "%PYTHON_SCRIPT%" not found!
    pause
    exit /b 1
)

:: Compilation with pyinstaller
echo Compile %PYTHON_SCRIPT% with pyinstaller...
pyinstaller --onefile --noconsole --icon=Icons/logo.ico --add-data "Icons/logo.png;Icons" --hidden-import=customtkinter  "%PYTHON_SCRIPT%"

:: Checking for result
if errorlevel 1 (
    echo Compile error! Check settings.
) else (
    echo Success! Exectutable file is dist
)

pause