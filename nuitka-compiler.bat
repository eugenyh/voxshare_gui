@echo off
setlocal enabledelayedexpansion

:: Check for argument
if "%~1"=="" (
    echo Error: Define name fot Python-file for compilation.
    echo Example: nuitka-compiler.bat myscript.py
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

:: Compilation with Nuitka
echo Compile %PYTHON_SCRIPT% with Nuitka...
python -m nuitka --onefile --standalone --windows-console-mode=disable --windows-icon-from-ico=Icons/logo.ico --include-data-files=Icons/logo.png=Icons/logo.png --output-dir=nuitka-dist --lto=yes --msvc=latest --enable-plugin=tk-inter,upx --nofollow-import-to=PIL.ImageQt "%PYTHON_SCRIPT%"

:: Checking for result
if errorlevel 1 (
    echo Compile error! Check settings.
) else (
    echo Success! Exectutable file is nutica-dist
)

pause