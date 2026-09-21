@echo off
REM Build standalone Windows executables for the TAK CoT Inspector.
REM Requires: pip install -r requirements-build.txt

setlocal

REM Pick a Python launcher. Prefer `py -3` (Python launcher), fall back to `python`.
set PY=
where py >nul 2>nul && set PY=py -3
if "%PY%"=="" (
    where python >nul 2>nul && set PY=python
)
if "%PY%"=="" (
    echo Could not find Python on PATH. Install Python 3 and try again.
    exit /b 1
)

REM Verify PyInstaller is importable in that interpreter.
%PY% -c "import PyInstaller" 1>nul 2>nul
if errorlevel 1 (
    echo PyInstaller not found for %PY%. Install build deps with:
    echo     %PY% -m pip install -r requirements-build.txt
    exit /b 1
)

echo.
echo === Building GUI executable ===
%PY% -m PyInstaller --noconfirm --clean inspect_cot_gui.spec
if errorlevel 1 goto :fail

echo.
echo Done. Executable is in the dist\ folder:
echo     dist\inspect_cot_gui.exe
exit /b 0

:fail
echo Build failed.
exit /b 1
