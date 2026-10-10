@echo off
rem Drag a <place>.bytecode.zip (or the place file saved with it) onto this file.
rem The rebuilt "<place> decompiled" file is written next to it.
setlocal
title USSI Bytecode Rebuilder
rem Saved before the loop: "shift" also shifts %0, which would move %~dp0
set "HERE=%~dp0"

if "%~1"=="" goto usage

where py >nul 2>nul && (set "PYTHON=py -3") || (set "PYTHON=python")

:next
if "%~1"=="" goto done
echo.
echo ===== "%~nx1"
%PYTHON% -I "%HERE%ussi_rebuild.py" "%~1"
shift
goto next

:usage
echo Drag a .bytecode.zip (or the .rbxl / .rbxlx saved with it) onto this file.

:done
echo.
pause
