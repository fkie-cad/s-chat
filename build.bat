@echo off

set prog_name=%~n0
set user_dir="%~dp0"
set /a verbose=1

set /a engine=0
set /a gui=0
set /a debug=0
set /a release=0
set /a debug_print=0
set /a rtl=0
set /a bitness=64
set platform=x64
set configuration=Debug
set /a pdb=0

set engine_proj=engine.vcxproj
set gui_proj=gui.vcxproj


set msb=msbuild

WHERE %msbuild% >nul 2>nul
IF %ERRORLEVEL% NEQ 0 set msb="C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\MSBuild\Current\Bin\MSBuild.exe"



GOTO :ParseParams

:ParseParams

    REM IF "%~1"=="" GOTO Main
    if [%1]==[/?] goto help
    if [%1]==[/h] goto help
    if [%1]==[/help] goto help

    IF "%~1"=="/e" (
        SET /a engine=1
        goto reParseParams
    )
    IF "%~1"=="/g" (
        SET /a gui=1
        goto reParseParams
    )

    IF "%~1"=="/d" (
        SET /a debug=1
        goto reParseParams
    )
    IF "%~1"=="/r" (
        SET /a release=1
        goto reParseParams
    )

    IF "%~1"=="/dp" (
        set /a "debug_print=%debug_print|1"
        goto reParseParams
    )
    IF "%~1"=="/dphd" (
        set /a "debug_print=%debug_print|2"
        goto reParseParams
    )
    IF "%~1"=="/dpm" (
        set /a "debug_print=%debug_print|4"
        goto reParseParams
    )

    IF "%~1"=="/b" (
        SET bitness=%~2
        SHIFT
        goto reParseParams
    )

    IF "%~1"=="/rtl" (
        SET /a rtl=1
        goto reParseParams
    )
    IF /i "%~1"=="/pdb" (
        SET /a pdb=1
        goto reParseParams
    )
    
    :reParseParams
    SHIFT
    if [%1]==[] goto main

GOTO :ParseParams


:main

set /a "s=%debug%+%release%"
if [%s%]==[0] (
    set /a debug=0
    set /a release=1
)
set /a "s=%engine%+%gui%"
if [%s%]==[0] (
    set /a engine=0
    set /a gui=1
)

if [%bitness%]==[64] (
    set platform=x64
)
if [%bitness%]==[32] (
    set platform=x86
)
if not [%bitness%]==[32] (
    if not [%bitness%]==[64] (
        echo ERROR: Bitness /b has to be 32 or 64!
        EXIT /B 1
    )
)

if [%engine%]==[1] call :build %engine_proj%
if [%gui%]==[1] call :build %gui_proj%

exit /B 0


:build
    SETLOCAL
        set proj=%~1
        if [%debug%]==[1] call :buildEx %proj%,%platform%,Debug,%debug_print%,%rtl%,%pdb%
        if [%release%]==[1] call :buildEx %proj%,%platform%,Release,%debug_print%,%rtl%,%pdb%
    ENDLOCAL
    
    EXIT /B %ERRORLEVEL%
    
:buildEx
    SETLOCAL
        set proj=%~1
        set platform=%~2
        set conf=%~3
        set dp=%~4
        set rtl=%~5
        set /a pdb=%~6
        
        if %rtl% == 1 (
            set rtl=%conf%
        ) else (
            set rtl=None
        )

        echo build
        echo  - Project=%proj%
        echo  - Platform=%platform%
        echo  - Configuration=%conf%
        echo  - DebugPrint=%dp%
        echo  - DebugPrintHexDump=%dphd%
        echo  - RuntimeLib=%rtl%
        echo.
        
        msbuild %proj% /p:Platform=%platform% /p:Configuration=%conf% /p:DebugPrint=%dp% /p:RuntimeLib=%rtl% /p:PDB=%pdb%
        echo.
        echo ----------------------------------------------------
        echo.
        echo.
    ENDLOCAL
    
    EXIT /B %ERRORLEVEL%


:usage
    echo Usage: %prog_name% [/e] [/g] [/d] [/r] [/dp] [/dphd] [/dpm] [/rtl] [/b 32^|64] [/pdb]
    echo Default: %prog_name% [/g /r /b 64]
    exit /B 0
    
:help
    call :usage
    echo.
    echo Targets:
    echo [/e: Build engine.]
    echo /g: Build the complete gui program.
    echo.
    echo Build modes:
    echo /d: Build in debug mode.
    echo /r: Build in release mode.
    echo /b: Bitness of exe. 32^|64. Default: 64.
    echo /rtl: Build with runtime libs.
    echo /pdb: Compile with pdbs.
    echo.
    echo Flags:
    echo /dp: Debug print output.
    echo /dphd: Extended hex dump debug print output.
    echo.
    echo Other:
    echo /h: Print this.
    exit /B 0
