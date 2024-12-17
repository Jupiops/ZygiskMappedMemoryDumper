@echo off
setlocal enabledelayedexpansion

REM Navigate to the directory where the script is located
cd /d "%~dp0"

REM Set the path to ndk-build using LocalAppData
set NDK_BUILD_CMD=%LocalAppData%\Android\Sdk\ndk\27.2.12479018\ndk-build.cmd

REM Step 1: Execute ndk-build command with -j8
echo Running ndk-build...
call "%NDK_BUILD_CMD%" -j8
if errorlevel 1 (
    echo ndk-build failed!
    exit /b 1
)

REM Step 2: Clean and recreate the out directory
set OUT_DIR=out
if exist "%OUT_DIR%" (
    echo Deleting existing %OUT_DIR% folder...
    rmdir /s /q "%OUT_DIR%"
)

echo Creating new %OUT_DIR% folder...
mkdir "%OUT_DIR%\zygisk"

REM Step 3: Copy the contents of the libs folder to the zygisk folder in the out directory
set LIBS_DIR=libs
if not exist "%LIBS_DIR%" (
    echo Error: %LIBS_DIR% folder not found!
    exit /b 1
)

echo Copying contents of %LIBS_DIR% to %OUT_DIR%\zygisk...
for /d %%G in (%LIBS_DIR%\*) do (
    set ABI_NAME=%%~nG
    mkdir "%OUT_DIR%\zygisk\!ABI_NAME!"
    copy "%%G\libmappedmemdumper.so" "%OUT_DIR%\zygisk\!ABI_NAME!.so"
)

REM Step 4: Copy the template folder to the out directory
set TEMPLATE_DIR=template
if not exist "%TEMPLATE_DIR%" (
    echo Error: %TEMPLATE_DIR% folder not found!
    exit /b 1
)

echo Copying %TEMPLATE_DIR% folder to %OUT_DIR%...
xcopy "%TEMPLATE_DIR%\*" "%OUT_DIR%\" /E /H /I

echo Build script executed successfully.
endlocal
exit /b 0
