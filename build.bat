@echo off
setlocal

:: Arg1: Build Directory
:: Arg2: Project Directory
:: Arg3: CMake Generator
:: Arg4 (Optional): Build Configuration (e.g., Debug, Release). Defaults to Release.
:: Arg5+: Botan Compiler Arguments (e.g., --cc=g++)

set BUILD_DIR=%~1
set PROJECT_DIR=%~2
set CMAKE_GENERATOR=%~3

shift
shift
shift

:: Check if BUILD_CONFIG is provided as the 4th argument.
set "TEMP_BUILD_CONFIG=%~1"
set "BUILD_CONFIG="

if defined TEMP_BUILD_CONFIG (
    echo "%TEMP_BUILD_CONFIG%" | findstr /I /B /C:"Debug" /C:"Release" /C:"RelWithDebInfo" /C:"MinSizeRel" >nul
    if %errorlevel% equ 0 (
        set "BUILD_CONFIG=%TEMP_BUILD_CONFIG%"
        shift :: Consume the BUILD_CONFIG argument
    ) else (
        set "BUILD_CONFIG=Release"
    )
)

:: If BUILD_CONFIG is still not set, set it to Release by default
if not defined BUILD_CONFIG (
    set "BUILD_CONFIG=Release"
)

:: All remaining arguments are CMAKE_EXTRA_ARGS
set CMAKE_EXTRA_ARGS=%*

:: --- Set the correct C++ Runtime library flag based on the build config ---
set "CRT_FLAG="
if /I "%BUILD_CONFIG%" == "Debug" (
    set "CRT_FLAG=-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDebugDLL"
) else (
    set "CRT_FLAG=-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDLL"
)
echo "--- Using CRT Flag: %CRT_FLAG%"
:: --- End of Fix ---

echo --- Building AURA Dependency ---
echo --- Build Dir: %BUILD_DIR%
echo --- Project Dir: %PROJECT_DIR%
echo --- Generator: %CMAKE_GENERATOR%
echo --- Build Config: %BUILD_CONFIG%

:: configure AURA, now with the explicit CRT flag
cmake -B "%BUILD_DIR%" -S "%PROJECT_DIR%" -G "%CMAKE_GENERATOR%" -DCMAKE_BUILD_TYPE=%BUILD_CONFIG% %CRT_FLAG% %CMAKE_EXTRA_ARGS%
if %errorlevel% neq 0 (
    echo [ERROR] CMake configuration failed.
    exit /b 1
)

:: build botan
cmake --build "%BUILD_DIR%" --target botan_dependency --config %BUILD_CONFIG%
if %errorlevel% neq 0 (
    echo [ERROR] Building botan_dependency failed.
    exit /b 1
)

:: build AURA
cmake --build "%BUILD_DIR%" --target aura_library --config %BUILD_CONFIG%
if %errorlevel% neq 0 (
    echo [ERROR] Building aura_library failed.
    exit /b 1
)

echo --- AURA Dependency Build Successful ---
exit /b 0