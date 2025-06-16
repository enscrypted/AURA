@echo off
setlocal

:: Arg1: Build Directory
:: Arg2: Project Directory
:: Arg3: CMake Generator
:: Arg4: Botan Compiler Arguments (e.g., --cc=g++)
set BUILD_DIR=%~1
set PROJECT_DIR=%~2
set CMAKE_GENERATOR=%~3
set BOTAN_ARGS=%~4

echo --- Building AURA Dependency ---
echo --- Build Dir: %BUILD_DIR%
echo --- Project Dir: %PROJECT_DIR%
echo --- Generator: %CMAKE_GENERATOR%
echo --- Botan Args: %BOTAN_ARGS%

:: configure AURA
cmake -B "%BUILD_DIR%" "%PROJECT_DIR%" -G "%CMAKE_GENERATOR%" -DBOTAN_EXTRA_ARGS="%BOTAN_ARGS%"
if %errorlevel% neq 0 (
    echo [ERROR] CMake configuration failed.
    exit /b 1
)

:: build botan
cmake --build "%BUILD_DIR%" --target botan_dependency
if %errorlevel% neq 0 (
    echo [ERROR] Building botan_dependency failed.
    exit /b 1
)

:: build AURA
cmake --build "%BUILD_DIR%" --target aura_library
if %errorlevel% neq 0 (
    echo [ERROR] Building aura_library failed.
    exit /b 1
)

echo --- AURA Dependency Build Successful ---
exit /b 0