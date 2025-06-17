#!/bin/sh

set -e

# Arg1: Build Directory
# Arg2: Project Directory
# Arg3: CMake Generator
# Arg4: Botan Compiler Arguments (e.g., --cc=g++)
BUILD_DIR=$1
PROJECT_DIR=$2
CMAKE_GENERATOR=$3
BOTAN_ARGS=$4

echo "--- Building AURA Dependency ---"
echo "--- Build Dir: ${BUILD_DIR}"
echo "--- Project Dir: ${PROJECT_DIR}"
echo "--- Generator: ${CMAKE_GENERATOR}"
echo "--- Botan Args: ${BOTAN_ARGS}"

# configure AURA
cmake -B "${BUILD_DIR}" -S "${PROJECT_DIR}" -G "${CMAKE_GENERATOR}" -DBOTAN_EXTRA_ARGS="${BOTAN_ARGS}"

# build botan
cmake --build "${BUILD_DIR}" --target botan_dependency

# build AURA
cmake --build "${BUILD_DIR}" --target aura_library

echo "--- AURA Dependency Build Successful ---"