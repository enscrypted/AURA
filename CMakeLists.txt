cmake_minimum_required(VERSION 3.15)
project(AURA_superbuild)

include(ExternalProject)

set(DEPS_INSTALL_DIR ${CMAKE_BINARY_DIR}/deps_install)

find_program(
    PYTHON_EXECUTABLE 
    NAMES python3 python
)
if(NOT PYTHON_EXECUTABLE)
    message(FATAL_ERROR "Python (python3 or python) could not be found, but is required to configure Botan. Please install Python and ensure it is in your system's PATH.")
endif()

message(STATUS "Found Python for Botan configuration: ${PYTHON_EXECUTABLE}")

# extra botan arguments, can be set via -D from command line
set(BOTAN_EXTRA_ARGS "" CACHE STRING "Extra arguments for Botan's configure.py script")
if(BOTAN_EXTRA_ARGS)
    message(STATUS "Using extra Botan configure args: ${BOTAN_EXTRA_ARGS}")
endif()

if(CMAKE_GENERATOR MATCHES "NMake")
    # NMake does not support -j flag
    set(BOTAN_BUILD_COMMAND ${CMAKE_MAKE_PROGRAM})
else()
    # assume other make tools support -j flag.
    set(BOTAN_BUILD_COMMAND ${CMAKE_MAKE_PROGRAM} -j8)
endif()

ExternalProject_Add(botan_dependency
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/external/botan

    CONFIGURE_COMMAND ${PYTHON_EXECUTABLE} <SOURCE_DIR>/configure.py --prefix=${DEPS_INSTALL_DIR} --amalgamation ${BOTAN_EXTRA_ARGS}

    # use correct make program for current platform/generator
    BUILD_COMMAND       ${CMAKE_MAKE_PROGRAM}
    INSTALL_COMMAND     ${CMAKE_MAKE_PROGRAM} install

    LOG_CONFIGURE 1
    LOG_BUILD     1
    LOG_INSTALL   1
)

ExternalProject_Add(aura_library
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src
    # this project depends on the Botan project completing first
    DEPENDS botan_dependency
    CMAKE_ARGS
        -DCMAKE_INSTALL_PREFIX=${DEPS_INSTALL_DIR}
        -DBOTAN_INCLUDE_DIR=${DEPS_INSTALL_DIR}/include/botan-2
        -DBOTAN_LIBRARY_DIR=${DEPS_INSTALL_DIR}/lib

    TEST_COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
)