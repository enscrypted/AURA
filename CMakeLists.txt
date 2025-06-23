cmake_minimum_required(VERSION 3.15)
project(AURA_superbuild)

# option to bypass internal botan build and use a pre-built one
option(AURA_USE_SYSTEM_BOTAN "Use a pre-built Botan library instead of building it." OFF)

# allow user to specify path to pre-built botan install
set(BOTAN_INCLUDE_DIR "" CACHE PATH "Path to pre-built Botan includes")
set(BOTAN_LIBRARY_DIR "" CACHE PATH "Path to pre-built Botan libraries")

include(ExternalProject)

if(AURA_USE_SYSTEM_BOTAN)
    # using a pre-built botan, no dependency target needed
    set(AURA_DEPS "")

    # CMAKE_ARGS for aura_library sub-project when using system botan
    set(AURA_CMAKE_ARGS
        -DBOTAN_INCLUDE_DIR=${BOTAN_INCLUDE_DIR}
        -DBOTAN_LIBRARY_DIR=${BOTAN_LIBRARY_DIR}
    )
    # The install prefix for aura should be the one passed to this project
    set(AURA_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})

else()
    # default behavior: build botan dependency internally
    set(DEPS_INSTALL_DIR ${CMAKE_BINARY_DIR}/deps_install)
    set(AURA_DEPS botan_dependency)

    # CMAKE_ARGS for aura_library sub-project when using internal botan
    set(AURA_CMAKE_ARGS
        -DBOTAN_INCLUDE_DIR=${DEPS_INSTALL_DIR}/include/botan-2
        -DBOTAN_LIBRARY_DIR=${DEPS_INSTALL_DIR}/lib
    )
    # The install prefix for aura should be the internal dependency dir
    set(AURA_INSTALL_PREFIX ${DEPS_INSTALL_DIR})

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

    ExternalProject_Add(botan_dependency
        SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/external/botan
        CONFIGURE_COMMAND ${PYTHON_EXECUTABLE} <SOURCE_DIR>/configure.py --prefix=${DEPS_INSTALL_DIR} --amalgamation ${BOTAN_EXTRA_ARGS}
        BUILD_COMMAND       ${CMAKE_MAKE_PROGRAM}
        INSTALL_COMMAND     ${CMAKE_MAKE_PROGRAM} install
        LOG_CONFIGURE 1
        LOG_BUILD     1
        LOG_INSTALL   1
    )
endif()

option(AURA_DISABLE_TESTS "Disable the tests for the AURA library" OFF)

if(AURA_DISABLE_TESTS)
    message(STATUS "AURA tests are disabled by build option.")
    set(AURA_TEST_COMMAND "")
else()
    set(AURA_TEST_COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure)
endif()

ExternalProject_Add(aura_library
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src
    DEPENDS ${AURA_DEPS}
    CMAKE_ARGS
        -DCMAKE_INSTALL_PREFIX=${AURA_INSTALL_PREFIX}
        ${AURA_CMAKE_ARGS}
        -DCMAKE_BUILD_TYPE=$<CONFIG>

    BUILD_COMMAND       ${CMAKE_COMMAND} --build <BINARY_DIR> --config $<CONFIG>
    INSTALL_COMMAND     ${CMAKE_COMMAND} --build <BINARY_DIR> --target install --config $<CONFIG>
    TEST_COMMAND ${AURA_TEST_COMMAND}
)