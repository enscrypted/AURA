cmake_minimum_required(VERSION 3.15)
project(AURA_superbuild)

set(BOTAN_INCLUDE_DIR "" CACHE PATH "Path to pre-built Botan includes")
set(BOTAN_LIBRARY_DIR "" CACHE PATH "Path to pre-built Botan libraries")
option(AURA_USE_SYSTEM_BOTAN "Use a pre-built Botan library instead of building it." OFF)

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

if(NOT AURA_USE_SYSTEM_BOTAN)
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
endif()

option(AURA_DISABLE_TESTS "Disable the tests for the AURA library" OFF)

if(AURA_DISABLE_TESTS)
    message(STATUS "AURA tests are disabled by build option.")
    set(AURA_TEST_COMMAND "")
else()
    set(AURA_TEST_COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure)
endif()


set(AURA_DEPS "")
if(NOT AURA_USE_SYSTEM_BOTAN)
    list(APPEND AURA_DEPS botan_dependency)
endif()

ExternalProject_Add(aura_library
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src
    DEPENDS ${AURA_DEPS}
    CMAKE_ARGS
        -DCMAKE_INSTALL_PREFIX=${DEPS_INSTALL_DIR}
        -DBOTAN_INCLUDE_DIR=${DEPS_INSTALL_DIR}/include/botan-2
        -DBOTAN_LIBRARY_DIR=${DEPS_INSTALL_DIR}/lib
		-DCMAKE_BUILD_TYPE=$<CONFIG>
		
	BUILD_COMMAND       ${CMAKE_COMMAND} --build <BINARY_DIR> --config $<CONFIG>
    
	INSTALL_COMMAND     ${CMAKE_COMMAND} --build <BINARY_DIR> --target install --config $<CONFIG>
    
    TEST_COMMAND ${AURA_TEST_COMMAND}
)
