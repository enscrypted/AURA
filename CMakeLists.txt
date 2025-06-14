cmake_minimum_required(VERSION 3.15)
project(AURA_superbuild)

include(ExternalProject)

set(DEPS_INSTALL_DIR ${CMAKE_BINARY_DIR}/deps_install)

# define the Botan external project target
ExternalProject_Add(botan_dependency
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/external/botan
    CONFIGURE_COMMAND python3 <SOURCE_DIR>/configure.py --prefix=${DEPS_INSTALL_DIR} --amalgamation
    BUILD_COMMAND make -j8
    INSTALL_COMMAND make install
)

# define the AURA library as a second external project
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