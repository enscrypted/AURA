cmake_minimum_required(VERSION 3.15)
project(AURA LANGUAGES CXX)

include(ExternalProject)

# ===================================================================
# == Define and Build Botan 2 as an External Project
# ===================================================================

set(BOTAN_INSTALL_DIR ${CMAKE_BINARY_DIR}/botan_install)
set(BOTAN_LIBRARY_DIR ${BOTAN_INSTALL_DIR}/lib)
set(BOTAN_INCLUDE_DIR ${BOTAN_INSTALL_DIR}/include/botan-2)

ExternalProject_Add(botan_external
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/external/botan
    BINARY_DIR ${CMAKE_BINARY_DIR}/botan_build
    INSTALL_DIR ${BOTAN_INSTALL_DIR}
    CONFIGURE_COMMAND python3 <SOURCE_DIR>/configure.py --prefix=${BOTAN_INSTALL_DIR} --amalgamation
    BUILD_COMMAND ${CMAKE_COMMAND} -E env "LDFLAGS=-L." make -j8
    INSTALL_COMMAND ${CMAKE_COMMAND} -E env "LDFLAGS=-L." make install
    BUILD_BYPRODUCTS ${BOTAN_LIBRARY_DIR}/libbotan-2.a
)

# ===================================================================
# == Create a Proxy Library to Represent the Built Botan
# ===================================================================

add_library(botan_imported INTERFACE IMPORTED GLOBAL)

# This ensures Botan is fully built before anything tries to use proxy.
add_dependencies(botan_imported botan_external)

target_include_directories(botan_imported INTERFACE ${BOTAN_INCLUDE_DIR})
target_link_directories(botan_imported INTERFACE ${BOTAN_LIBRARY_DIR})
target_link_libraries(botan_imported INTERFACE botan-2)

# ===================================================================
# == Define and Build the AURA Library
# ===================================================================

add_library(AURA src/AURA.cpp)

# Link AURA against proxy target. This transitively provides all the
# necessary include paths and library links to AURA at the correct time.
target_link_libraries(AURA PUBLIC botan_imported)

target_include_directories(AURA PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

set_target_properties(AURA PROPERTIES CXX_STANDARD 17)

# ===================================================================
# == Define the Test Executable
# ===================================================================

if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/test)
    add_executable(aura_tester test/main.cpp)
    target_link_libraries(aura_tester PRIVATE AURA)
    set_target_properties(aura_tester PROPERTIES RUNTIME_OUTPUT_DIRECTORY "test")
endif()