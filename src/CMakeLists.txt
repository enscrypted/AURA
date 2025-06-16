cmake_minimum_required(VERSION 3.15)
project(AURA_library)

enable_testing()

# this target will be pre-populated with properties by the super-build
add_library(Botan::botan INTERFACE IMPORTED)
target_include_directories(Botan::botan INTERFACE ${BOTAN_INCLUDE_DIR})
target_link_directories(Botan::botan INTERFACE ${BOTAN_LIBRARY_DIR})
target_link_libraries(Botan::botan INTERFACE botan-2)

add_library(AURA AURA.cpp)

target_include_directories(AURA PUBLIC ../include)

target_link_libraries(AURA PUBLIC Botan::botan)

set_target_properties(AURA PROPERTIES CXX_STANDARD 17)

if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/../test/main.cpp)
    add_executable(aura_tester ../test/main.cpp)
    target_link_libraries(aura_tester PRIVATE AURA)

    # add test to CTest so it can run automatically
    add_test(NAME AuraRoundTripTest COMMAND aura_tester)
endif()

include(GNUInstallDirs)
install(TARGETS AURA
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(DIRECTORY ../include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})