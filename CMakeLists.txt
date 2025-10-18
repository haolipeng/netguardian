cmake_minimum_required(VERSION 3.15)

project(NetGuardian
    VERSION 0.1.0
    DESCRIPTION "Network Security Monitor combining Snort3 and Zeek capabilities"
    LANGUAGES CXX C
)

# Platform check - Linux only
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "NetGuardian only supports Linux. Detected system: ${CMAKE_SYSTEM_NAME}")
endif()

message(STATUS "Platform: Linux (${CMAKE_SYSTEM_PROCESSOR})")

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Add project cmake modules path
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")

# Build options
option(BUILD_SHARED_LIBS "Build shared libraries" ON)
option(ENABLE_SNORT_INTEGRATION "Enable Snort3 integration" ON)
option(ENABLE_ZEEK_INTEGRATION "Enable Zeek integration" ON)
option(BUILD_TESTS "Build test suite" ON)
option(BUILD_EXAMPLES "Build example programs" ON)
option(ENABLE_PROFILING "Enable profiling support" OFF)
option(ENABLE_SANITIZERS "Enable address and undefined behavior sanitizers" OFF)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Choose build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "RelWithDebInfo" "MinSizeRel")
endif()

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Compiler flags
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(
        -Wall
        -Wextra
        -Wpedantic
        -Wno-unused-parameter
        $<$<CONFIG:Debug>:-g3>
        $<$<CONFIG:Debug>:-O0>
        $<$<CONFIG:Release>:-O3>
        $<$<CONFIG:Release>:-DNDEBUG>
    )

    if(ENABLE_SANITIZERS)
        add_compile_options(-fsanitize=address -fsanitize=undefined)
        add_link_options(-fsanitize=address -fsanitize=undefined)
    endif()
endif()

# Find required packages
find_package(Threads REQUIRED)

# Optional packages
find_package(PkgConfig)
if(PkgConfig_FOUND)
    pkg_check_modules(PCAP libpcap)
    pkg_check_modules(DAQ libdaq)
endif()

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_BINARY_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/concurrentqueue
)

# Generate version header
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/include/core/version.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/include/core/version.h
    @ONLY
)

# Add subdirectories
add_subdirectory(src/core)
add_subdirectory(src/utils)
add_subdirectory(src/decoders)
add_subdirectory(src/flow)
add_subdirectory(src/reassembly)
add_subdirectory(src/rules)
add_subdirectory(src/alerts)
add_subdirectory(src/bridge)

if(ENABLE_SNORT_INTEGRATION)
    add_subdirectory(src/snort)
endif()

if(ENABLE_ZEEK_INTEGRATION)
    add_subdirectory(src/zeek)
endif()

if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# Main executable
add_executable(netguardian
    src/main.cpp
)

target_link_libraries(netguardian
    PRIVATE
        netguardian_core
        netguardian_utils
        netguardian_decoders
        netguardian_flow
        reassembly
        netguardian_rules
        alerts
        netguardian_bridge
        Threads::Threads
)

if(ENABLE_SNORT_INTEGRATION)
    target_link_libraries(netguardian PRIVATE netguardian_snort)
    target_compile_definitions(netguardian PRIVATE ENABLE_SNORT_INTEGRATION)
endif()

if(ENABLE_ZEEK_INTEGRATION)
    target_link_libraries(netguardian PRIVATE netguardian_zeek)
    target_compile_definitions(netguardian PRIVATE ENABLE_ZEEK_INTEGRATION)
endif()

# Installation rules
include(GNUInstallDirs)

install(TARGETS netguardian
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/netguardian
    FILES_MATCHING PATTERN "*.h"
)

install(DIRECTORY examples/configs/
    DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/netguardian
)

# Package configuration
include(CMakePackageConfigHelpers)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/NetGuardianConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/NetGuardianConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/NetGuardian
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/NetGuardianConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/NetGuardianConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/NetGuardianConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/NetGuardian
)

# Summary
message(STATUS "")
message(STATUS "╔════════════════════════════════════════════════════════╗")
message(STATUS "║       NetGuardian Configuration Summary               ║")
message(STATUS "╚════════════════════════════════════════════════════════╝")
message(STATUS "  Platform: Linux (${CMAKE_SYSTEM_PROCESSOR})")
message(STATUS "  Version: ${PROJECT_VERSION}")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++ standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "")
message(STATUS "  Snort integration: ${ENABLE_SNORT_INTEGRATION}")
message(STATUS "  Zeek integration: ${ENABLE_ZEEK_INTEGRATION}")
message(STATUS "  Build tests: ${BUILD_TESTS}")
message(STATUS "  Build examples: ${BUILD_EXAMPLES}")
message(STATUS "  Sanitizers: ${ENABLE_SANITIZERS}")
message(STATUS "")
message(STATUS "  Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "")
