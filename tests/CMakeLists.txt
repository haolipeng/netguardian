# Test suite configuration

# Try to find GoogleTest
find_package(GTest)

if(NOT GTest_FOUND)
    message(STATUS "GoogleTest not found, downloading...")
    include(FetchContent)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG release-1.12.1
    )
    FetchContent_MakeAvailable(googletest)
endif()

# Enable testing
enable_testing()

# Helper function to add tests (must be defined before subdirectories)
function(add_netguardian_test test_name)
    add_executable(${test_name} ${ARGN})
    target_link_libraries(${test_name}
        PRIVATE
            GTest::gtest
            GTest::gtest_main
            netguardian_core
            netguardian_utils
            netguardian_bridge
    )

    if(ENABLE_SNORT_INTEGRATION)
        target_link_libraries(${test_name} PRIVATE netguardian_snort)
    endif()

    if(ENABLE_ZEEK_INTEGRATION)
        target_link_libraries(${test_name} PRIVATE netguardian_zeek)
    endif()

    add_test(NAME ${test_name} COMMAND ${test_name})

    # Set test properties
    set_tests_properties(${test_name} PROPERTIES
        TIMEOUT 300
        LABELS "unit"
    )
endfunction()

# Unit tests
add_subdirectory(unit)

# Integration tests
add_subdirectory(integration)

# Performance tests (optional)
if(ENABLE_PROFILING)
    add_subdirectory(performance)
endif()
