# Integration tests

add_executable(test_integration_basic
    test_basic_flow.cpp
)

target_link_libraries(test_integration_basic
    PRIVATE
        GTest::gtest
        GTest::gtest_main
        netguardian_core
        netguardian_bridge
)

if(ENABLE_SNORT_INTEGRATION AND ENABLE_ZEEK_INTEGRATION)
    add_executable(test_integration_full
        test_snort_zeek_bridge.cpp
    )

    target_link_libraries(test_integration_full
        PRIVATE
            GTest::gtest
            GTest::gtest_main
            netguardian_core
            netguardian_bridge
            netguardian_snort
            netguardian_zeek
    )

    add_test(NAME test_integration_full COMMAND test_integration_full)
    set_tests_properties(test_integration_full PROPERTIES
        TIMEOUT 600
        LABELS "integration"
    )
endif()

add_test(NAME test_integration_basic COMMAND test_integration_basic)
set_tests_properties(test_integration_basic PROPERTIES
    TIMEOUT 600
    LABELS "integration"
)
