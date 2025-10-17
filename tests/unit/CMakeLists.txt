# Unit tests

add_netguardian_test(test_packet
    test_packet.cpp
)

add_netguardian_test(test_flow
    test_flow.cpp
)

add_netguardian_test(test_utils
    test_string_utils.cpp
    test_time_utils.cpp
    test_hash.cpp
)

add_netguardian_test(test_bridge
    test_event_bus.cpp
    test_data_adapter.cpp
)

if(ENABLE_SNORT_INTEGRATION)
    add_netguardian_test(test_snort_integration
        test_detection_engine.cpp
        test_rule_parser.cpp
    )
endif()

if(ENABLE_ZEEK_INTEGRATION)
    add_netguardian_test(test_zeek_integration
        test_protocol_analyzer.cpp
        test_log_writer.cpp
    )
endif()
