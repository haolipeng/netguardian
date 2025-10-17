# Example programs

# Basic packet capture example
add_executable(example_basic_capture
    basic_capture.cpp
)

target_link_libraries(example_basic_capture
    PRIVATE
        netguardian_core
        netguardian_utils
)

# Protocol identification demo
add_executable(example_protocol_identification
    protocol_identification_demo.cpp
)

target_link_libraries(example_protocol_identification
    PRIVATE
        netguardian_core
        netguardian_utils
)

# Protocol decoder demo
add_executable(example_decoder
    decoder_demo.cpp
)

target_link_libraries(example_decoder
    PRIVATE
        netguardian_core
        netguardian_utils
        netguardian_decoders
)

# Flow tracking demo
add_executable(example_flow_tracking
    flow_tracking_demo.cpp
)

target_link_libraries(example_flow_tracking
    PRIVATE
        netguardian_core
        netguardian_utils
        netguardian_decoders
        netguardian_flow
        reassembly
)

# Flow management demo (with timeout and export)
add_executable(example_flow_management
    flow_management_demo.cpp
)

target_link_libraries(example_flow_management
    PRIVATE
        netguardian_core
        netguardian_utils
        netguardian_decoders
        netguardian_flow
        reassembly
)

# Rule parser demo
add_executable(example_rule_parser
    rule_parser_demo.cpp
)

target_link_libraries(example_rule_parser
    PRIVATE
        netguardian_core
        netguardian_utils
        netguardian_rules
)

# Matcher demo
add_executable(example_matcher
    matcher_demo.cpp
)

target_link_libraries(example_matcher
    PRIVATE
        netguardian_core
        netguardian_utils
        netguardian_rules
        netguardian_decoders
)

# TCP reassembly demo
add_executable(example_tcp_reassembly
    example_tcp_reassembly.cpp
)

target_link_libraries(example_tcp_reassembly
    PRIVATE
        netguardian_core
        netguardian_utils
        netguardian_flow
        reassembly
)

# Alert system demo
add_executable(example_alert_system
    example_alert_system.cpp
)

target_link_libraries(example_alert_system
    PRIVATE
        netguardian_core
        netguardian_utils
        netguardian_rules
        netguardian_decoders
        alerts
)

# IP fragmentation reassembly demo
add_executable(example_ip_reassembly
    example_ip_reassembly.cpp
)

target_link_libraries(example_ip_reassembly
    PRIVATE
        netguardian_core
        netguardian_utils
        reassembly
)

# Snort integration example
# TODO: Implement snort_detection.cpp
# if(ENABLE_SNORT_INTEGRATION)
#     add_executable(example_snort_detection
#         snort_detection.cpp
#     )
#
#     target_link_libraries(example_snort_detection
#         PRIVATE
#             netguardian_core
#             netguardian_snort
#             netguardian_bridge
#     )
# endif()

# Zeek integration example
# TODO: Implement zeek_analysis.cpp
# if(ENABLE_ZEEK_INTEGRATION)
#     add_executable(example_zeek_analysis
#         zeek_analysis.cpp
#     )
#
#     target_link_libraries(example_zeek_analysis
#         PRIVATE
#             netguardian_core
#             netguardian_zeek
#             netguardian_bridge
#     )
# endif()

# Full integration example
# TODO: Implement full_monitor.cpp
# if(ENABLE_SNORT_INTEGRATION AND ENABLE_ZEEK_INTEGRATION)
#     add_executable(example_full_monitor
#         full_monitor.cpp
#     )
#
#     target_link_libraries(example_full_monitor
#         PRIVATE
#             netguardian_core
#             netguardian_snort
#             netguardian_zeek
#             netguardian_bridge
#             netguardian_utils
#     )
# endif()

# Install examples
install(TARGETS
    example_basic_capture
    example_protocol_identification
    example_decoder
    example_flow_tracking
    example_flow_management
    example_rule_parser
    example_matcher
    example_tcp_reassembly
    example_alert_system
    example_ip_reassembly
    RUNTIME DESTINATION ${CMAKE_INSTALL_DOCDIR}/examples
)

# TODO: Add back when implemented
# if(ENABLE_SNORT_INTEGRATION)
#     install(TARGETS example_snort_detection
#         RUNTIME DESTINATION ${CMAKE_INSTALL_DOCDIR}/examples
#     )
# endif()
#
# if(ENABLE_ZEEK_INTEGRATION)
#     install(TARGETS example_zeek_analysis
#         RUNTIME DESTINATION ${CMAKE_INSTALL_DOCDIR}/examples
#     )
# endif()
#
# if(ENABLE_SNORT_INTEGRATION AND ENABLE_ZEEK_INTEGRATION)
#     install(TARGETS example_full_monitor
#         RUNTIME DESTINATION ${CMAKE_INSTALL_DOCDIR}/examples
#     )
# endif()
