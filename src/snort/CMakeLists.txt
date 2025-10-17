# Snort integration module
# This module integrates components from Snort3

add_library(netguardian_snort STATIC
    detection_engine.cpp
    rule_parser.cpp
    packet_decoder.cpp
    flow_tracker.cpp
    alert_handler.cpp
)

target_include_directories(netguardian_snort
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(netguardian_snort
    PUBLIC
        netguardian_core
        netguardian_bridge
    PRIVATE
        netguardian_utils
)

# Link to PCAP if available
if(PCAP_FOUND)
    target_include_directories(netguardian_snort PRIVATE ${PCAP_INCLUDE_DIRS})
    target_link_libraries(netguardian_snort PRIVATE ${PCAP_LIBRARIES})
endif()

# Link to DAQ if available
if(DAQ_FOUND)
    target_include_directories(netguardian_snort PRIVATE ${DAQ_INCLUDE_DIRS})
    target_link_libraries(netguardian_snort PRIVATE ${DAQ_LIBRARIES})
endif()

target_compile_features(netguardian_snort PUBLIC cxx_std_17)

# Install library
install(TARGETS netguardian_snort
    EXPORT NetGuardianTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
