# Zeek integration module
# This module integrates components from Zeek

add_library(netguardian_zeek STATIC
    protocol_analyzer.cpp
    http_analyzer.cpp
    dns_analyzer.cpp
    ssl_analyzer.cpp
    log_writer.cpp
    script_engine.cpp
)

target_include_directories(netguardian_zeek
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(netguardian_zeek
    PUBLIC
        netguardian_core
        netguardian_bridge
    PRIVATE
        netguardian_utils
)

target_compile_features(netguardian_zeek PUBLIC cxx_std_17)

# Install library
install(TARGETS netguardian_zeek
    EXPORT NetGuardianTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
