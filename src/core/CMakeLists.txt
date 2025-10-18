# Core module - Fundamental components
add_library(netguardian_core STATIC
    packet.cpp
    packet_capture.cpp
    protocol_types.cpp
    protocol_parser.cpp
    app_protocol_identifier.cpp
    flow.cpp
    session.cpp
    config.cpp
    logger.cpp
    engine.cpp
    # detection_engine.cpp  # 新版本是 header-only
    # detection_engine_old.cpp  # 旧版本暂时不编译
    # mt_detection_engine.cpp  # 待修复
)

target_include_directories(netguardian_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(netguardian_core
    PUBLIC
        Threads::Threads
    PRIVATE
        netguardian_utils
        pcap
)

# Set compile features
target_compile_features(netguardian_core PUBLIC cxx_std_17)

# Install library
install(TARGETS netguardian_core
    EXPORT NetGuardianTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
