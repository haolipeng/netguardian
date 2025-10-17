# Bridge module - Integration layer between Snort and Zeek
add_library(netguardian_bridge STATIC
    event_bus.cpp
    data_adapter.cpp
    plugin_manager.cpp
    protocol_mapper.cpp
)

target_include_directories(netguardian_bridge
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(netguardian_bridge
    PUBLIC
        netguardian_core
    PRIVATE
        netguardian_utils
)

target_compile_features(netguardian_bridge PUBLIC cxx_std_17)

# Install library
install(TARGETS netguardian_bridge
    EXPORT NetGuardianTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
