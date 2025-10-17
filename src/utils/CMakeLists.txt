# Utilities module - Helper functions and common utilities
add_library(netguardian_utils STATIC
    string_utils.cpp
    time_utils.cpp
    hash.cpp
    memory_pool.cpp
    ring_buffer.cpp
)

target_include_directories(netguardian_utils
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_features(netguardian_utils PUBLIC cxx_std_17)

# Install library
install(TARGETS netguardian_utils
    EXPORT NetGuardianTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
