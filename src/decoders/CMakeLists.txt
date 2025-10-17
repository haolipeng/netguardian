# Decoder library

add_library(netguardian_decoders STATIC
    ethernet_decoder.cpp
    ipv4_decoder.cpp
    tcp_decoder.cpp
    udp_decoder.cpp
    http_decoder.cpp
    dns_decoder.cpp
)

target_include_directories(netguardian_decoders
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(netguardian_decoders
    PUBLIC
        netguardian_core
)

# 设置编译选项
target_compile_features(netguardian_decoders PUBLIC cxx_std_17)
target_compile_options(netguardian_decoders PRIVATE
    -Wall -Wextra -Wpedantic
)

# 安装规则
install(TARGETS netguardian_decoders
    EXPORT NetGuardianTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/decoders
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/netguardian
    FILES_MATCHING PATTERN "*.h"
)
