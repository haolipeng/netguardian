# Flow tracking library

add_library(netguardian_flow STATIC
    flow.cpp
    tcp_state_machine.cpp
    flow_manager.cpp
)

target_include_directories(netguardian_flow
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(netguardian_flow
    PUBLIC
        netguardian_core
        netguardian_decoders
)

# 设置编译选项
target_compile_features(netguardian_flow PUBLIC cxx_std_17)
target_compile_options(netguardian_flow PRIVATE
    -Wall -Wextra -Wpedantic
)

# 安装规则
install(TARGETS netguardian_flow
    EXPORT NetGuardianTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/flow
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/netguardian
    FILES_MATCHING PATTERN "*.h"
)
