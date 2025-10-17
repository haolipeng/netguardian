# Alert system library
# 告警系统是纯头文件库，不需要编译源文件

# 创建接口库
add_library(alerts INTERFACE)

target_include_directories(alerts INTERFACE
    ${CMAKE_SOURCE_DIR}/include
)

# 链接依赖
target_link_libraries(alerts INTERFACE
    netguardian_rules
    netguardian_decoders
)
