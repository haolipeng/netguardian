# Rules engine library

add_library(netguardian_rules STATIC
    rule.cpp
    rule_parser.cpp
    rule_manager.cpp
)

target_include_directories(netguardian_rules
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(netguardian_rules
    PUBLIC
        netguardian_core
)
