# Reassembly library (TCP + IP fragmentation)
add_library(reassembly STATIC
    tcp_segment.cpp
    tcp_reassembler.cpp
    ip_fragment.cpp
    ipv4_reassembler.cpp
    ipv6_reassembler.cpp
)

target_include_directories(reassembly PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

# 添加编译选项
target_compile_options(reassembly PRIVATE
    -Wall
    -Wextra
    -Werror
)
