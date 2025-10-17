# Performance tests (benchmarks)

# Try to find Google Benchmark
find_package(benchmark QUIET)

if(NOT benchmark_FOUND)
    message(STATUS "Google Benchmark not found, downloading...")
    include(FetchContent)
    FetchContent_Declare(
        benchmark
        GIT_REPOSITORY https://github.com/google/benchmark.git
        GIT_TAG v1.8.3
    )
    set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(benchmark)
endif()

# Benchmark executable
add_executable(bench_packet_processing
    bench_packet.cpp
    bench_flow.cpp
    bench_detection.cpp
)

target_link_libraries(bench_packet_processing
    PRIVATE
        benchmark::benchmark
        benchmark::benchmark_main
        netguardian_core
        netguardian_utils
)

if(ENABLE_SNORT_INTEGRATION)
    target_link_libraries(bench_packet_processing PRIVATE netguardian_snort)
endif()

if(ENABLE_ZEEK_INTEGRATION)
    target_link_libraries(bench_packet_processing PRIVATE netguardian_zeek)
endif()

# Add as CTest but don't fail build on performance regression
add_test(NAME bench_packet_processing COMMAND bench_packet_processing)
set_tests_properties(bench_packet_processing PROPERTIES
    TIMEOUT 1800
    LABELS "performance"
)
