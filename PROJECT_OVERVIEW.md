# NetGuardian Project Overview

## Project Information

- **Name**: NetGuardian
- **Version**: 0.1.0 (Alpha)
- **Description**: Network security monitoring system combining Snort3 and Zeek
- **Language**: C++17
- **Build System**: CMake 3.15+

## Project Structure

```
netguardian/
├── cmake/                      # CMake configuration files
│   ├── modules/               # Custom CMake find modules
│   └── NetGuardianConfig.cmake.in
│
├── docs/                       # Documentation
│   ├── api/                   # API reference (auto-generated)
│   ├── developer/             # Developer documentation
│   └── user/                  # User manual
│
├── examples/                   # Example programs and configurations
│   ├── configs/               # Sample configuration files
│   ├── rules/                 # Sample detection rules
│   ├── scripts/               # Sample scripts
│   └── *.cpp                  # Example source code
│
├── include/                    # Public header files
│   ├── core/                  # Core module headers
│   ├── bridge/                # Bridge layer headers
│   ├── snort/                 # Snort integration headers
│   ├── zeek/                  # Zeek integration headers
│   └── utils/                 # Utility headers
│
├── scripts/                    # Build and utility scripts
│   ├── build/                 # Build scripts
│   ├── install/               # Installation scripts
│   └── test/                  # Test scripts
│
├── src/                        # Source code
│   ├── core/                  # Core functionality
│   ├── bridge/                # Integration bridge layer
│   ├── snort/                 # Snort3 integration
│   ├── zeek/                  # Zeek integration
│   ├── utils/                 # Utilities
│   └── main.cpp               # Main entry point
│
├── tests/                      # Test suites
│   ├── unit/                  # Unit tests
│   ├── integration/           # Integration tests
│   └── performance/           # Performance benchmarks
│
├── third_party/                # Third-party dependencies (git submodules)
│
├── CMakeLists.txt             # Root CMake configuration
├── README.md                   # Project README
├── CONTRIBUTING.md            # Contribution guidelines
└── .gitignore                 # Git ignore rules
```

## Module Overview

### Core Modules

#### 1. **core/** - Core Packet Processing
- `packet.h/cpp`: Packet structure and management
- `flow.h/cpp`: Flow tracking and session management
- `session.cpp`: Session state management
- `config.cpp`: Configuration management
- `logger.cpp`: Logging infrastructure
- `engine.cpp`: Main processing engine

**Responsibilities**:
- Packet capture and basic processing
- Flow/session tracking
- Configuration parsing
- Logging and output management

#### 2. **utils/** - Utilities
- `string_utils.cpp`: String manipulation helpers
- `time_utils.cpp`: Time/date utilities
- `hash.cpp`: Hash functions
- `memory_pool.cpp`: Memory pool allocator
- `ring_buffer.cpp`: Lock-free ring buffer

**Responsibilities**:
- Common utility functions
- Performance-critical data structures
- Memory management helpers

#### 3. **bridge/** - Integration Bridge
- `event_bus.cpp`: Event system for inter-module communication
- `data_adapter.cpp`: Data format conversion between Snort/Zeek
- `plugin_manager.cpp`: Plugin loading and management
- `protocol_mapper.cpp`: Protocol identification mapping

**Responsibilities**:
- Coordinate between Snort and Zeek components
- Event routing and handling
- Data format translation
- Plugin architecture

### Integration Modules

#### 4. **snort/** - Snort3 Integration
- `detection_engine.cpp`: Pattern matching and rule evaluation
- `rule_parser.cpp`: Snort rule parsing
- `packet_decoder.cpp`: Protocol decoding
- `flow_tracker.cpp`: Flow state tracking
- `alert_handler.cpp`: Alert generation

**From Snort3**:
- Detection engine logic
- Rule matching algorithms
- Protocol decoders
- Alert mechanisms

#### 5. **zeek/** - Zeek Integration
- `protocol_analyzer.cpp`: Base protocol analyzer
- `http_analyzer.cpp`: HTTP protocol analysis
- `dns_analyzer.cpp`: DNS protocol analysis
- `ssl_analyzer.cpp`: SSL/TLS analysis
- `log_writer.cpp`: Structured log output
- `script_engine.cpp`: Zeek script support

**From Zeek**:
- Protocol analysis framework
- Specific protocol analyzers
- Log writing infrastructure
- Scripting capabilities

## Build Configuration

### CMake Options

| Option | Default | Description |
|--------|---------|-------------|
| `BUILD_SHARED_LIBS` | ON | Build shared libraries |
| `ENABLE_SNORT_INTEGRATION` | ON | Enable Snort3 features |
| `ENABLE_ZEEK_INTEGRATION` | ON | Enable Zeek features |
| `BUILD_TESTS` | ON | Build test suite |
| `BUILD_EXAMPLES` | ON | Build examples |
| `ENABLE_PROFILING` | OFF | Enable profiling |
| `ENABLE_SANITIZERS` | OFF | Enable sanitizers |

### Build Targets

- `netguardian`: Main executable
- `netguardian_core`: Core library
- `netguardian_utils`: Utilities library
- `netguardian_bridge`: Bridge library
- `netguardian_snort`: Snort integration library
- `netguardian_zeek`: Zeek integration library

### Test Targets

- `test_*`: Individual unit tests
- `test_integration_*`: Integration tests
- `bench_*`: Performance benchmarks

## Dependencies

### Required
- C++17 compiler (GCC 8+, Clang 7+, MSVC 2019+)
- CMake 3.15+
- libpcap (for packet capture)

### Optional
- DAQ library (for advanced packet I/O)
- GoogleTest (auto-downloaded if not found)
- Google Benchmark (auto-downloaded if not found)

## Development Workflow

### Quick Start

```bash
# Build the project
./scripts/build/build.sh

# Run tests
cd build
ctest --output-on-failure

# Run the program (as root for packet capture)
sudo ./bin/netguardian -i eth0 -c ../examples/configs/netguardian.conf.example
```

### Development Build

```bash
mkdir build-debug && cd build-debug
cmake .. -DCMAKE_BUILD_TYPE=Debug -DENABLE_SANITIZERS=ON
make -j$(nproc)
```

### Running Tests

```bash
# All tests
ctest

# Specific test suite
ctest -R unit

# Verbose output
ctest -V

# With valgrind
ctest -D ExperimentalMemCheck
```

## Code Organization Principles

1. **Separation of Concerns**: Each module has clear responsibilities
2. **Loose Coupling**: Modules communicate through well-defined interfaces
3. **Plugin Architecture**: Easy to extend with new analyzers
4. **Performance**: Zero-copy where possible, memory pools for hot paths
5. **Testability**: All modules have corresponding unit tests

## Integration Strategy

### Snort3 Integration
- Extract core detection algorithms
- Adapt to NetGuardian's packet structure
- Integrate rule parser
- Map alerts to unified event system

### Zeek Integration
- Port protocol analyzer framework
- Adapt specific analyzers (HTTP, DNS, SSL)
- Integrate logging infrastructure
- Map events to bridge layer

### Bridge Layer
- Unified event bus for both engines
- Data format conversion
- Coordinated packet processing
- Shared state management

## Performance Targets

- **Throughput**: 10 Gbps on 8-core system
- **Latency**: <1ms for fast path (Snort detection only)
- **Memory**: <2GB for 100K active flows
- **CPU**: Linear scaling up to 16 cores

## Future Enhancements

### Phase 1 (Current)
- [x] Project structure
- [ ] Core packet capture
- [ ] Basic Snort integration
- [ ] Basic Zeek integration

### Phase 2
- [ ] Full protocol analyzer suite
- [ ] Rule management system
- [ ] Advanced logging
- [ ] Performance optimization

### Phase 3
- [ ] Cluster mode
- [ ] Threat intelligence integration
- [ ] Machine learning models
- [ ] Web dashboard

## License Compliance

This project integrates code from:
- **Snort3**: GPL v2
- **Zeek**: BSD License

NetGuardian is therefore licensed under **GPL v2** (most restrictive license applies).

All source files must include appropriate copyright notices.

## Contact & Support

- **Repository**: https://github.com/yourusername/netguardian
- **Issues**: https://github.com/yourusername/netguardian/issues
- **Discussions**: https://github.com/yourusername/netguardian/discussions

---

**Last Updated**: 2025-10-17
