# NetGuardian Developer Guide

This guide is for developers who want to contribute to NetGuardian or extend its capabilities.

## Table of Contents

1. [Development Setup](setup.md)
2. [Architecture Overview](architecture.md)
3. [Core Modules](modules.md)
4. [Plugin Development](plugins.md)
5. [Testing Guidelines](testing.md)
6. [Coding Standards](coding-standards.md)

## Project Structure

```
netguardian/
├── src/
│   ├── core/           # Core packet processing and flow management
│   ├── utils/          # Utility functions and helpers
│   ├── bridge/         # Integration layer between Snort and Zeek
│   ├── snort/          # Snort3 integration components
│   └── zeek/           # Zeek integration components
├── include/            # Public headers
├── tests/              # Test suites
│   ├── unit/          # Unit tests
│   ├── integration/   # Integration tests
│   └── performance/   # Performance benchmarks
├── examples/           # Example programs and configurations
└── docs/              # Documentation
```

## Core Components

### Packet Processing Pipeline

```cpp
Packet Capture → Decoder → Flow Tracker → Detection/Analysis → Output
```

### Module Responsibilities

- **core/**: Packet, Flow, Session, Config, Logger
- **snort/**: Detection engine, rule parsing, pattern matching
- **zeek/**: Protocol analyzers, script engine, log writers
- **bridge/**: Event bus, data adapters, protocol mappers
- **utils/**: String utils, time utils, hashing, memory pools

## Development Workflow

1. Fork the repository
2. Create a feature branch
3. Write code following our style guide
4. Add tests for new functionality
5. Run the test suite
6. Submit a pull request

## Building with Debug Symbols

```bash
mkdir build-debug && cd build-debug
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)
```

## Running Tests

```bash
# All tests
ctest --output-on-failure

# Specific test suite
ctest -R unit --verbose

# With valgrind
ctest -D ExperimentalMemCheck
```

## Code Style

- C++17 standard
- Follow [Google C++ Style Guide](https://google.github.io/styleguide/cppguide.html)
- Use clang-format for automatic formatting
- Maximum line length: 100 characters

## Adding New Protocol Analyzers

See [Protocol Analyzer Development](protocol-analyzers.md) for details.

## Performance Considerations

- Avoid memory allocations in hot paths
- Use memory pools for frequently allocated objects
- Profile before optimizing
- Target: Process 10 Gbps on 8-core system
