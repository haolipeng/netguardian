# NetGuardian Memory Bank Configuration

## Overview

This project has Memory Bank enabled to maintain context across development sessions.

## What is Memory Bank?

Memory Bank is a feature that allows Claude Code to remember important project information, architectural decisions, and development patterns across conversations. This makes it easier to:

- Maintain consistency in code style and architecture
- Remember key design decisions
- Track project status and priorities
- Provide context-aware assistance

## Configuration File

The Memory Bank configuration is stored in [.clinerules](.clinerules) at the project root.

## Key Information Stored

### Project Metadata
- Name: NetGuardian
- Version: 0.1.0
- Language: C++17
- Platform: Linux only
- Build System: CMake

### Architecture Principles
- Dual-engine design (Snort3 + Zeek)
- Bridge layer for inter-module communication
- Modular structure for easy extension
- Performance-focused with zero-copy optimization

### Module Organization
- **core/**: Packet processing, flow tracking
- **snort/**: Fast pattern matching, intrusion detection
- **zeek/**: Deep protocol analysis, metadata extraction
- **bridge/**: Event bus, data adapters
- **utils/**: Common utilities

### Coding Standards
- C++17 standard (no C++20/23)
- Google C++ Style Guide baseline
- snake_case for variables/functions
- PascalCase for classes
- 4 spaces indentation, 100 char limit
- Doxygen comments for public APIs

### Development Priorities
1. Implement libpcap packet capture
2. Add basic protocol decoders
3. Implement flow tracking
4. Port Snort3 rule parser
5. Port Zeek HTTP analyzer

### Performance Targets
- Throughput: 10 Gbps on 8-core system
- Latency: <1ms for fast path
- Memory: <2GB for 100K flows
- Scalability: Linear to 16 cores

## License Information

- Project License: GPL v2 (inherited from Snort3)
- Must preserve copyright notices from both Snort3 (GPL v2) and Zeek (BSD)
- All new files need appropriate copyright headers

## Integration Points

### Snort3 Source Directories
- `../snort3/src/detection/`
- `../snort3/src/flow/`
- `../snort3/src/codecs/`
- `../snort3/src/packet_io/`

### Zeek Source Directories
- `../zeek/src/analyzer/protocol/`
- `../zeek/src/packet_analysis/`
- `../zeek/src/logging/`

## Useful Commands

```bash
# Build project
./scripts/build/build.sh

# Run tests
cd build && ctest --output-on-failure

# Format code
find src include -name '*.cpp' -o -name '*.h' | xargs clang-format -i

# Clean build
rm -rf build
```

## Current Status

- **Framework**: ✅ COMPLETE
- **Implementation**: 🚧 IN PROGRESS (0% functional code)
- **Platform Support**: Linux only
- **Memory Bank**: ✅ ENABLED

## Benefits for Development

With Memory Bank enabled, Claude Code will:

1. **Remember Context**: Understand the project structure without re-explanation
2. **Maintain Consistency**: Follow established patterns and conventions
3. **Track Progress**: Know what's implemented and what's pending
4. **Provide Relevant Help**: Suggest improvements based on project goals
5. **Speed Up Development**: Less repetition, more productive coding

## Updating Memory Bank

The [.clinerules](.clinerules) file can be edited to:
- Add new architectural decisions
- Update development priorities
- Document new patterns
- Record lessons learned

## Notes

- Memory Bank data is stored locally in the project
- It does not share information between different projects
- You can disable it by removing or renaming `.clinerules`
- The configuration is version-controlled with the project

---

For more information, see the project documentation in the `docs/` directory.
