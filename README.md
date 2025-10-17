# NetGuardian

A next-generation network security monitoring system that combines the real-time detection capabilities of Snort3 with the deep protocol analysis power of Zeek.

## Overview

NetGuardian is an open-source network security monitor that integrates components from two industry-leading projects:
- **Snort3**: Fast pattern matching and intrusion detection
- **Zeek**: Deep protocol analysis and metadata extraction

### Key Features

- **Dual-Engine Architecture**: Combines signature-based detection with behavioral analysis
- **Real-time Detection**: Fast pattern matching for known threats
- **Deep Protocol Analysis**: Comprehensive protocol parsing for 50+ protocols
- **Flexible Logging**: Structured logs compatible with SIEM systems
- **Modular Design**: Easy to extend with custom analyzers and detectors
- **High Performance**: Multi-threaded architecture for high-speed networks

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                   NetGuardian                         │
├──────────────────────────────────────────────────────┤
│  Configuration Layer                                  │
│   ├─ Unified Configuration Interface                 │
│   └─ Plugin Management                               │
├──────────────────────────────────────────────────────┤
│  Detection & Analysis Layer                          │
│   ├─ Snort Detection Engine (Fast Path)             │
│   └─ Zeek Protocol Analyzers (Deep Path)            │
├──────────────────────────────────────────────────────┤
│  Bridge Layer (Event Bus & Data Sharing)             │
├──────────────────────────────────────────────────────┤
│  Core Layer (Packet I/O, Flow Management)            │
├──────────────────────────────────────────────────────┤
│  Output Layer (Alerts, Logs, Integrations)           │
└──────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- **Platform**: Linux only (Ubuntu 20.04+, CentOS 8+, Debian 11+, RHEL 8+)
- **Compiler**: C++17 compatible (GCC 8+, Clang 7+)
- **Build System**: CMake 3.15 or higher
- **Libraries**: libpcap development library

### Build from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/netguardian.git
cd netguardian

# Create build directory
mkdir build && cd build

# Configure
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DENABLE_SNORT_INTEGRATION=ON \
    -DENABLE_ZEEK_INTEGRATION=ON \
    -DBUILD_TESTS=ON

# Build
cmake --build . -j$(nproc)

# Run tests
ctest --output-on-failure

# Install
sudo cmake --install .
```

### Basic Usage

```bash
# Capture on interface and detect threats
sudo netguardian -i eth0 -c /etc/netguardian/netguardian.conf

# Read from pcap file
netguardian -r capture.pcap -c netguardian.conf

# Enable verbose output
netguardian -i eth0 -v -c netguardian.conf
```

## Configuration

Example configuration file:

```yaml
# netguardian.conf
interfaces:
  - eth0

snort:
  enabled: true
  rules_path: /etc/netguardian/rules/
  fast_pattern_engine: ac-bnfa

zeek:
  enabled: true
  scripts:
    - http
    - dns
    - ssl
  log_path: /var/log/netguardian/

output:
  alerts:
    - type: syslog
      facility: local0
  logs:
    - type: json
      path: /var/log/netguardian/
```

## Documentation

- [User Guide](docs/user/README.md)
- [Developer Guide](docs/developer/README.md)
- [API Reference](docs/api/README.md)
- [Examples](examples/)

## Project Status

**Current Version**: 0.1.0 (Alpha)

This project is in early development. Core features are being implemented.

### Roadmap

- [x] Project structure and build system
- [ ] Core packet capture and processing
- [ ] Basic Snort3 detection engine integration
- [ ] Basic Zeek protocol analyzer integration
- [ ] Event bus and data sharing layer
- [ ] Configuration management
- [ ] Logging and alerting system
- [ ] Performance optimization
- [ ] Full test coverage
- [ ] Documentation completion

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## Acknowledgments

This project incorporates components from:

- **Snort3** - Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
  - Licensed under GNU General Public License v2
  - https://github.com/snort3/snort3

- **Zeek** - Copyright (C) 1995-2024 The Regents of the University of California
  - Licensed under BSD License
  - https://github.com/zeek/zeek

We are grateful to the Snort and Zeek communities for their excellent work.

## Support

- GitHub Issues: https://github.com/yourusername/netguardian/issues
- Documentation: https://netguardian.readthedocs.io
- Community Forum: https://community.netguardian.io

## Author

[Your Name/Organization]

---

**Note**: This project is not officially affiliated with Cisco (Snort) or the Zeek project.
