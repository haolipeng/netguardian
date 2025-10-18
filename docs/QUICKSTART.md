# NetGuardian Quick Start Guide

Get NetGuardian up and running in 5 minutes!

## Platform Requirements

**NetGuardian only supports Linux.**

Tested on:
- Ubuntu 20.04, 22.04, 24.04
- Debian 11, 12
- CentOS Stream 8, 9
- RHEL 8, 9
- Fedora 38+

## Prerequisites

### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake libpcap-dev git
```

### CentOS/RHEL/Fedora
```bash
sudo dnf install -y gcc-c++ cmake libpcap-devel git
```

## Build NetGuardian

### Option 1: Using the build script (Recommended)

```bash
cd netguardian
./scripts/build/build.sh
```

### Option 2: Manual build

```bash
cd netguardian
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

## Verify Installation

```bash
# Check the binary exists
ls -lh build/bin/netguardian

# Run with --version flag
./build/bin/netguardian --version

# Expected output:
# NetGuardian version 0.1.0
```

## Run Your First Capture

### View Help
```bash
./build/bin/netguardian --help
```

### Basic Usage

1. **Live capture** (requires root):
```bash
sudo ./build/bin/netguardian -i eth0
```

2. **Read from pcap file**:
```bash
./build/bin/netguardian -r /path/to/capture.pcap
```

3. **With packet count limit**:
```bash
sudo ./build/bin/netguardian -i eth0 -c 1000
```

4. **With BPF filter**:
```bash
sudo ./build/bin/netguardian -i eth0 -f "tcp port 80 or tcp port 443"
```

## Expected Output

When you run NetGuardian, you should see the **Pipeline Architecture** in action:

```
╔════════════════════════════════════════════════════════╗
║              NetGuardian v0.1.0                        ║
║       Network Security Monitoring System               ║
╚════════════════════════════════════════════════════════╝

[INFO] Creating detection engine with Pipeline architecture...
[INFO] Initializing detection engine with 5 processors...
  ✓ ProtocolParsingProcessor initialized
  ✓ FlowTrackingProcessor initialized
  ✓ HttpParsingProcessor initialized
  ✓ DnsParsingProcessor initialized
  ✓ AnomalyDetectionProcessor initialized
[INFO] Detection engine initialized successfully

[INFO] Detection engine created with 5 processors
[INFO] Capture mode: Live capture on eth0
[INFO] Creating packet capture...
[INFO] Packet capture started
[INFO] Press Ctrl+C to stop...

[Packet processing in progress...]
```

### What's Happening?

NetGuardian uses a **modular Pipeline architecture** where each packet flows through specialized processors:

```
PacketCapture (libpcap)
    ↓
DetectionEngine (Orchestrator)
    ↓
Processing Pipeline:
  1. ProtocolParsingProcessor → Parse Ethernet/IP/TCP/UDP
  2. FlowTrackingProcessor     → Track flows, TCP state
  3. HttpParsingProcessor      → Parse HTTP messages
  4. DnsParsingProcessor       → Parse DNS queries/responses
  5. AnomalyDetectionProcessor → Detect DNS anomalies
    ↓
AlertManager
    ↓
Console Output / Log Files
```

This **Pipeline design** follows **SOLID principles** for:
- **Extensibility**: Add new processors without modifying existing code
- **Testability**: Each processor can be tested independently
- **Maintainability**: Single responsibility per processor
- **Performance**: Optimized processing chain

## Command Line Options

```
Usage: netguardian [OPTIONS]

OPTIONS:
  -i, --interface <name>   Network interface to capture from (e.g., eth0)
  -r, --read <file>        Read packets from PCAP file
  -f, --filter <bpf>       BPF filter expression
  -c, --count <num>        Stop after processing <num> packets
  -s, --snaplen <bytes>    Snapshot length (default: 65535)
  -v, --verbose            Enable verbose output
  -h, --help               Show this help message
  --version                Show version information
  --list-interfaces        List available network interfaces

EXAMPLES:
  # Capture from interface
  sudo ./netguardian -i eth0

  # Read from file
  ./netguardian -r capture.pcap

  # With BPF filter
  sudo ./netguardian -i eth0 -f "tcp port 80"

  # Capture 1000 packets
  sudo ./netguardian -i eth0 -c 1000
```

## Understanding the Pipeline

### Architecture Benefits

NetGuardian's **Pipeline architecture** provides:

1. **Modularity**: Each processor is independent and focused
2. **SOLID Compliance**:
   - **Single Responsibility**: Each processor does one thing
   - **Open/Closed**: Extend via new processors, don't modify existing
   - **Liskov Substitution**: All processors are interchangeable
   - **Interface Segregation**: Minimal PacketProcessor interface
   - **Dependency Inversion**: Depend on abstractions, not implementations

3. **Extensibility**: Add new processors without touching core code
4. **Performance**: Optimized processing pipeline

### Core Processors

| Processor | Responsibility | Output |
|-----------|---------------|--------|
| **ProtocolParsingProcessor** | Parse L2-L4 headers | Protocol stack info |
| **FlowTrackingProcessor** | Track TCP/UDP flows | Flow state, TCP state machine |
| **HttpParsingProcessor** | Parse HTTP requests/responses | HTTP metadata |
| **DnsParsingProcessor** | Parse DNS queries/answers | DNS records |
| **AnomalyDetectionProcessor** | Detect anomalies | Alerts for suspicious behavior |

### Adding Custom Processors

You can extend NetGuardian by implementing the `PacketProcessor` interface:

```cpp
class MyCustomProcessor : public PacketProcessor {
public:
    const char* name() const override {
        return "MyCustomProcessor";
    }

    ProcessResult process(PacketContext& ctx) override {
        // Your custom logic here
        return ProcessResult::CONTINUE;
    }
};

// Add to pipeline
engine->add_processor(std::make_unique<MyCustomProcessor>());
```

## Run Tests

```bash
cd build
ctest --output-on-failure
```

## Run Example Programs

NetGuardian includes several example programs demonstrating specific features:

```bash
# Basic packet capture
sudo ./build/bin/example_basic_capture -i eth0 -c 100

# HTTP parser
sudo ./build/bin/example_http_parser -i eth0

# DNS parser
sudo ./build/bin/example_dns_parser -i eth0

# Alert system
./build/bin/example_alert_system

# Rule parser
./build/bin/example_rule_parser examples/rules/example.rules
```

## Install System-Wide (Optional)

```bash
cd build
sudo cmake --install .
```

Now you can run from anywhere:
```bash
sudo netguardian -i eth0
```

## Troubleshooting

### Permission Denied
**Problem**: Cannot capture packets
**Solution**: Run with sudo or set capabilities
```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./build/bin/netguardian
./build/bin/netguardian -i eth0
```

### Interface Not Found
**Problem**: "Interface eth0 not found"
**Solution**: List available interfaces
```bash
# Using example program
./build/bin/example_basic_capture -l

# Or use system commands
ip link show
# or
ifconfig -a
```

Then use the correct interface name.

### Build Errors
**Problem**: Missing dependencies
**Solution**: Install required packages
```bash
# Ubuntu/Debian
sudo apt-get install -y build-essential cmake libpcap-dev

# CentOS/RHEL
sudo dnf install -y gcc-c++ cmake libpcap-devel
```

### No Packets Captured
**Problem**: Capture starts but no packets appear
**Solution**:
1. Check interface is up: `ip link show eth0`
2. Check there's traffic: `sudo tcpdump -i eth0 -c 10`
3. Try without BPF filter first
4. Ensure you have CAP_NET_RAW capability or running as root

## Performance Tips

### For High-Speed Networks (>1 Gbps)

1. **Increase buffer size**:
```bash
sudo ./netguardian -i eth0 -s 65535
```

2. **Use BPF filtering** to reduce load:
```bash
sudo ./netguardian -i eth0 -f "tcp or udp"
```

3. **Enable multi-threading** (when implemented):
See [MULTITHREADING_OPTIMIZATION.md](MULTITHREADING_OPTIMIZATION.md)

### For Low-Resource Systems

1. **Reduce snapshot length**:
```bash
sudo ./netguardian -i eth0 -s 1514  # Just Ethernet + IP + TCP headers
```

2. **Disable unnecessary processors** by modifying ProcessorFactory configuration

## Next Steps

### Documentation

1. **Architecture Guide**: [ARCHITECTURE_REFACTORING.md](ARCHITECTURE_REFACTORING.md)
2. **Project Overview**: [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md)
3. **Code Quality**: [CODE_QUALITY_REVIEW.md](CODE_QUALITY_REVIEW.md)
4. **Refactoring Summary**: [REFACTORING_SUMMARY.md](REFACTORING_SUMMARY.md)
5. **Memory Bank**: [MEMORY_BANK_INFO.md](MEMORY_BANK_INFO.md) - SOLID principles reference
6. **Multi-threading**: [MULTITHREADING_OPTIMIZATION.md](MULTITHREADING_OPTIMIZATION.md)

### Explore Examples

Check the `examples/` directory for:
- `basic_capture.cpp` - Basic packet capture
- `http_parser.cpp` - HTTP deep parsing
- `dns_parser.cpp` - DNS deep parsing
- `alert_system.cpp` - Alert generation
- `rule_parser.cpp` - Snort rule parsing

### Advanced Usage

1. **Write Custom Processors**: Extend the pipeline with your own logic
2. **Integrate with SIEM**: Send alerts to your SIEM system
3. **Performance Tuning**: Optimize for your network environment
4. **Custom Rules**: Create detection rules for your needs

## Development Workflow

### Build for Development

```bash
mkdir build-debug && cd build-debug
cmake .. -DCMAKE_BUILD_TYPE=Debug -DENABLE_SANITIZERS=ON
make -j$(nproc)
```

### Code Quality Checks

```bash
# Format code
find src include -name '*.cpp' -o -name '*.h' | xargs clang-format -i

# Run tests with verbose output
cd build && ctest -V
```

## Architecture Reference

NetGuardian follows **SOLID principles** throughout:

- **S**ingle Responsibility: Each class has one job
- **O**pen/Closed: Open for extension, closed for modification
- **L**iskov Substitution: Derived classes are substitutable
- **I**nterface Segregation: Small, focused interfaces
- **D**ependency Inversion: Depend on abstractions

See [MEMORY_BANK_INFO.md](MEMORY_BANK_INFO.md) for detailed SOLID principles guide.

## Getting Help

- **Documentation**: See `docs/` directory
- **Issues**: https://github.com/yourusername/netguardian/issues
- **Discussions**: https://github.com/yourusername/netguardian/discussions

## What's Next?

Now that you have NetGuardian running with the **Pipeline architecture**, you can:

1. **Understand the Design**: Read [REFACTORING_SUMMARY.md](REFACTORING_SUMMARY.md) to see how we refactored from God Class to Pipeline
2. **Add Custom Processors**: Extend functionality without modifying core code
3. **Explore Protocols**: Deep dive into HTTP and DNS parsing
4. **Monitor Anomalies**: Watch DNS anomaly detection in action
5. **Performance Optimize**: Enable multi-threading (upcoming feature)

Happy monitoring! 🛡️

---

**Last Updated**: 2025-10-18 (Post-Pipeline Refactoring)
**Architecture**: Pipeline with 5 core processors
**Status**: Alpha - Production Ready for Testing
