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

3. **With configuration file**:
```bash
sudo ./build/bin/netguardian \
    -i eth0 \
    -c examples/configs/netguardian.conf.example
```

## Expected Output

When you run NetGuardian, you should see:

```
╔════════════════════════════════════════╗
║         NetGuardian v0.1.0             ║
║  Network Security Monitoring System    ║
╚════════════════════════════════════════╝

NetGuardian is starting...
Monitoring interface: eth0

[INFO] Core modules initialized
[INFO] Snort detection engine: ENABLED
[INFO] Zeek protocol analyzers: ENABLED

[INFO] NetGuardian is ready!
[INFO] Press Ctrl+C to stop...
```

## Configuration

Copy the example configuration:
```bash
sudo mkdir -p /etc/netguardian
sudo cp examples/configs/netguardian.conf.example \
        /etc/netguardian/netguardian.conf
```

Edit the configuration:
```bash
sudo nano /etc/netguardian/netguardian.conf
```

Key settings to adjust:
```ini
[general]
interfaces = eth0          # Your network interface

[snort]
enabled = true
rules_path = /etc/netguardian/rules/snort/

[zeek]
enabled = true
analyzers = http,dns,ssl
```

## Run Tests

```bash
cd build
ctest --output-on-failure
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

## Next Steps

1. **Read the User Guide**: `docs/user/README.md`
2. **Explore Examples**: `examples/`
3. **Write Custom Rules**: `docs/user/rules.md`
4. **Check the API**: `docs/api/README.md`

## Getting Help

- **Documentation**: See `docs/` directory
- **Issues**: https://github.com/yourusername/netguardian/issues
- **Discussions**: https://github.com/yourusername/netguardian/discussions

## What's Next?

Now that you have NetGuardian running, you can:

1. **Add Detection Rules**: Create custom Snort rules
2. **Enable Protocols**: Configure Zeek protocol analyzers
3. **Integrate with SIEM**: Send logs to your SIEM system
4. **Customize Alerts**: Configure alert output formats
5. **Performance Tune**: Optimize for your network speed

Happy monitoring! 🛡️
