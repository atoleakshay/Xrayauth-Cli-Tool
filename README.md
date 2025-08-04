# XRayAuth 🔐

A lightweight session hijack detection tool that monitors HTTP traffic for suspicious token reuse patterns.

## Features

- 🕵️ **Real-time monitoring** of HTTP traffic
- 🚨 **Session hijack detection** via token analysis
- 📊 **Comprehensive logging** with JSON output
- ⚡ **Optimized performance** with minimal resource usage
- 🛡️ **Robust error handling** and graceful shutdown

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/atoleakshay/xrayauth.git
cd xrayauth

# Install dependencies
pip install -e .
```

### Usage

```bash
# Basic monitoring (default interface: eth0)
xrayauth

# Custom interface and log file
xrayauth -i wlan0 -l ~/xrayauth.log

# Verbose logging
xrayauth -v
```

## Configuration

Configuration is automatically created at `~/.xrayauth_config.ini`:

```ini
[XRayAuth]
interface = eth0
log = ~/xrayauth_logs.json
log_level = INFO
```

## Requirements

- Python 3.6+
- Scapy
- Root/Administrator privileges (for packet capture)

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Issues & Support

Found a bug? Want a feature? [Open an issue](https://github.com/atoleakshay/Xrayauth-Cli-Tool/issues)!

---

**Note**: This tool requires elevated privileges to capture network packets. Use responsibly and only on networks you own or have permission to monitor. 
