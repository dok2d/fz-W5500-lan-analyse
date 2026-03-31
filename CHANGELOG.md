# Changelog

## [0.1.0] - 2025

### Added
- **Link Info** view: PHY status, speed, duplex, MAC address, W5500 version check
- **LLDP Listener**: passive IEEE 802.1AB neighbor discovery with full TLV parsing (Types 0-8, 127)
- **CDP Listener**: Cisco Discovery Protocol parser with LLC/SNAP detection
- **ARP Scanner**: active subnet scan with batch requests, OUI vendor lookup (~120 vendors)
- **DHCP Analyzer**: Discover-only mode with option fingerprinting (no IP lease taken)
- **ICMP Ping**: Echo request/reply to gateway with RTT measurement
- **Packet Statistics**: frame counters by destination type and EtherType
- **SD Card Export**: all results saved to `/ext/apps_data/eth_tester/`
- W5500 HAL with SPI init, hardware reset, PHYCFGR register read, MACRAW socket management
- OUI lookup table covering ~120 common network equipment vendors
- Modular architecture: `hal/`, `protocols/`, `utils/`
- ViewDispatcher-based UI with Submenu and TextBox views
