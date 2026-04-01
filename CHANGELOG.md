# Changelog

## [0.12.0] - 2025

### Added
- **File Manager**: web-based file manager for Flipper's microSD card in Tools category
  - HTTP server on port 80 accessible from any browser on the LAN
  - Browse directories, download files, upload files, create folders, delete files/folders
  - Dark theme web UI optimized for mobile and desktop
  - Reliable TCP send layer with SEND_OK polling for W5500's non-blocking send()
  - Streams large file downloads in chunks; handles multipart/form-data uploads

### Changed
- **MAC Changer** moved from Tools to Settings
- **Settings** now includes: Auto-save, Sound & vibro, Clear History, MAC Changer

### Fixed
- Force-close HTTP socket on back/exit to prevent Flipper freeze (WIZnet send() has internal while(1) with no timeout)

## [0.11.0] - 2025

### Added
- **PXE Server**: minimal PXE boot server in Tools category
  - Configurable Server IP, Client IP, Subnet via IP Keyboard before start
  - Optional DHCP server (toggle ON/OFF; OFF = TFTP-only mode)
  - TFTP server reads boot files from SD (`/ext/apps_data/eth_tester/pxe/`)
  - Auto-detects boot file: .kpxe, .efi, .pxe, .0
  - Real-time progress bar with block counters
  - Resets to idle after each transfer (multi-client sequential)

## [0.10.0] - 2025

### Added
- **ETH Bridge**: new tool that turns Flipper Zero into a USB-to-Ethernet bridge
  - Phone/PC connects via USB CDC-ECM, Flipper bridges traffic to LAN via W5500 MACRAW at Layer 2
  - Host transparently gets an IP from the LAN's DHCP server
  - Live status screen showing USB connection state, LAN link info, frame counters (USB->LAN, LAN->USB), and error count
  - Automatic USB profile save/restore: switches to CDC-ECM on start, restores original USB (CDC Serial) on exit
  - Compatible with Linux, macOS, and Android (native CDC-ECM support)
- New `usb_eth/` module: USB CDC-ECM device implementation using Flipper's FuriHalUsbInterface
- New `bridge/` module: bidirectional Ethernet frame forwarding engine

## [0.9.0] - 2025

### Added
- **Continuous Ping**: real-time RTT graph with min/max/avg/loss stats, target IP displayed on screen
- **DNS Lookup**: resolve hostnames via UDP DNS (A-record) using DHCP-provided DNS server
- **Wake-on-LAN**: send magic packets to any MAC address via broadcast UDP
- **Port Scanner**: TCP connect scan with Top-20 (quick) and Top-100 (full) presets
- **Traceroute**: ICMP-based hop-by-hop path discovery with per-hop RTT
- **Ping Sweep**: ICMP sweep of entire subnet with CIDR input, auto-detected from DHCP
- **mDNS/SSDP Discovery**: find services and devices via multicast DNS and UPnP/SSDP
- **STP/VLAN Detection**: passive BPDU listener + 802.1Q VLAN tag extraction
- **MAC Changer**: randomize or set custom MAC, persisted to SD card
- **History Browser**: timestamped results saved to SD, browse and delete old entries
- **Settings screen**: toggle auto-save and sound/vibro notifications, clear history
- **Hierarchical menu**: features grouped into Network Info, Discovery, Diagnostics, Tools
- **Link status header**: main menu shows live link state (UP/DOWN, speed, duplex)
- **LED/vibro notifications**: green blink + vibro on scan completion, red on errors (optional)
- **Countdown timers**: LLDP/CDP (60s), STP/VLAN (30s), Statistics (10s) show remaining time
- **ASCII progress bars**: visual `[####........] 45%` for Ping Sweep and Port Scan
- **Smart IP defaults**: ping/traceroute inputs pre-populated with DHCP gateway

### Changed
- **DHCP caching**: single DHCP negotiation shared across all operations (was: repeated per scan)
- **Compact output**: ARP scan shows 2 lines per host (was: 3), Statistics uses single-screen layout
- **Compact headers**: `[Xxx]` instead of `=== Xxx ===` — saves one line per screen
- **Menu reordered**: most-used tools (Ping, ARP, DHCP) at the top
- **MAC Changer**: requires user confirmation via ByteInput before applying (was: auto-randomize)
- **Back navigation**: returns to parent category submenu, not always to main menu
- **Cancel feedback**: shows "Stopping..." in header when cancelling a running operation
- **frame_buf moved to heap**: reduces static memory footprint by 1.6 KB
- **Stack safety**: 2 KB history read buffer moved from stack to heap

### Fixed
- History file TextBox scroll (was broken by input callback override)
- Version mismatch between application.fam and About screen

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
