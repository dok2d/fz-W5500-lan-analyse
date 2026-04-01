# Flipper Zero LAN Tester (W5500) — Full Documentation

Turn your **Flipper Zero + W5500 Lite** module into a professional-grade portable LAN tester.

---

## Features

| Feature | Description |
|---|---|
| **Link Info** | PHY link status, speed (10/100 Mbps), duplex (Half/Full), MAC address, W5500 version check |
| **DHCP Analyzer** | Discover-only analysis (no IP lease taken), option fingerprinting, full offer parsing |
| **ARP Scanner** | Active subnet scan with batch requests, OUI vendor lookup (~120 vendors), duplicate detection |
| **Ping** | Echo request/reply to any IP with configurable count and timeout |
| **Continuous Ping** | Real-time RTT graph with min/max/avg and packet loss, configurable interval |
| **DNS Lookup** | Resolve hostnames via UDP DNS, supports custom DNS server |
| **Traceroute** | ICMP-based hop-by-hop path discovery, accepts IPs and hostnames with DNS resolve |
| **Ping Sweep** | ICMP sweep of an entire subnet with interactive host list |
| **Port Scanner** | TCP connect scan: Top-20, Top-100, or custom port range (1-65535) |
| **LLDP/CDP** | Passive IEEE 802.1AB & Cisco CDP neighbor discovery with full TLV parsing |
| **mDNS/SSDP** | Discover services and devices via multicast DNS and UPnP/SSDP |
| **STP/VLAN** | Passive BPDU listener + 802.1Q VLAN tag detection |
| **Statistics** | Frame counters by type (unicast/broadcast/multicast) and EtherType |
| **Wake-on-LAN** | Send magic packets to any MAC address |
| **Packet Capture** | Standalone PCAP traffic dump to .pcap file on SD card |
| **ETH Bridge** | USB-to-Ethernet bridge via CDC-ECM, optional PCAP traffic dump to SD |
| **PXE Server** | PXE boot server with DHCP auto-detection + TFTP, multiple boot file selection |
| **File Manager** | Web-based SD card manager via HTTP with auth token, upload/download/delete |
| **History** | All scan results auto-saved with timestamps, browsable and deletable |
| **Settings** | Auto-save, sound/vibro, custom DNS, ping count/timeout/interval, clear history, MAC Changer |

---

## Hardware

### Required

- **Flipper Zero** (OFW firmware)
- **W5500 Lite** Ethernet module (or any W5500-based board with SPI)

### Where to Buy

- [W5500 Ethernet Module for Flipper Zero](https://flipperaddons.com/product/w5500-ethernet/)

### Wiring

```
W5500 Module    Flipper Zero GPIO
-----           -----
MOSI (MO)   ->  A7  (pin 2)
SCLK (SCK)  ->  B3  (pin 5)
CS   (nSS)  ->  A4  (pin 4)
MISO (MI)   ->  A6  (pin 3)
RESET (RST) ->  C3  (pin 7)
3V3  (VCC)  ->  3V3 (pin 9)
GND  (G)    ->  GND (pin 8 or 11)
```

The W5500 is powered via Flipper's OTG 3.3V output, enabled automatically when the app starts.

---

## Building

### Prerequisites

- [ufbt](https://github.com/flipperdevices/flipperzero-ufbt) (micro Flipper Build Tool)

### Build & Install

```bash
cd eth_tester
ufbt build              # build only
ufbt launch             # build and run on Flipper via USB
ufbt install            # install .fap to Flipper's SD card
```

The compiled `.fap` file appears in `dist/`. You can also copy it manually to `/ext/apps/GPIO/` on the Flipper's SD card.

---

## Architecture

```
eth_tester/
├── application.fam              # FAP manifest
├── eth_tester_app.c/h           # Entry point, ViewDispatcher, feature logic
├── hal/w5500_hal.c/h            # SPI, GPIO, MACRAW socket management
├── usb_eth/                     # USB CDC-ECM network device
├── bridge/                      # L2 frame forwarding + PCAP dump
├── protocols/                   # 16 network protocol modules
├── utils/                       # OUI lookup, packet parsing
├── assets/icon.png              # FAP icon
└── lib/ioLibrary_Driver/        # WIZnet W5500 driver (vendored copy)
```

### W5500 Socket Allocation

| Socket | Buffer | Usage |
|--------|--------|-------|
| 0 | 8KB RX/TX | MACRAW (promiscuous frame capture) |
| 1 | 2KB | DHCP client |
| 2 | 2KB | ICMP ping / traceroute (IPRAW) |
| 3 | 2KB | DNS / WoL / mDNS / SSDP / File Manager HTTP |
| 4 | 1KB | PXE TFTP listen (port 69) |
| 5 | 1KB | PXE TFTP data transfer |

### Threading Model

- **Main thread** (4KB stack): GUI event loop via ViewDispatcher
- **Worker thread** (8KB stack): created on-demand for long-running operations (scans, listeners, servers)
- Communication: `volatile bool worker_running` flag for cancellation
- Back button stops the worker gracefully

### Memory Model

- Frame buffer (1600B) allocated on heap, shared by worker thread
- Large scan results (ARP hosts, directory listings) heap-allocated
- Text buffers use FuriString (dynamic allocation)
- App stack is 4KB — all large buffers are in the heap

---

## Usage Guide

### Getting Started

1. Connect W5500 module to Flipper Zero using the wiring diagram
2. Plug an Ethernet cable into the RJ45 port
3. Open **GPIO -> LAN Tester** on the Flipper
4. The menu header shows link status: `LAN [UP 100M FD]`

### Network Info

- **Link Info** — PHY status, speed, duplex, MAC. Use first to verify hardware works.
- **DHCP Analyze** — sends Discover, parses Offer. Does **not** take an IP lease. Safe for production networks. Shows: offered IP, server IP, subnet, gateway, DNS, NTP, domain, lease time, DHCP option fingerprint.
- **Statistics** — captures all frames for 10 seconds, shows breakdown by destination type (unicast/broadcast/multicast) and EtherType (IPv4/ARP/IPv6/LLDP/CDP).

### Discovery

- **ARP Scan** — runs DHCP first, then scans the local subnet. Shows IP, last 3 MAC bytes, vendor name. Batch sends (16 ARPs per 15ms) with tail wait for late replies.
- **Ping Sweep** — ICMP sweep of a CIDR range. Auto-detected from DHCP or enter manually (e.g. `192.168.1.0/24`).
- **LLDP/CDP** — passive listener, waits up to 60 seconds for switch advertisements. Shows: system name, port ID, description, management IP, VLAN, capabilities.
- **mDNS/SSDP** — sends mDNS query (`_services._dns-sd._udp.local`) and SSDP M-SEARCH. Collects responses for ~10 seconds.
- **STP/VLAN** — listens 30 seconds for BPDU frames (STP/RSTP/MSTP). Also detects 802.1Q VLAN tags on any passing traffic.

### Diagnostics

- **Ping** — 4 ICMP echo requests with 3s timeout each. Default target: DHCP gateway.
- **Continuous Ping** — real-time RTT graph (128px wide), shows current/avg RTT and loss%. Runs until Back is pressed.
- **DNS Lookup** — resolves a hostname (e.g. `google.com`) to an IP via the DHCP-provided DNS server.
- **Traceroute** — ICMP with incrementing TTL (1-30). Shows each hop's IP and RTT.
- **Port Scan** — TCP connect scan. Top-20 preset: 18 most common ports. Top-100: 100 ports. Shows open/closed/filtered per port.

### Tools

- **Wake-on-LAN** — enter a target MAC address, sends the magic packet via broadcast UDP to port 9.
- **ETH Bridge** — see [ETH Bridge Guide](#eth-bridge-guide) below.
- **PXE Server** — see [PXE Server Guide](#pxe-server-guide) below.
- **File Manager** — see [File Manager Guide](#file-manager-guide) below.

### Settings

- **Auto-save results** — when ON, scan results are saved to SD card history automatically.
- **Sound & vibro** — green LED + vibro on success, red on error.
- **Clear History** — deletes all saved result files.
- **MAC Changer** — generate a random locally-administered MAC or enter a custom one. Saved to SD card, persists across reboots.

---

## PXE Server Guide

The PXE Server turns Flipper into a network boot server for PXE-capable machines.

### Setup

1. Place boot files on SD card at `/ext/apps_data/eth_tester/pxe/`
   - Supported: `.kpxe` (Legacy BIOS), `.efi` (UEFI), `.pxe`, `.0`
   - Recommended: `undionly.kpxe` (~70KB) from [netboot.xyz](https://boot.netboot.xyz)
2. Connect Flipper to target machine via Ethernet (direct cable or through a switch)
3. Open **Tools -> PXE Server**

### DHCP Auto-Detection

When you enter PXE settings, the app automatically probes the network for an existing DHCP server (sends a Discover, waits 5 seconds):

- **External DHCP found**: own DHCP is disabled, Server IP / Client IP / Subnet are populated from the detected network. Flipper acts as TFTP-only server.
- **No external DHCP**: own DHCP is enabled with defaults (192.168.77.x subnet). Flipper provides both DHCP and TFTP.

All IP fields are editable — the auto-detected values are defaults you can override.

### Boot File Selection

If multiple boot files are found in the PXE directory, use left/right arrows on the "Boot File" item to cycle through them (up to 8 files). Preferred files (`undionly.kpxe`, `ipxe.efi`, `snponly.efi`) are listed first.

### Settings Order

1. **Start PXE** — launch the server
2. **DHCP Server** — ON/OFF toggle
3. **Boot File** — select from detected files
4. **Server IP** — Flipper's IP on the PXE network
5. **Client IP** — IP to offer to the booting machine
6. **Subnet Mask**
7. **Help**

### Target Machine BIOS

Enable Network/PXE Boot in BIOS/UEFI settings. Set boot order to Network first.

---

## File Manager Guide

The File Manager starts an HTTP server on port 80 for managing files on the Flipper's microSD card from any browser.

### Auth Token

Each session generates a random 4-character hex token (e.g. `a3f1`). The full URL including the token is displayed on the Flipper screen:

```
http://192.168.1.42/?t=a3f1
```

All HTTP requests require this token as a `?t=XXXX` query parameter. Requests without a valid token receive `403 Forbidden`. The token is automatically included in all links within the web UI.

### Operations

- **Browse** directories on the SD card
- **Download** any file
- **Upload** files via the web form (multipart/form-data)
- **Create** new folders
- **Delete** files and folders (with confirmation dialog)

### How to Use

1. Open **Tools -> File Manager**
2. Flipper runs DHCP to get an IP, then starts the HTTP server
3. The URL with token is shown on screen
4. Open the URL in any browser on the same LAN
5. Press Back on Flipper to stop the server

### Browser Compatibility

Works with any modern browser (Chrome, Firefox, Safari, Edge). The dark-themed UI is responsive and works on both desktop and mobile.

---

## ETH Bridge Guide

The ETH Bridge turns Flipper into a USB-to-Ethernet adapter using the CDC-ECM protocol.

### How It Works

1. Open **Tools -> ETH Bridge**
2. Flipper switches USB to CDC-ECM mode
3. Connect a phone/PC via USB — it sees a new network interface
4. All traffic is bridged at Layer 2 between USB and the W5500 Ethernet port
5. The host gets an IP from the LAN's DHCP server transparently

### PCAP Recording

Press **OK** during bridge operation to start/stop recording traffic to a `.pcap` file on the SD card. Files are saved to `apps_data/eth_tester/pcap/` with timestamped names, compatible with Wireshark.

### Platform Compatibility

- **Linux**: native CDC-ECM support, works out of the box
- **macOS**: native CDC-ECM support
- **Android**: works on most devices with USB OTG
- **Windows**: may require RNDIS driver or third-party CDC-ECM driver

Press **Back** to stop the bridge and restore the original USB profile (CDC Serial for Flipper CLI).

---

## Technical Details

- **W5500 MACRAW mode**: Socket 0 with `MFEN=0` (promiscuous — receives all frames including multicast)
- **Worker thread**: 8KB stack, non-blocking UI via ViewDispatcher + worker pattern
- **DHCP caching**: single negotiation, result reused across all subsequent operations
- **Memory-safe**: bounds checking on all protocol parsers, large buffers heap-allocated
- **Unique MAC**: random MAC generated on first boot using hardware RNG, persisted to SD card. No two devices share the same default MAC.
- **Endianness**: manual big-endian parsing — no `htons`/`ntohs`, no float printf

---

## Security

The following security measures are implemented:

- **Path traversal protection**: all URL paths in File Manager and TFTP filenames are validated — `..` sequences are rejected
- **XSS prevention**: filenames are HTML-escaped before rendering in the File Manager web UI
- **Auth token**: File Manager requires a random session token in all HTTP requests; the token is displayed on the Flipper screen and not accessible over the network
- **Upload sanitization**: uploaded filenames are stripped of path separators (`/`, `\`)
- **DNS validation**: DNS responses are verified to come from the expected server IP
- **mDNS safety**: recursive DNS pointer following is limited to depth 4 to prevent stack overflow from malicious responses
- **Content-Disposition safety**: special characters are stripped from download filenames in HTTP headers

---

## Limitations

These cannot be implemented on Flipper Zero + W5500:

- **802.1X** — requires a full supplicant, insufficient RAM
- **Full 100Mbps Wireshark capture** — SPI limits throughput; PCAP dump in bridge mode captures traffic actually passing through the bridge
- **SNMP queries** — ASN.1 parser too heavy for RAM
- **TLS/HTTPS** — no crypto libraries in FAP SDK

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "W5500 Not Found!" | Check SPI wiring. Verify 3V3 and GND connections. Try replugging the module. |
| "No Link!" | Connect an Ethernet cable. Check cable and remote port. |
| "DHCP failed" | Ensure the network has a DHCP server. Check cable. Try Link Info first. |
| Flipper freezes on Back | Fixed in v1.0 — HTTP socket is force-closed on exit. Update to latest version. |
| File Manager shows 403 | Include the auth token in the URL: `?t=XXXX` (shown on Flipper screen). |
| PXE client doesn't boot | Check BIOS network boot settings. Verify boot file is in `apps_data/eth_tester/pxe/`. |

---

## Third-party Libraries

- **WIZnet ioLibrary_Driver** — vendored copy (not a git submodule) of the [official W5500 driver](https://github.com/Wiznet/ioLibrary_Driver). Provides socket abstraction, DHCP, DNS, and ICMP protocol support. Only W5500/Ethernet/DHCP/DNS/ICMP components are compiled; MQTT, FTP, HTTP, SNMP, SNTP are excluded.

---

## Credits

- Based on [arag0re/fz-eth-troubleshooter](https://github.com/arag0re/fz-eth-troubleshooter) (fork of [karasevia/finik_eth](https://github.com/karasevia/finik_eth))
- Uses [WIZnet ioLibrary_Driver](https://github.com/Wiznet/ioLibrary_Driver) for W5500 hardware abstraction
- Built for [Flipper Zero OFW](https://github.com/flipperdevices/flipperzero-firmware)

## License

MIT License. See [LICENSE](../../LICENSE) for details.
