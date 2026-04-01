# Security Audit Report: fz-W5500-lan-analyse (LAN Tester for Flipper Zero)

**Date:** 2026-04-01
**Auditor:** Claude (Embedded Security Audit)
**Version:** 1.0a (commit 3183699)
**Scope:** Full source code audit of all application files (excluding vendored ioLibrary_Driver)

---

## Executive Summary

The application is a comprehensive Ethernet LAN analyzer for Flipper Zero using the W5500 SPI Ethernet module. It implements LLDP/CDP discovery, ARP scanning, DHCP analysis, DNS lookup, ping/traceroute, port scanning, Wake-on-LAN, mDNS/SSDP discovery, STP/VLAN detection, USB-Ethernet bridge with PCAP capture, PXE server (DHCP+TFTP), and an HTTP-based SD card file manager.

Overall the code quality is good for an embedded hobbyist project. The protocol parsers are well-bounded, memory management follows Flipper Zero patterns correctly, and the worker thread architecture is sound. However, 24 issues were identified ranging from **critical** (path traversal in HTTP file manager) to **informational** (dead code, minor resource leaks).

**Note on Flipper Zero platform:** FAPs run in the same address space as firmware with no sandboxing. `malloc` halts on failure (never returns NULL). Thread priority is 16 (lower than system timer at 2), so long-running operations without `furi_delay_ms()` can starve system services.

---

## Findings

### CRITICAL

#### 1. Path Traversal in HTTP File Manager (CWE-22)
**File:** `protocols/file_manager.c:799-806, 822, 861-878`
**Severity:** CRITICAL

The `web_to_sd_path()` function blindly concatenates user-controlled URL paths with `/ext` prefix:
```c
static void web_to_sd_path(const char* web_path, char* sd_path, size_t sd_size) {
    if(web_path[0] == '\0' || strcmp(web_path, "/") == 0) {
        strncpy(sd_path, "/ext", sd_size);
    } else {
        snprintf(sd_path, sd_size, "/ext%s", web_path);
    }
}
```

An attacker on the local network can craft URLs like `/browse/../../int` or `/download/../../../any/path` to escape the `/ext` SD card directory and access internal Flipper filesystem paths. While `url_decode()` is applied to the URI, it does NOT sanitize `../` sequences.

The `/delete` endpoint is particularly dangerous as it calls `storage_simply_remove()` on the attacker-controlled path, potentially deleting critical system files:
```c
static void handle_delete(uint8_t sn, const char* sd_path, ...) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    storage_simply_remove(storage, sd_path);  // No path validation!
}
```

Similarly, `/upload` allows writing arbitrary files to any Flipper filesystem location, and `/mkdir` allows creating directories anywhere.

**Impact:** Any device on the same LAN segment can read, write, and delete arbitrary files on the Flipper Zero filesystem when File Manager is active.

**Recommendation:** Add path canonicalization and validation:
- Reject any path containing `..` components
- Verify the resolved path starts with `/ext/`
- Consider restricting to `/ext/apps_data/eth_tester/` only

#### 2. No Authentication on HTTP File Manager (CWE-306)
**File:** `protocols/file_manager.c`
**Severity:** CRITICAL

The HTTP file manager listens on port 80 with zero authentication. Any device on the LAN can browse, upload, download, and delete files. There is no password, no token, no IP whitelist.

**Impact:** Combined with the path traversal above, this gives any LAN device full filesystem access.

**Recommendation:** At minimum, display the server IP and a random access token on the Flipper screen, and require the token as a URL parameter or HTTP header. Alternatively, restrict to a single client IP (first to connect).

#### 3. No Authentication on PXE/DHCP Server (CWE-306)
**File:** `protocols/pxe_server.c`
**Severity:** HIGH

The PXE server runs a fully open DHCP server on the network. If accidentally started on a production network (instead of a direct cable), it will answer DHCP requests from any device, potentially:
- Causing IP address conflicts
- Redirecting devices to boot from the Flipper's TFTP server
- Disrupting network operations (rogue DHCP)

**Impact:** Accidental or deliberate network disruption. A rogue DHCP server is a serious network security concern.

**Recommendation:**
- Show a prominent warning when starting PXE on a network with existing DHCP
- Consider checking for existing DHCP servers before starting
- Add a confirmation dialog

---

### HIGH

#### 4. XSS in File Manager HTML Output (CWE-79)
**File:** `protocols/file_manager.c:339-374`
**Severity:** HIGH

File and directory names are inserted directly into HTML without escaping:
```c
http_send_str(sn, entries[i].name);  // Directly in HTML table
```

A maliciously-crafted filename like `<script>alert(1)</script>.txt` on the SD card would execute JavaScript in the browser of anyone using the File Manager. This could be used to:
- Steal cookies/session data from other tabs
- Redirect the user to a malicious site
- Make additional requests to the Flipper via the File Manager API

**Impact:** Persistent XSS via crafted filenames on SD card.

**Recommendation:** Implement HTML entity escaping for all user-controlled strings (`<`, `>`, `&`, `"`, `'`) before inserting into HTML.

#### 5. Filename Injection in Upload (CWE-22)
**File:** `protocols/file_manager.c:535-554, 569-580`
**Severity:** HIGH

The uploaded filename is extracted from the `Content-Disposition` header and used directly in the file path without sanitization:
```c
char* fn_ptr = strstr((char*)buf, "filename=\"");
// ... extract filename ...
memcpy(filepath + dir_len + 1, filename, name_len + 1);
```

A crafted `filename="../../int/important_file"` in the multipart header allows writing files outside the intended directory (compounding the path traversal issue).

**Recommendation:** Strip all path separators (`/`, `\`) from the extracted filename. Reject filenames containing `..`.

#### 6. TFTP Path Traversal in PXE Server (CWE-22)
**File:** `protocols/pxe_server.c:303-309`
**Severity:** HIGH

The TFTP filename from the client is used directly in a path construction:
```c
char* filename = (char*)(buf + 2);
char filepath[128];
snprintf(filepath, sizeof(filepath), "%s/%s", PXE_BOOT_DIR, filename);
```

A TFTP client can request `../../ext/any/file` to read arbitrary files from the Flipper's filesystem via TFTP.

**Recommendation:** Validate the filename contains no `/` or `..` sequences. Only serve files from the PXE boot directory.

#### 7. Stack-Allocated Buffers with Unchecked Sizes (CWE-120)
**File:** `protocols/file_manager.c:528-532`
**Severity:** MEDIUM-HIGH

The multipart boundary is extracted into a fixed 80-byte stack buffer:
```c
char boundary[80];
size_t boundary_len = boundary_end - (char*)buf;
if(boundary_len >= sizeof(boundary)) boundary_len = sizeof(boundary) - 1;
```

While truncation is handled, a truncated boundary will cause the boundary detection logic to never find the end of the upload, leading to the upload writing indefinitely until the SD card is full or the connection closes.

---

### MEDIUM

#### 8. Insufficient Stack Size (CWE-770)
**File:** `application.fam:8`
**Severity:** MEDIUM

The main app stack is configured as `4 * 1024` (4KB), while the worker thread gets `8 * 1024` (8KB). Several functions use significant stack:
- `lldp_format_neighbor` uses a 512-byte local buffer
- `cdp_format_neighbor` uses a 512-byte local buffer
- `bridge_draw_callback` and `cont_ping_draw_callback` use `char buf[64]`
- `handle_connection` uses `char uri[256]` + `char method[8]`
- Various `snprintf` calls with large local buffers

The 4KB main stack could overflow with deep call chains through ViewDispatcher callbacks.

**Recommendation:** Increase `stack_size` to at least `8 * 1024` or audit all view callbacks for stack depth.

#### 9. Race Condition in Worker Thread Flag (CWE-362)
**File:** `eth_tester_app.h:139`, `eth_tester_app.c:1322-1363`
**Severity:** MEDIUM

The `worker_running` flag is `volatile bool` but is accessed from both the main thread (setting it to false) and the worker thread (reading it in loops). While `volatile` prevents compiler optimization, it does NOT provide memory ordering guarantees on ARM Cortex-M. In practice this works on the STM32 used in Flipper Zero due to single-core architecture, but it's technically undefined behavior and would break on multi-core systems.

More importantly, `eth_tester_worker_start()` sets `worker_running = false` to signal the old worker, then immediately sets it to `true` for the new worker before calling `furi_thread_join()`. If the old worker hasn't checked the flag yet, it may see `true` and never stop:
```c
app->worker_running = false;  // Signal old worker
// ... thread join ...
app->worker_running = true;   // For new worker - but old may still be running!
```

**Recommendation:** Use `furi_thread_join()` to wait for the old worker to fully stop before starting a new one (which is already done, but the flag ordering is fragile).

#### 10. Hardcoded Default MAC Address (CWE-798)
**File:** `eth_tester_app.c:84`
**Severity:** MEDIUM

```c
#define DEFAULT_MAC { 0x00, 0x08, 0xDC, 0x47, 0x47, 0x54 }
```

All instances of the application use the same default MAC address. If multiple Flipper devices run this app on the same network simultaneously, MAC address conflicts will occur causing network issues. The WIZnet OUI `00:08:DC` is shared across all WIZnet products.

**Recommendation:** Generate a random locally-administered MAC on first boot and persist it, or derive it from the Flipper's unique hardware ID.

#### 11. DHCP Buffer on Heap Without Size Validation (CWE-120)
**File:** `eth_tester_app.c:1431`
**Severity:** MEDIUM

```c
uint8_t* dhcp_buffer = malloc(1024);
```

The DHCP receive buffer is 1024 bytes, but there's no check that received DHCP packets fit within this. The WIZnet `DHCP_run()` function uses this buffer internally and may overflow it with a crafted DHCP response exceeding 1024 bytes.

**Recommendation:** Verify the WIZnet DHCP library's buffer size requirements and ensure the allocation matches.

#### 12. DNS Response Spoofing (CWE-290)
**File:** `protocols/dns_lookup.c:220-240`
**Severity:** MEDIUM

DNS responses are accepted from any source IP, only validated by transaction ID (16-bit). An attacker on the same network can race the legitimate DNS server and send forged responses. The 16-bit transaction ID space is trivially brute-forceable.

**Recommendation:** Validate that the response comes from the expected DNS server IP. Consider using a random source port for additional entropy.

#### 13. USB Frame Buffer Concurrency (CWE-362)
**File:** `usb_eth/usb_descriptors.c:80-84, 267-293`
**Severity:** MEDIUM

The USB RX frame buffer is shared between the USB interrupt context (writing) and the main/worker thread (reading):
```c
static uint8_t usb_rx_frame[USB_FRAME_BUF_SIZE];
static volatile uint16_t usb_rx_frame_pos = 0;
static volatile uint16_t usb_rx_frame_len = 0;
static volatile bool usb_rx_frame_ready = false;
```

There's no mutex or critical section protecting the buffer. The USB callback writes to the buffer while the worker thread reads it, potentially causing torn reads. `volatile` does not provide atomicity for multi-byte operations.

**Recommendation:** Use `FURI_CRITICAL_ENTER()`/`FURI_CRITICAL_EXIT()` around buffer access, or use a double-buffer scheme.

#### 14. USB TX Pointer to Caller's Stack/Buffer (CWE-416)
**File:** `usb_eth/usb_descriptors.c:461-491`
**Severity:** MEDIUM

`usb_eth_send_frame_internal()` stores a raw pointer to the caller's frame buffer:
```c
usb_tx_data = frame;  // Points to caller's buffer
```

The TX callback fires asynchronously from the USB interrupt. If the caller frees or reuses the buffer before the TX completes, the USB interrupt will read freed memory. The busy-wait loop (20ms timeout) partially mitigates this, but a forced reset path sets `usb_tx_busy = false` while data may still be in the USB peripheral's FIFO.

**Recommendation:** Copy frame data to a dedicated TX buffer, or ensure the caller's buffer lifetime exceeds the USB TX completion.

---

### LOW

#### 15. Missing CSRF Protection on File Manager (CWE-352)
**File:** `protocols/file_manager.c`
**Severity:** LOW

The HTTP file manager uses GET requests for destructive operations (delete) and has no CSRF tokens. A malicious website could trigger file deletions via `<img>` tags:
```html
<img src="http://192.168.1.x/delete/path/to/file">
```

The JavaScript `confirm()` dialog on the delete button only works in the browser UI, not for programmatic requests.

**Recommendation:** Use POST for destructive operations with a CSRF token, or at minimum check the `Referer` header.

#### 16. Content-Disposition Header Injection (CWE-113)
**File:** `protocols/file_manager.c:432-435`
**Severity:** LOW

The filename in the download response header is not sanitized:
```c
snprintf(hdr, sizeof(hdr),
    "Content-Disposition: attachment; filename=\"%.48s\"\r\n", filename);
```

While truncated to 48 chars, a filename containing `"` or `\r\n` could break HTTP header parsing (HTTP response splitting).

**Recommendation:** Escape or strip special characters from the filename.

#### 17. Potential Integer Overflow in Ping Graph (CWE-190)
**File:** `eth_tester_app.c:346`
**Severity:** LOW

```c
max_rtt = max_rtt + max_rtt / 10 + 1;
```

If `max_rtt` approaches `UINT32_MAX`, this expression overflows. In practice, RTT values are limited to timeout durations (typically < 10,000ms), making this theoretical.

#### 18. mDNS Recursive Pointer Following Without Depth Limit (CWE-674)
**File:** `protocols/discovery.c:82-86`
**Severity:** MEDIUM

The `dns_read_name()` function follows DNS compression pointers recursively without a depth limit:
```c
if((label_len & 0xC0) == 0xC0) {
    uint16_t ptr = ((uint16_t)(label_len & 0x3F) << 8) | buf[pos + 1];
    dns_read_name(buf, len, ptr, out + out_pos, out_size - out_pos);  // recursive!
    return offset + 2;
}
```

A malicious mDNS response with circular pointer references (pointer A -> pointer B -> pointer A) will cause unbounded recursion, overflowing the worker thread's 8KB stack and crashing the Flipper.

**Impact:** Denial of service from any device on the LAN sending a crafted mDNS response.

**Recommendation:** Add a recursion depth counter (max 4-5 levels per RFC 1035) or use an iterative approach.

#### 19. SPI Acquire Without Error Check (CWE-252)
**File:** `hal/w5500_hal.c:58`
**Severity:** LOW

```c
furi_hal_spi_acquire(&furi_hal_spi_bus_handle_external);
spi_acquired = true;  // Assumed success
```

`furi_hal_spi_acquire()` return value is not checked. If another app holds the SPI bus, subsequent operations will be undefined.

**Recommendation:** Check return value and fail gracefully if SPI cannot be acquired.

#### 20. Dead Code: malloc NULL Check on Flipper Zero (CWE-561)
**File:** `eth_tester_app.c:418`
**Severity:** INFORMATIONAL

```c
HistoryState* hs = malloc(sizeof(HistoryState));
if(hs) {  // Dead code: Flipper's malloc halts on failure, never returns NULL
```

On Flipper Zero, `malloc` calls `furi_check` internally and halts the firmware on allocation failure rather than returning NULL. All `if(ptr)` checks after `malloc` are dead code. This is not a bug but is misleading to readers.

**Note:** The `furi_assert(app->frame_buf)` calls elsewhere are also redundant for the same reason.

#### 21. Global Mutable State (CWE-362)
**File:** `eth_tester_app.c:51`
**Severity:** LOW

```c
static EthTesterApp* g_app = NULL;
```

A global pointer is used for navigation callbacks. While Flipper Zero apps are single-instance, this pattern is fragile and prevents future multi-instance use.

#### 22. SPI Bus Not Released on Error Path (CWE-404)
**File:** `hal/w5500_hal.c:50-76`
**Severity:** LOW

If `w5500_hal_init()` succeeds (acquiring SPI) but subsequent operations fail in `eth_tester_ensure_w5500()`, the error handler calls `w5500_hal_deinit()` which releases SPI. However, if the application crashes between `w5500_hal_init()` and the error check, the SPI bus remains locked, blocking other Flipper applications from using the external SPI.

#### 23. PCAP Dump Uses Global State (CWE-362)
**File:** `bridge/pcap_dump.c:42-47`
**Severity:** LOW

```c
static Storage* pcap_storage = NULL;
static File* pcap_file = NULL;
```

Global state means only one PCAP capture can be active at a time (which is fine for the current design), but there's no guard against calling `pcap_dump_start()` twice without stopping.

#### 24. Unused Port Scan Entries
**File:** `protocols/port_scan.c:10-13`
**Severity:** INFORMATIONAL

`PORT_PRESET_TOP20` contains only 18 entries, not 20 as the name implies.

---

## Architecture Observations

### Positive Aspects
1. **Clean separation of concerns** - HAL, protocols, utilities, and UI are well-separated
2. **Proper use of Flipper Zero APIs** - ViewDispatcher, TextBox, FuriString, FuriTimer patterns are correct
3. **Bounded protocol parsing** - LLDP, CDP, DHCP, DNS parsers all check lengths before accessing data
4. **Heap allocation for large buffers** - Frame buffers and scan state are heap-allocated, not stack
5. **Worker thread pattern** - Long operations run in a background thread, keeping UI responsive
6. **Graceful cleanup** - `eth_tester_app_free()` properly releases all allocated resources

### Areas for Improvement
1. **File manager security** is the weakest point - it needs authentication, path validation, and output encoding
2. **PXE server** needs safety guards against accidental deployment on production networks
3. **USB ECM driver** has concurrency concerns that could cause intermittent bridge failures
4. **Error handling** is inconsistent - some paths assert, others silently fail

---

## Recommended Priority Fixes

| Priority | Finding | Effort |
|----------|---------|--------|
| P0 | #1 Path traversal in File Manager | Low |
| P0 | #5 Filename injection in Upload | Low |
| P0 | #6 TFTP path traversal | Low |
| P1 | #2 Authentication on File Manager | Medium |
| P1 | #4 XSS in File Manager HTML | Medium |
| P1 | #3 PXE server safety warnings | Low |
| P2 | #13 USB frame buffer concurrency | Medium |
| P2 | #14 USB TX pointer lifetime | Medium |
| P2 | #9 Worker thread race condition | Low |
| P2 | #18 mDNS recursive pointer stack overflow | Low |
| P3 | #10 Hardcoded MAC address | Low |
| P3 | #12 DNS response validation | Low |
