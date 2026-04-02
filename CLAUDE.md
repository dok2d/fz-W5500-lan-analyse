# CLAUDE.md — Agent Guidelines for fz-W5500-lan-analyse

## Project

Flipper Zero LAN Tester — portable Ethernet analyzer & security toolkit using W5500 SPI module. C99, ufbt build system, ~130 KB heap, 4 KB stack.

## Build & Verify

```bash
ufbt build          # must pass with zero warnings (treated as errors)
```

Always build after changes. Never push code that doesn't compile.

## Critical Constraints

### Memory (most important)
- **130 KB heap total** — every malloc matters. Prefer reusing existing buffers.
- **4 KB stack** — no arrays >128 bytes on stack. Use `malloc`/`free` or `app->frame_buf` (1600 B shared buffer, available after W5500 init).
- **One worker thread at a time** — all tools share `text_box_tool`, `tool_text`, `text_input_tool`, `byte_input_tool`. Set `app->tool_back_view` before switching to `LanTesterViewToolResult`.
- **WIZnet DHCP_init() keeps pointer** — never pass `frame_buf` to `DHCP_init()`. DHCP needs its own `malloc(1024)`.
- **OOM-prone operations**: ARP scan (hosts array), Discovery (device array), History (file list). Keep caps low, structs small.
- After malloc, always check for NULL. After use, always free. No exceptions.

### HAL / Hardware
- `w5500_hal_init()`: acquires SPI **first**, then enables OTG. This order prevents resource leaks if SPI hangs.
- `w5500_hal_deinit()`: idempotent — safe to call without prior init, safe to call multiple times.
- `app_free()` calls `deinit()` unconditionally — handles partial init and crash recovery.
- `furi_hal_power_disable_otg()`: check `is_otg_enabled()` first to avoid ref-count underflow.

### UI / Views
- One shared `TextBox` (`text_box_tool`) for ALL tool results (except `text_box_autotest`, `text_box_about`, `text_box_pxe_help`).
- One shared `FuriString` (`tool_text`) for ALL tool output.
- One shared `TextInput` (`text_input_tool`) and `ByteInput` (`byte_input_tool`) — separate view IDs (`LanTesterViewToolInput` vs `LanTesterViewToolByteInput`). Never register both under the same view ID.
- Set `app->tool_back_view = LanTesterViewCatXxx` before launching any tool.
- `nav_back_tool()` handles: stop running worker on first Back, return to category on second Back, repopulate History on return to History view.

## Code Style

- C99, 4 spaces, 99 columns, K&R braces, `snake_case`
- `#include <furi.h>` **before** `#include <socket.h>` — prevents STM32 CMSIS `MR` macro conflict with W5500 headers.
- No `\n\n` in output strings — Flipper screen is 128×64 px (~6 text lines). Every line counts.
- Labels and values on same line: `"Name: %s\n"` not `"Name:\n  %s\n"`.
- Tool output header: `"[ToolName] %s\n"` — one line, no blank line after.

## Adding a New Tool

1. **Protocol**: `protocols/new_tool.c` + `protocols/new_tool.h` — pure logic, no UI. Include `<furi.h>` before `<socket.h>`.
2. **Menu item**: add to `LanTesterMenuItem` enum in `lan_tester_app.h`.
3. **Input buffers**: add small fields (IP, hostname) to app struct. No TextBox/FuriString — use shared ones.
4. **Submenu**: add to appropriate category submenu in `lan_tester_app_alloc()`.
5. **Worker dispatch**: add case to `lan_tester_worker_fn()` → call `lan_tester_do_xxx(app)` → `lan_tester_update_view(app->text_box_tool, app->tool_text)`.
6. **Submenu callback**: set `app->tool_back_view`, show IP keyboard or text input, start worker.
7. **do_xxx function**: use `app->tool_text` for output, `app->frame_buf` for network I/O (if not DHCP). Call `lan_tester_save_and_notify()` at end.
8. **No new TextBox/FuriString/TextInput allocations** — use the shared ones.

## Documentation

When adding features, update ALL of:
- `CHANGELOG.md` (English, user-facing language, no programmer jargon)
- `README.md` (feature table EN + RU sections, architecture tree)
- `docs/en/README.md` + `docs/ru/README.md` (feature tables)
- `lan_tester_app.c` About view (if version bumped)
- `application.fam` (version, description)

## Don't

- Don't add `\n\n` to output — screen is tiny
- Don't `malloc` without checking NULL and having a `free` path
- Don't put >128 byte arrays on stack
- Don't register two different widgets under the same view ID
- Don't share `frame_buf` with `DHCP_init()` (WIZnet keeps the pointer)
- Don't call `furi_hal_power_disable_otg()` without checking `is_otg_enabled()`
- Don't allocate new TextBox/FuriString per tool — use shared `text_box_tool`/`tool_text`
- Don't modify files under `lib/ioLibrary_Driver/` — vendored, read-only
