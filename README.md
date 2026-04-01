# Flipper Zero LAN Tester (W5500)

> **[Русская версия ниже / Russian version below](#русская-версия)**

Turn your **Flipper Zero + W5500 Lite** module into a professional-grade portable LAN tester. Analyze Ethernet links, discover network neighbors, scan subnets, fingerprint DHCP servers --- all from a pocket-sized device.

![Flipper Zero](https://img.shields.io/badge/Flipper%20Zero-OFW-orange)
![License](https://img.shields.io/badge/license-MIT-blue)
![Language](https://img.shields.io/badge/language-C99-green)
![Build](https://img.shields.io/badge/build-ufbt-yellow)
![Version](https://img.shields.io/badge/version-0.9-brightgreen)

---

## Features

| Feature | Description |
|---|---|
| **Link Info** | PHY link status, speed (10/100 Mbps), duplex (Half/Full), MAC address, W5500 version check |
| **DHCP Analyzer** | Discover-only analysis (no IP lease taken), option fingerprinting, full offer parsing |
| **ARP Scanner** | Active subnet scan with batch requests, OUI vendor lookup (~120 vendors), duplicate detection |
| **Ping** | Echo request/reply to any IP with RTT measurement (4 pings, 3s timeout) |
| **Continuous Ping** | Real-time RTT graph with min/max/avg and packet loss percentage |
| **DNS Lookup** | Resolve hostnames via UDP DNS using DHCP-provided DNS server |
| **Traceroute** | ICMP-based hop-by-hop path discovery with per-hop RTT |
| **Ping Sweep** | ICMP sweep of an entire subnet, CIDR auto-detected from DHCP |
| **Port Scanner** | TCP connect scan with Top-20 (quick) and Top-100 (full) presets |
| **LLDP/CDP** | Passive IEEE 802.1AB & Cisco CDP neighbor discovery with full TLV parsing |
| **mDNS/SSDP** | Discover services and devices via multicast DNS and UPnP/SSDP |
| **STP/VLAN** | Passive BPDU listener + 802.1Q VLAN tag detection |
| **Statistics** | Frame counters by type (unicast/broadcast/multicast) and EtherType |
| **Wake-on-LAN** | Send magic packets to any MAC address |
| **MAC Changer** | Randomize or set custom MAC, persisted to SD card |
| **History** | All scan results auto-saved with timestamps, browsable and deletable |
| **Settings** | Toggle auto-save and sound/vibro notifications, clear history |

### UX Highlights

- **Hierarchical menu**: features grouped into Network Info, Discovery, Diagnostics, Tools
- **Link status in header**: see UP/DOWN, speed, duplex without entering Link Info
- **DHCP caching**: single negotiation shared across all operations — no repeated 15s waits
- **Visual progress**: countdown timers for listeners, ASCII progress bars for scans
- **LED/vibro feedback**: green blink on success, red on error (optional, toggle in Settings)
- **Smart defaults**: IP inputs pre-populated with DHCP gateway

## Hardware

### Required

- **Flipper Zero** (OFW firmware)
- **W5500 Lite** Ethernet module (or any W5500-based board with SPI)

### Wiring

```
W5500 Module    Flipper Zero GPIO
─────────────   ─────────────────
MOSI (MO)   →   A7  (pin 2)
SCLK (SCK)  →   B3  (pin 5)
CS   (nSS)  →   A4  (pin 4)
MISO (MI)   →   A6  (pin 3)
RESET (RST) →   C3  (pin 7)
3V3  (VCC)  →   3V3 (pin 9)
GND  (G)    →   GND (pin 8 or 11)
```

> The W5500 is powered via Flipper's OTG 3.3V output, which is enabled automatically when the app starts.

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

The compiled `.fap` file will appear in `dist/`. You can also copy it manually to the Flipper's SD card at `/ext/apps/GPIO/`.

## Architecture

```
eth_tester/
├── application.fam              # FAP manifest
├── eth_tester_app.c             # Entry point, ViewDispatcher, feature logic
├── eth_tester_app.h             # Shared types and app state
│
├── hal/
│   ├── w5500_hal.c              # SPI, GPIO, MACRAW socket management
│   └── w5500_hal.h
│
├── protocols/
│   ├── lldp.c / lldp.h         # IEEE 802.1AB LLDP parser
│   ├── cdp.c / cdp.h           # Cisco CDP parser (LLC/SNAP)
│   ├── arp_scan.c / arp_scan.h  # ARP request builder & reply parser
│   ├── dhcp_discover.c / .h     # DHCP Discover builder & Offer parser
│   ├── icmp.c / icmp.h         # ICMP Echo (ping) via IPRAW
│   ├── dns_lookup.c / .h       # DNS A-record resolver via UDP
│   ├── wol.c / .h              # Wake-on-LAN magic packet
│   ├── port_scan.c / .h        # TCP connect port scanner
│   ├── traceroute.c / .h       # ICMP traceroute with TTL
│   ├── ping_graph.c / .h       # Ring buffer RTT graph for continuous ping
│   ├── discovery.c / .h        # mDNS + SSDP service discovery
│   ├── stp_vlan.c / .h         # STP BPDU parser + 802.1Q VLAN detection
│   ├── mac_changer.c / .h      # Random/custom MAC with SD persistence
│   └── history.c / .h          # Timestamped result storage on SD card
│
├── utils/
│   ├── oui_lookup.c / .h       # MAC → Vendor (top ~120 OUI prefixes)
│   └── packet_utils.c / .h     # Endian helpers, checksums, formatters
│
├── assets/
│   └── icon.png                 # 10x10 FAP icon
│
└── lib/
    └── ioLibrary_Driver/        # WIZnet W5500 driver
```

## Usage

1. Connect the W5500 module to Flipper Zero using the wiring diagram above
2. Plug an Ethernet cable into the W5500's RJ45 port
3. Open **GPIO → LAN Tester** on the Flipper
4. The menu header shows link status (e.g. `LAN [UP 100M FD]`)
5. Select a category and then a tool:

### Network Info
- **Link Info** — link status, speed, duplex, MAC. Use first to verify hardware.
- **DHCP Analyze** — sends Discover, parses Offer. Does **not** take an IP lease.
- **Statistics** — captures frames for 10s, shows breakdown by type and EtherType.

### Discovery
- **ARP Scan** — scans local subnet via DHCP-detected range, shows IP/MAC/vendor.
- **Ping Sweep** — ICMP sweep of a CIDR range, auto-detected or manually entered.
- **LLDP/CDP** — listens up to 60s for switch neighbor advertisements.
- **mDNS/SSDP** — discovers services via multicast DNS and UPnP.
- **STP/VLAN** — listens 30s for BPDU frames and 802.1Q VLAN tags.

### Diagnostics
- **Ping** — 4 pings to any IP (default: gateway from DHCP).
- **Continuous Ping** — live RTT graph with loss tracking, runs until Back.
- **DNS Lookup** — resolves a hostname via the DHCP-provided DNS server.
- **Traceroute** — hop-by-hop ICMP path discovery up to 30 hops.
- **Port Scan (Top 20/100)** — TCP connect scan of common ports.

### Tools
- **Wake-on-LAN** — send magic packet to wake a device by MAC address.
- **MAC Changer** — generate random MAC or enter custom, saved to SD.

### Settings
- **Auto-save results** — ON/OFF, controls automatic history saving.
- **Sound & vibro** — ON/OFF, controls LED/vibro notifications.
- **Clear History** — delete all saved result files.

## Technical Details

- **W5500 MACRAW mode**: Socket 0 with `MFEN=0` (promiscuous --- receives all frames including multicast)
- **Worker thread**: 8 KB stack, non-blocking UI via ViewDispatcher + worker pattern
- **DHCP caching**: single negotiation, result reused across all subsequent operations
- **Memory-safe**: large buffers heap-allocated, frame buffer on heap (4 KB app stack), bounds checking on all parsers
- **Endianness**: manual big-endian parsing --- no float printf, no `htons`/`ntohs`

## OUI Vendor Database

The built-in lookup table covers ~120 common OUI prefixes including:

> Cisco, HP/HPE, Dell, Intel, Broadcom, Realtek, Apple, Samsung, Huawei, TP-Link, Ubiquiti, Juniper, Arista, MikroTik, Netgear, ASUS, D-Link, Synology, QNAP, VMware, Microsoft, Google, Amazon, Lenovo, Supermicro, Aruba, Fortinet, Palo Alto, WIZnet, Raspberry Pi, Espressif, and more.

## Credits

- Based on [arag0re/fz-eth-troubleshooter](https://github.com/arag0re/fz-eth-troubleshooter) (fork of [karasevia/finik_eth](https://github.com/karasevia/finik_eth))
- Uses [WIZnet ioLibrary_Driver](https://github.com/Wiznet/ioLibrary_Driver) for W5500 hardware abstraction
- Built for [Flipper Zero OFW](https://github.com/flipperdevices/flipperzero-firmware)

## License

MIT License. See [LICENSE](LICENSE) for details.

---

---

# Русская версия

# Flipper Zero LAN Тестер (W5500)

Превратите **Flipper Zero + модуль W5500 Lite** в профессиональный портативный LAN-тестер. Анализ Ethernet-соединений, обнаружение сетевых соседей, сканирование подсетей, фингерпринтинг DHCP-серверов --- всё с устройства, помещающегося в карман.

---

## Возможности

| Функция | Описание |
|---|---|
| **Link Info** | Статус PHY-линка, скорость (10/100 Мбит/с), дуплекс, MAC-адрес, версия W5500 |
| **DHCP Analyzer** | Анализ Discover/Offer (IP не берётся!), фингерпринтинг опций |
| **ARP Scanner** | Сканирование подсети с определением вендора по OUI (~120 производителей) |
| **Ping** | Echo Request/Reply на любой IP с измерением RTT (4 пинга, таймаут 3с) |
| **Continuous Ping** | Графики RTT в реальном времени с min/max/avg и процентом потерь |
| **DNS Lookup** | Разрешение имён через UDP DNS сервер из DHCP |
| **Traceroute** | ICMP трассировка маршрута с RTT на каждый хоп |
| **Ping Sweep** | ICMP-сканирование всей подсети, CIDR автоопределяется из DHCP |
| **Port Scanner** | TCP connect-сканирование: Top-20 (быстро) и Top-100 (полно) |
| **LLDP/CDP** | Пассивное обнаружение соседей IEEE 802.1AB и Cisco CDP |
| **mDNS/SSDP** | Обнаружение сервисов через multicast DNS и UPnP/SSDP |
| **STP/VLAN** | Пассивный захват BPDU + определение 802.1Q VLAN-тегов |
| **Статистика** | Счётчики фреймов по типу и EtherType |
| **Wake-on-LAN** | Отправка magic-пакетов на любой MAC-адрес |
| **MAC Changer** | Рандомизация или ручной ввод MAC, сохранение на SD |
| **История** | Все результаты автосохраняются с метками времени, просмотр и удаление |
| **Настройки** | Переключение автосохранения и звука/вибрации, очистка истории |

### UX-особенности

- **Иерархическое меню**: функции сгруппированы в Network Info, Discovery, Diagnostics, Tools
- **Статус линка в заголовке**: UP/DOWN, скорость, дуплекс видны сразу
- **Кеширование DHCP**: одна DHCP-сессия на всё — не ждёте 15 секунд каждый раз
- **Визуальный прогресс**: таймеры обратного отсчёта для прослушиваний, прогрессбары для сканов
- **LED/вибро оповещения**: зелёный при успехе, красный при ошибке (опционально)
- **Умные дефолты**: IP-поля предзаполнены шлюзом из DHCP

## Оборудование

### Необходимо

- **Flipper Zero** (официальная прошивка OFW)
- **W5500 Lite** Ethernet-модуль (или любая плата на W5500 с SPI)

### Подключение

```
Модуль W5500     GPIO Flipper Zero
─────────────    ─────────────────
MOSI (MO)    →    A7  (пин 2)
SCLK (SCK)   →    B3  (пин 5)
CS   (nSS)   →    A4  (пин 4)
MISO (MI)    →    A6  (пин 3)
RESET (RST)  →    C3  (пин 7)
3V3  (VCC)   →    3V3 (пин 9)
GND  (G)     →    GND (пин 8 или 11)
```

> W5500 питается через OTG 3.3В Flipper'а, который включается автоматически при запуске приложения.

## Сборка

### Требования

- [ufbt](https://github.com/flipperdevices/flipperzero-ufbt) (micro Flipper Build Tool)

### Сборка и установка

```bash
cd eth_tester
ufbt build              # только сборка
ufbt launch             # сборка и запуск на Flipper через USB
ufbt install            # установка .fap на SD-карту Flipper
```

Скомпилированный `.fap` файл появится в `dist/`. Его также можно скопировать вручную на SD-карту Flipper'а в `/ext/apps/GPIO/`.

## Архитектура

```
eth_tester/
├── application.fam              # Манифест FAP
├── eth_tester_app.c             # Точка входа, ViewDispatcher, логика функций
├── eth_tester_app.h             # Общие типы и состояние приложения
│
├── hal/                         # Hardware Abstraction Layer
│   ├── w5500_hal.c              # SPI, GPIO, управление MACRAW-сокетом
│   └── w5500_hal.h
│
├── protocols/                   # Парсеры и генераторы протоколов
│   ├── lldp.c / lldp.h         # Парсер IEEE 802.1AB LLDP
│   ├── cdp.c / cdp.h           # Парсер Cisco CDP (LLC/SNAP)
│   ├── arp_scan.c / arp_scan.h  # ARP-запросы и парсер ответов
│   ├── dhcp_discover.c / .h     # DHCP Discover/Offer
│   ├── icmp.c / icmp.h         # ICMP Echo (ping) через IPRAW
│   ├── dns_lookup.c / .h       # DNS A-запросы через UDP
│   ├── wol.c / .h              # Wake-on-LAN magic packet
│   ├── port_scan.c / .h        # TCP connect сканер портов
│   ├── traceroute.c / .h       # ICMP traceroute с TTL
│   ├── ping_graph.c / .h       # Кольцевой буфер RTT для continuous ping
│   ├── discovery.c / .h        # mDNS + SSDP обнаружение
│   ├── stp_vlan.c / .h         # STP BPDU + 802.1Q VLAN
│   ├── mac_changer.c / .h      # Смена MAC с сохранением на SD
│   └── history.c / .h          # Хранение результатов на SD
│
├── utils/
│   ├── oui_lookup.c / .h       # MAC → Вендор (~120 OUI-префиксов)
│   └── packet_utils.c / .h     # Байтовый порядок, контрольные суммы
│
├── assets/
│   └── icon.png                 # Иконка FAP 10x10
│
└── lib/
    └── ioLibrary_Driver/        # Драйвер WIZnet W5500
```

## Использование

1. Подключите модуль W5500 к Flipper Zero по схеме выше
2. Вставьте Ethernet-кабель в RJ45 разъём W5500
3. Откройте **GPIO → LAN Tester** на Flipper'е
4. В заголовке меню отображается статус линка (напр. `LAN [UP 100M FD]`)
5. Выберите категорию, затем инструмент:

### Network Info
- **Link Info** — статус линка, скорость, дуплекс, MAC. Используйте первым.
- **DHCP Analyze** — Discover/Offer без занятия адреса. Безопасно для прода.
- **Statistics** — захват фреймов 10с, разбивка по типам и EtherType.

### Discovery
- **ARP Scan** — сканирование подсети, IP/MAC/вендор для каждого хоста.
- **Ping Sweep** — ICMP-свип по CIDR (автоопределение или ручной ввод).
- **LLDP/CDP** — пассивное прослушивание до 60с для обнаружения свитча.
- **mDNS/SSDP** — обнаружение сервисов через multicast DNS и UPnP.
- **STP/VLAN** — прослушивание BPDU (30с) и определение VLAN-тегов.

### Diagnostics
- **Ping** — 4 пинга на любой IP (по умолчанию — шлюз из DHCP).
- **Continuous Ping** — живой график RTT с отслеживанием потерь, до нажатия Back.
- **DNS Lookup** — разрешение имени через DNS-сервер из DHCP.
- **Traceroute** — ICMP-трассировка до 30 хопов.
- **Port Scan (Top 20/100)** — TCP connect-сканирование популярных портов.

### Tools
- **Wake-on-LAN** — отправка magic-пакета для пробуждения устройства по MAC.
- **MAC Changer** — рандомный или пользовательский MAC, сохраняется на SD.

### Settings
- **Auto-save results** — вкл/выкл автосохранение результатов в историю.
- **Sound & vibro** — вкл/выкл LED/вибро уведомления.
- **Clear History** — удалить все сохранённые результаты.

## Технические детали

- **W5500 MACRAW режим**: Socket 0 с `MFEN=0` (принимает все фреймы)
- **Worker thread**: 8 КБ стек, неблокирующий UI через ViewDispatcher + worker
- **Кеширование DHCP**: одна сессия, результат переиспользуется всеми операциями
- **Безопасность памяти**: буферы в куче, frame_buf в куче (стек приложения 4 КБ)
- **Порядок байтов**: ручной парсинг big-endian — нет float printf, нет `htons`/`ntohs`

## База данных OUI-вендоров

Встроенная таблица покрывает ~120 распространённых OUI-префиксов:

> Cisco, HP/HPE, Dell, Intel, Broadcom, Realtek, Apple, Samsung, Huawei, TP-Link, Ubiquiti, Juniper, Arista, MikroTik, Netgear, ASUS, D-Link, Synology, QNAP, VMware, Microsoft, Google, Amazon, Lenovo, Supermicro, Aruba, Fortinet, Palo Alto, WIZnet, Raspberry Pi, Espressif и другие.

## Что нельзя реализовать на Flipper + W5500

- **802.1X** --- нужен полноценный supplicant, не хватит RAM
- **Wireshark-захват** --- SPI слишком медленный для полного capture на 100 Мбит
- **SNMP-запросы** --- ASN.1 парсер слишком тяжёл для RAM
- **TLS/HTTPS** --- нет криптобиблиотек в FAP SDK

## Благодарности

- Основано на [arag0re/fz-eth-troubleshooter](https://github.com/arag0re/fz-eth-troubleshooter) (форк [karasevia/finik_eth](https://github.com/karasevia/finik_eth))
- Использует [WIZnet ioLibrary_Driver](https://github.com/Wiznet/ioLibrary_Driver) для работы с W5500
- Создано для [Flipper Zero OFW](https://github.com/flipperdevices/flipperzero-firmware)

## Лицензия

MIT License. Подробности в файле [LICENSE](LICENSE).
