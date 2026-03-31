# Flipper Zero LAN Tester (W5500)

> **[Русская версия ниже / Russian version below](#русская-версия)**

Turn your **Flipper Zero + W5500 Lite** module into a professional-grade portable LAN tester. Analyze Ethernet links, discover network neighbors, scan subnets, fingerprint DHCP servers --- all from a pocket-sized device.

![Flipper Zero](https://img.shields.io/badge/Flipper%20Zero-OFW-orange)
![License](https://img.shields.io/badge/license-MIT-blue)
![Language](https://img.shields.io/badge/language-C99-green)
![Build](https://img.shields.io/badge/build-ufbt-yellow)

---

## Features

| Feature | Description |
|---|---|
| **Link Info** | PHY link status, speed (10/100 Mbps), duplex (Half/Full), MAC address, W5500 version check |
| **LLDP Listener** | Passive IEEE 802.1AB neighbor discovery --- system name, port ID, management IP, VLAN, capabilities |
| **CDP Listener** | Cisco Discovery Protocol parsing --- device ID, platform, software version, native VLAN, duplex |
| **ARP Scanner** | Active subnet scan with batch requests, OUI vendor lookup (~120 vendors), duplicate detection |
| **DHCP Analyzer** | Discover-only analysis (no IP lease taken), option fingerprinting, full offer parsing |
| **ICMP Ping** | Echo request/reply to gateway with RTT measurement |
| **Packet Statistics** | Frame counters by type (unicast/broadcast/multicast) and EtherType (IPv4/ARP/IPv6/LLDP/CDP) |
| **SD Card Export** | All scan results saved to `/ext/apps_data/eth_tester/` as plain text |

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
ufbt build
ufbt install    # with Flipper connected via USB
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
│   └── icmp.c / icmp.h         # ICMP Echo (ping) via IPRAW
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
4. Select a function from the menu:

### Link Info
Instantly shows link status, negotiated speed and duplex, MAC address. Use this first to verify your hardware connection.

### LLDP/CDP
Passively listens for up to 60 seconds. Most managed switches send LLDP every 30 seconds. Shows switch name, port, VLAN, management IP, and device capabilities.

### ARP Scan
Acquires an IP via DHCP, then scans the local subnet (max /24). Sends ARP requests in batches of 16 with 15ms delays. Shows IP, MAC, and vendor for each responding host.

### DHCP Analyze
Sends a single DHCP Discover and analyzes the Offer response. Does **not** take an IP lease --- safe to run on production networks. Shows server IP, offered address, gateway, DNS, domain, NTP, lease times, and a DHCP option fingerprint string.

### Ping
Gets an IP via DHCP, then pings the default gateway 4 times with 3-second timeout. Shows RTT for each attempt.

### Statistics
Captures raw Ethernet frames for 10 seconds (or shows accumulated stats from previous LLDP/CDP sessions). Breaks down traffic by destination type and EtherType.

## Technical Details

- **W5500 MACRAW mode**: Socket 0 with `MFEN=0` (promiscuous --- receives all frames including multicast)
- **No extra threads**: Single-threaded event loop, compatible with FreeRTOS on Flipper
- **Memory-safe**: All buffers are statically sized, no `malloc` in hot paths, bounds checking on all TLV parsers
- **Endianness**: Manual big-endian parsing (`(buf[0] << 8) | buf[1]`) --- no float printf, no `htons`/`ntohs`

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
| **Link Info** | Статус PHY-линка, скорость (10/100 Мбит/с), дуплекс (Half/Full), MAC-адрес, проверка версии W5500 |
| **LLDP Listener** | Пассивное обнаружение соседей IEEE 802.1AB --- имя системы, порт, management IP, VLAN, capabilities |
| **CDP Listener** | Парсинг Cisco Discovery Protocol --- ID устройства, платформа, версия ПО, Native VLAN, дуплекс |
| **ARP Scanner** | Активное сканирование подсети пакетами по 16 штук, определение вендора по OUI (~120 производителей) |
| **DHCP Analyzer** | Анализ только Discover/Offer (IP-адрес не берётся!), фингерпринтинг, полный разбор Offer |
| **ICMP Ping** | Echo Request/Reply до шлюза с измерением RTT |
| **Статистика пакетов** | Счётчики фреймов по типу (unicast/broadcast/multicast) и EtherType (IPv4/ARP/IPv6/LLDP/CDP) |
| **Экспорт на SD** | Все результаты сохраняются в `/ext/apps_data/eth_tester/` в текстовом формате |

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
ufbt build
ufbt install    # при подключённом Flipper по USB
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
│   ├── arp_scan.c / arp_scan.h  # Построитель ARP-запросов и парсер ответов
│   ├── dhcp_discover.c / .h     # Построитель DHCP Discover и парсер Offer
│   └── icmp.c / icmp.h         # ICMP Echo (ping) через IPRAW
│
├── utils/                       # Утилиты
│   ├── oui_lookup.c / .h       # MAC → Вендор (топ ~120 OUI-префиксов)
│   └── packet_utils.c / .h     # Работа с байтовым порядком, контрольные суммы
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
4. Выберите функцию в меню:

### Link Info
Мгновенно показывает статус линка, согласованную скорость и дуплекс, MAC-адрес. Используйте первым для проверки подключения.

### LLDP/CDP
Пассивно слушает до 60 секунд. Большинство управляемых коммутаторов отправляют LLDP каждые 30 секунд. Показывает имя коммутатора, порт, VLAN, management IP, capabilities устройства.

### ARP Scan
Получает IP через DHCP, затем сканирует локальную подсеть (максимум /24). Отправляет ARP-запросы пачками по 16 с задержкой 15 мс. Показывает IP, MAC и вендора для каждого ответившего хоста.

### DHCP Analyze
Отправляет один DHCP Discover и анализирует ответ Offer. **Не берёт IP-адрес** --- безопасно для использования в продуктивных сетях. Показывает IP сервера, предложенный адрес, шлюз, DNS, домен, NTP, время аренды и строку фингерпринта DHCP-опций.

### Ping
Получает IP через DHCP, затем пингует шлюз по умолчанию 4 раза с таймаутом 3 секунды. Показывает RTT для каждой попытки.

### Статистика
Захватывает сырые Ethernet-фреймы 10 секунд (или показывает накопленную статистику от предыдущих LLDP/CDP сессий). Разбивает трафик по типу назначения и EtherType.

## Технические детали

- **W5500 MACRAW режим**: Socket 0 с `MFEN=0` (принимает все фреймы, включая multicast)
- **Без дополнительных потоков**: один поток в event loop, совместимо с FreeRTOS на Flipper
- **Безопасность памяти**: все буферы статического размера, нет `malloc` в горячих путях, проверка границ во всех TLV-парсерах
- **Порядок байтов**: ручной парсинг big-endian (`(buf[0] << 8) | buf[1]`) --- нет float printf, нет `htons`/`ntohs`

## База данных OUI-вендоров

Встроенная таблица покрывает ~120 распространённых OUI-префиксов:

> Cisco, HP/HPE, Dell, Intel, Broadcom, Realtek, Apple, Samsung, Huawei, TP-Link, Ubiquiti, Juniper, Arista, MikroTik, Netgear, ASUS, D-Link, Synology, QNAP, VMware, Microsoft, Google, Amazon, Lenovo, Supermicro, Aruba, Fortinet, Palo Alto, WIZnet, Raspberry Pi, Espressif и другие.

## Что нельзя реализовать на Flipper + W5500

- **802.1X** --- нужен полноценный supplicant, не хватит RAM
- **Wireshark-захват** --- SPI слишком медленный для полного capture на 100 Мбит
- **SNMP-запросы** --- ASN.1 парсер слишком тяжёл для RAM
- **TLS/HTTPS** --- нет криптобиблиотек в FAP SDK

## Что можно добавить позже

- STP/BPDU пассивный listener
- 802.1Q VLAN tagging detection
- ICMP ping с графиком RTT на экране
- DNS lookup через UDP-сокет
- mDNS / SSDP discovery
- Сохранение профилей портов для сравнения

## Благодарности

- Основано на [arag0re/fz-eth-troubleshooter](https://github.com/arag0re/fz-eth-troubleshooter) (форк [karasevia/finik_eth](https://github.com/karasevia/finik_eth))
- Использует [WIZnet ioLibrary_Driver](https://github.com/Wiznet/ioLibrary_Driver) для работы с W5500
- Создано для [Flipper Zero OFW](https://github.com/flipperdevices/flipperzero-firmware)

## Лицензия

MIT License. Подробности в файле [LICENSE](LICENSE).
