# Промпт для Claude Code: Flipper Zero LAN Tester (W5500)

## Как использовать

Скопируй весь блок ниже (от `---START---` до `---END---`) и вставь в Claude Code как начальное задание. Промпт разбит на фазы — Claude Code будет спрашивать подтверждение перед переходом к следующей.

---

## ---START---

Ты — embedded-разработчик, специализирующийся на Flipper Zero (STM32WB55, ARM Cortex-M4, 256 КБ RAM, 1 МБ Flash). Твоя задача — создать FAP-приложение (Flipper Application Package) для OFW, превращающее Flipper Zero + модуль W5500 Lite в полноценный LAN-тестер уровня профессиональных кабельных тестеров.

### Контекст проекта

**Базовый репозиторий:** https://github.com/arag0re/fz-eth-troubleshooter  
Это форк `karasevia/finik_eth`. Текущие возможности: DHCP-клиент, ping, traceroute. Используется библиотека WIZnet `ioLibrary_Driver`. Подключение W5500 по SPI:

```
W5500       → Flipper GPIO
MOSI (MO)   → A7  (pin 2)
SCLK (SCK)  → B3  (pin 5)
nSS  (CS)   → A4  (pin 4)
MISO (MI)   → A6  (pin 3)
RESET (RST) → C3  (pin 7)
3V3  (VCC)  → 3V3 (pin 9)
GND  (G)    → GND (pin 8 или 11)
```

**Целевая прошивка:** Официальная OFW (flipperdevices/flipperzero-firmware, ветка `dev`)  
**Инструмент сборки:** `ufbt` (micro Flipper Build Tool)  
**Язык:** C (чистый C99, без C++, это ограничение FAP)

### Критические технические ограничения

1. **RAM:** ~256 КБ общая, приложению доступно ~80-120 КБ. Все буферы должны быть минимальными. Один Ethernet-фрейм = до 1518 байт. Не выделяй буферов больше 2-4 КБ на задачу.
2. **W5500 MACRAW:** Только Socket 0 может работать в режиме MACRAW (сырые Ethernet-фреймы). Остальные 7 сокетов — TCP/UDP/IPRAW. Для LLDP/CDP/ARP нужен именно MACRAW.
3. **Конкурентность:** Flipper Zero использует FreeRTOS. Приложение работает в одном потоке. Используй event loop / state machine, НЕ создавай дополнительные потоки.
4. **Экран:** 128×64 пикселей, монохромный. UI должен быть минималистичным, данные — прокручиваемыми.
5. **Ввод:** 5 кнопок (Up, Down, Left, Right, OK) + Back. Навигация по меню через ViewDispatcher и стандартные Flipper views.
6. **Нет динамической аллокации в горячих путях:** `malloc`/`free` — только при инициализации/деинициализации. В цикле обработки пакетов — только статические/стековые буферы.

### Архитектура приложения

Реализуй следующую модульную архитектуру:

```
eth_tester/
├── application.fam            # Манифест FAP
├── eth_tester_app.c           # Точка входа, инициализация, ViewDispatcher
├── eth_tester_app.h           # Общие структуры и определения
│
├── hal/                       # Hardware Abstraction Layer
│   ├── w5500_hal.c            # SPI init, reset, MACRAW socket management
│   └── w5500_hal.h
│
├── protocols/                 # Парсеры и генераторы протоколов
│   ├── lldp.c                 # LLDP listener + parser (IEEE 802.1AB)
│   ├── lldp.h
│   ├── cdp.c                  # CDP listener + parser (Cisco)
│   ├── cdp.h
│   ├── arp_scan.c             # ARP scanner (отправка ARP Request, сбор Reply)
│   ├── arp_scan.h
│   ├── dhcp_discover.c        # DHCP Discover + анализ Offer (fingerprinting)
│   ├── dhcp_discover.h
│   ├── icmp.c                 # Ping (ICMP Echo)
│   └── icmp.h
│
├── views/                     # UI-представления (Flipper View API)
│   ├── main_menu_view.c       # Главное меню
│   ├── lldp_view.c            # Отображение LLDP/CDP данных
│   ├── arp_view.c             # Список обнаруженных хостов
│   ├── dhcp_view.c            # DHCP-информация
│   ├── link_info_view.c       # PHY link status, speed, duplex
│   └── log_view.c             # Сырой лог пакетов
│
├── utils/
│   ├── oui_lookup.c           # MAC → Vendor (таблица OUI, top-100 вендоров)
│   ├── oui_lookup.h
│   ├── packet_utils.c         # Парсинг Ethernet-фреймов, TLV, контрольные суммы
│   └── packet_utils.h
│
├── assets/                    # Иконки для FAP
│   └── ...
│
└── lib/
    └── ioLibrary_Driver/      # WIZnet driver (субмодуль, как в оригинале)
```

### Фаза 1: Базовый каркас + Link Info

1. Склонируй `arag0re/fz-eth-troubleshooter` как стартовую точку
2. Рефактори структуру под описанную архитектуру
3. Реализуй `w5500_hal.c`:
   - Инициализация SPI (используй Flipper `furi_hal_spi` API)
   - Аппаратный сброс W5500 через GPIO C3
   - Чтение регистра PHYCFGR (0x002E) для определения link status, speed (10/100), duplex (half/full)
   - Открытие Socket 0 в режиме MACRAW: `Sn_MR = 0x04`, с `MFEN=0` (принимать все фреймы, не только свои MAC)
4. Реализуй `link_info_view`: показывай Link Up/Down, 100M/10M, Full/Half, MAC-адрес
5. Главное меню с пунктами: `[Link Info] [LLDP/CDP] [ARP Scan] [DHCP Analyze] [Ping]`
6. Убедись, что `application.fam` корректен для OFW:

```python
App(
    appid="eth_tester",
    name="LAN Tester",
    apptype=FlipperAppType.EXTERNAL,
    entry_point="eth_tester_app",
    stack_size=4 * 1024,
    fap_category="GPIO",
    fap_icon="assets/icon.png",
    fap_icon_assets="assets",
    fap_libs=["spi"],
    fap_author="...",
    fap_version="0.1",
)
```

**Спроси подтверждение перед переходом к Фазе 2.**

### Фаза 2: LLDP / CDP Listener

Реализуй пассивный слушатель LLDP и CDP:

**LLDP (IEEE 802.1AB):**
- EtherType: `0x88CC`
- Destination MAC: `01:80:C2:00:00:0E`
- Парси TLV (Type-Length-Value):
  - Type 1: Chassis ID (обычно MAC-адрес)
  - Type 2: Port ID
  - Type 3: TTL
  - Type 4: Port Description
  - Type 5: System Name
  - Type 6: System Description
  - Type 7: System Capabilities (Router/Bridge/etc)
  - Type 8: Management Address
  - Type 127 (org-specific): IEEE 802.1 VLAN Name (OUI: 00-80-C2), IEEE 802.3 MAC/PHY (OUI: 00-12-0F)
  - Type 0: End of LLDPDU

**CDP (Cisco Discovery Protocol):**
- EtherType: `0x2000` (в LLC/SNAP: DSAP=0xAA, SSAP=0xAA, Control=0x03, OUI=00-00-0C, Type=0x2000)
- Destination MAC: `01:00:0C:CC:CC:CC`
- Парси TLV:
  - Type 0x0001: Device ID
  - Type 0x0002: Addresses
  - Type 0x0003: Port ID
  - Type 0x0004: Capabilities
  - Type 0x0005: Software Version
  - Type 0x0006: Platform
  - Type 0x0009: VTP Management Domain
  - Type 0x000A: Native VLAN
  - Type 0x000B: Duplex

**Алгоритм работы:**
1. Открой Socket 0 в MACRAW с фильтром выключенным (MFEN=0 в Sn_MR)
2. В цикле event loop (используй `furi_delay_ms(100)` между проверками):
   - Проверяй `Sn_RX_RSR` на наличие данных
   - Если есть — читай фрейм, проверяй EtherType
   - Если LLDP (0x88CC): парси LLDP TLV, обнови структуру `LldpNeighbor`
   - Если CDP (SNAP header + 0x2000): парси CDP TLV, обнови структуру `CdpNeighbor`
   - Остальные фреймы — игнорируй (или считай для статистики)
3. Таймаут ожидания: 60 секунд (LLDP обычно шлётся каждые 30 сек)
4. Отображай на экране: System Name, Port ID, VLAN, Management IP, Capabilities

**Структуры данных (пример):**
```c
#define LLDP_MAX_STRING 64

typedef struct {
    char system_name[LLDP_MAX_STRING];
    char port_id[LLDP_MAX_STRING];
    char port_desc[LLDP_MAX_STRING];
    char system_desc[LLDP_MAX_STRING];
    uint8_t chassis_mac[6];
    uint8_t mgmt_ip[4];
    uint16_t mgmt_vlan;
    uint16_t ttl;
    uint16_t capabilities;
    bool valid;
    uint32_t last_seen_tick;
} LldpNeighbor;
```

**Критически важно:**
- LLDP приходит на multicast `01:80:C2:00:00:0E`. В MACRAW режиме с MFEN=0 W5500 получает ВСЕ фреймы, включая multicast — это то что нам нужно.
- НЕ используй встроенный TCP/IP стек W5500 для этого. MACRAW — это bypass TCP/IP стека.
- Проверяй длину фрейма перед парсингом каждого TLV, чтобы избежать выход за буфер.

**Спроси подтверждение перед переходом к Фазе 3.**

### Фаза 3: ARP Scanner

Реализуй активный ARP-сканер подсети:

**Алгоритм:**
1. Сначала получи IP через DHCP (используй существующий DHCP-клиент из базового приложения, или реализуй минимальный через UDP-сокет W5500)
2. По полученному IP и маске определи диапазон сканирования (например, `192.168.1.0/24` → сканируй `.1` — `.254`)
3. Ограничь максимальный размер подсети: /24 (254 хоста). Для /16 и больше — отказывай с сообщением.
4. Для каждого IP в диапазоне:
   - Сформируй ARP Request (EtherType 0x0806, Operation 1):
     ```
     Ethernet Header:
       Dst MAC: FF:FF:FF:FF:FF:FF (broadcast)
       Src MAC: наш MAC
       EtherType: 0x0806
     ARP Payload:
       HTYPE: 0x0001 (Ethernet)
       PTYPE: 0x0800 (IPv4)
       HLEN: 6
       PLEN: 4
       OPER: 0x0001 (Request)
       SHA: наш MAC
       SPA: наш IP
       THA: 00:00:00:00:00:00
       TPA: целевой IP
     ```
   - Отправь через MACRAW Socket 0
   - Не жди ответа сразу — отправляй пакеты пачками по 8-16 штук с задержкой 10-20 мс между пачками
5. Параллельно (в том же event loop) читай входящие фреймы:
   - Фильтруй по EtherType 0x0806, Operation 2 (ARP Reply)
   - Извлекай: Sender MAC (SHA), Sender IP (SPA)
   - Добавляй в таблицу обнаруженных хостов
6. После отправки всех запросов — жди ещё 3 секунды на опоздавшие ответы

**Таблица хостов:**
```c
#define ARP_MAX_HOSTS 64  // Ограничение по RAM

typedef struct {
    uint8_t ip[4];
    uint8_t mac[6];
    char vendor[24];  // Из OUI lookup
    bool responded;
} ArpHost;

typedef struct {
    ArpHost hosts[ARP_MAX_HOSTS];
    uint8_t count;
    uint8_t total_sent;
    uint8_t progress_percent;
    bool scanning;
} ArpScanState;
```

**UI (arp_view):**
- Прогресс-бар во время сканирования
- Прокручиваемый список хостов: `IP — MAC — Vendor`
- Итоговая строка: "Found X hosts in Y.Zs"

**OUI Lookup:**
- Встрой compact-таблицу из ~100-150 самых распространённых OUI (3 байта MAC → короткое имя вендора)
- Формат: `static const struct { uint8_t oui[3]; const char* vendor; } oui_table[]`
- Включи: Cisco, HP/HPE, Dell, Intel, Broadcom, Realtek, Apple, Samsung, Huawei, TP-Link, Ubiquiti, Juniper, Arista, MikroTik, Netgear, ASUS, D-Link, Synology, QNAP, VMware, Microsoft (Hyper-V), и т.д.
- Поиск: линейный (для 100-150 записей это ~O(1) по скорости, бинарный — оверинжиниринг)

**Спроси подтверждение перед переходом к Фазе 4.**

### Фаза 4: DHCP Analyzer

Реализуй DHCP Discover + анализ Offer для fingerprinting:

**Алгоритм:**
1. Используй UDP-сокет W5500 (не MACRAW):
   - Сокет 1 в UDP-режиме, bind на порт 68 (DHCP Client)
   - Destination: `255.255.255.255:67` (DHCP Server)
2. Сформируй DHCP Discover:
   ```
   OP: 1 (BOOTREQUEST)
   HTYPE: 1 (Ethernet)
   HLEN: 6
   XID: random 4 bytes
   FLAGS: 0x8000 (Broadcast)
   CHADDR: наш MAC (+ 10 байт нулей)
   Magic Cookie: 99.130.83.99 (0x63825363)
   Options:
     53 (DHCP Message Type): 1 (Discover)
     55 (Parameter Request List): 1,3,6,15,28,42,51,54,58,59
     61 (Client Identifier): 01 + наш MAC
     255 (End)
   ```
3. Отправь и жди DHCP Offer (до 10 секунд)
4. Парси DHCP Offer:
   - Предложенный IP (YIADDR)
   - Option 1: Subnet Mask
   - Option 3: Router/Gateway
   - Option 6: DNS Server(s)
   - Option 15: Domain Name
   - Option 28: Broadcast Address
   - Option 42: NTP Server(s)
   - Option 51: Lease Time
   - Option 54: DHCP Server Identifier
   - Option 58: Renewal Time
   - Option 59: Rebinding Time
5. **DHCP Fingerprinting:** Запомни порядок опций в Offer — это fingerprint DHCP-сервера (аналогично fingerbank.org). Отображай как строку через запятую.
6. НЕ отправляй DHCP Request — мы только анализируем, не берём адрес.

**UI (dhcp_view):**
- Server IP, Offered IP, Subnet, Gateway
- DNS, Domain, NTP
- Lease/Renewal/Rebinding times
- DHCP Fingerprint (option order string)
- Vendor (OUI по MAC серверу, если получим через ARP)

**Спроси подтверждение перед переходом к Фазе 5.**

### Фаза 5: Финализация и полировка

1. **Сохранение результатов:**
   - Добавь возможность сохранять результаты на SD-карту Flipper в `/ext/apps_data/eth_tester/`
   - Формат: простой текст (`.txt`), один файл на сканирование
   - Используй Flipper Storage API (`storage_file_open`, `storage_file_write`)

2. **Packet counter / статистика:**
   - В фоне (когда открыт MACRAW) считай: общее количество фреймов, broadcast, multicast, unicast
   - Считай количество по EtherType: IPv4, ARP, IPv6, LLDP, CDP, Unknown
   - Отображай в отдельном view "Statistics"

3. **Обработка ошибок:**
   - No link (кабель не подключен) → показывай "No Link" на экране, retry каждые 2 сек
   - W5500 не отвечает (SPI fail) → показывай "W5500 Not Found", проверяй VERSIONR (должен быть 0x04)
   - Timeout на LLDP/CDP → "No LLDP/CDP neighbors detected (waited 60s)"
   - DHCP timeout → "No DHCP server found"

4. **Graceful shutdown:**
   - При нажатии Back — корректно закрывай сокеты, деинициализируй SPI
   - Освобождай все ресурсы через `ViewDispatcher` callback

5. **Тестирование:**
   - Убедись, что проект собирается через `ufbt build`
   - Проверь отсутствие warnings на `-Wall -Wextra`
   - Убедись, что нет утечек памяти (все `malloc` имеют парный `free` в cleanup)

### Общие правила кода

- **Naming convention:** `snake_case` для всего (как в Flipper SDK)
- **Включай guards:** `#pragma once` для всех .h файлов
- **Логирование:** используй `FURI_LOG_I("ETH", "...")`, `FURI_LOG_E(...)` и т.д.
- **Assertions:** `furi_assert(ptr)` для проверки указателей
- **Порядок байт:** Ethernet = Big Endian. ARM = Little Endian. Используй `__builtin_bswap16()` / `__builtin_bswap32()` или ручной парсинг `(buf[0] << 8) | buf[1]`
- **Не используй `printf`/`sprintf` с float** — Flipper SDK может не включать float support в printf. Используй целочисленную арифметику для отображения
- **Комментарии:** пиши на английском, подробно описывай назначение каждого TLV type и magic number

## ---END---

---

## Дополнительные заметки

### Порядок работы с Claude Code

1. Скопируй промпт выше в Claude Code
2. Claude Code спросит, клонировать ли репозиторий — подтверди
3. После каждой фазы проверяй: `ufbt build` — должно компилироваться
4. Фазы можно пропускать или менять порядок
5. Если что-то не работает — скопируй ошибку компиляции обратно в Claude Code

### Что НЕ получится реализовать на Flipper + W5500

- **802.1X аутентификация** — нужен полноценный supplicant, не хватит RAM
- **Wireshark-подобный захват** — нет достаточного хранилища и скорости SPI для capture на 100 Мбит
- **Spanning Tree (STP/RSTP)** — только пассивное прослушивание BPDU возможно, но малополезно
- **SNMP-запросы** — теоретически возможно, но ASN.1 парсер съест слишком много RAM
- **TLS/HTTPS** — нет криптобиблиотек в FAP SDK

### Что МОЖНО добавить позже (post-MVP)

- STP/BPDU пассивный listener
- 802.1Q VLAN tagging detection
- ICMP ping с RTT-графиком на экране
- DNS lookup (через UDP-сокет)
- Сохранение профилей портов для сравнения
- mDNS / SSDP discovery
