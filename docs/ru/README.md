# Flipper Zero LAN Тестер (W5500) -- Документация

Превратите **Flipper Zero + модуль W5500** в профессиональный портативный LAN-тестер. Анализ линков, обнаружение сетевых соседей, сканирование подсетей, фингерпринтинг DHCP, захват пакетов, USB-Ethernet мост, PXE-загрузка, HTTP-менеджер файлов -- всё с карманного устройства.

## Ключевые особенности

- 20+ сетевых инструментов в одном приложении Flipper Zero
- Работает с любой SPI-платой на чипе W5500
- DHCP-анализ не занимает IP-адрес (безопасно для продакшн-сетей)
- Результат DHCP кешируется -- нет повторных 15-секундных ожиданий
- Визуальная обратная связь: прогрессбары, таймеры, графики RTT
- Автосохранение результатов с метками времени
- USB-Ethernet мост с опциональной записью PCAP
- Встроенный PXE-сервер и веб-менеджер файлов

## Возможности

| Функция | Категория | Описание |
|---|---|---|
| Link Info | Network Info | Статус PHY-линка, скорость, дуплекс, MAC, версия W5500 |
| DHCP Analyzer | Network Info | Анализ Discover/Offer с фингерпринтом опций |
| Statistics | Network Info | Счётчики фреймов по типам и EtherType (10с) |
| ARP Scanner | Discovery | Сканирование подсети с OUI-поиском (~120 вендоров) |
| Ping Sweep | Discovery | ICMP-свип CIDR-диапазона с интерактивным списком хостов |
| LLDP/CDP | Discovery | Пассивное обнаружение соседей IEEE 802.1AB и Cisco CDP |
| mDNS/SSDP | Discovery | Обнаружение сервисов через multicast DNS и UPnP |
| STP/VLAN | Discovery | Захват BPDU и определение 802.1Q VLAN |
| Ping | Diagnostics | ICMP echo с настраиваемым количеством и таймаутом |
| Continuous Ping | Diagnostics | График RTT с min/max/avg и процентом потерь |
| DNS Lookup | Diagnostics | Разрешение имён через UDP DNS |
| Traceroute | Diagnostics | ICMP-трассировка до 30 хопов |
| Port Scanner | Diagnostics | TCP connect: Top-20, Top-100 или свой диапазон |
| Wake-on-LAN | Tools | Отправка magic-пакетов |
| Packet Capture | Tools | Автономный PCAP-дамп на SD-карту |
| ETH Bridge | Tools | USB-Ethernet мост через CDC-ECM с записью PCAP |
| PXE Server | Tools | Сервер сетевой загрузки (DHCP + TFTP) |
| File Manager | Tools | Веб-менеджер файлов SD через HTTP |
| History | -- | Автосохранение результатов с метками времени |
| Settings | -- | Автосохранение, звук, DNS, пинг, MAC Changer |

## Документация

| Страница | Содержание |
|---|---|
| **[Оборудование и подключение](hardware.md)** | Схема подключения, описание пинов, питание, совместимые платы |
| **[Сборка из исходников](building.md)** | Требования, команды сборки, установка, CI/CD |
| **[Архитектура и внутренности](architecture.md)** | Структура проекта, сокеты, потоки, модель памяти |
| **[Руководство по функциям](usage.md)** | Подробное описание каждой функции по категориям |
| **[ETH Bridge](eth-bridge.md)** | USB-Ethernet мост, запись PCAP, совместимость с ОС |
| **[PXE Server](pxe-server.md)** | Сетевая загрузка, автодетект DHCP, TFTP |
| **[Файловый менеджер](file-manager.md)** | HTTP-сервер, токены авторизации, управление SD |
| **[Безопасность](security.md)** | Модель безопасности, меры защиты, отчёты |
| **[Решение проблем](troubleshooting.md)** | Частые проблемы, ограничения, сторонние библиотеки |

## Благодарности

- Основано на [arag0re/fz-eth-troubleshooter](https://github.com/arag0re/fz-eth-troubleshooter) (форк [karasevia/finik_eth](https://github.com/karasevia/finik_eth))
- Использует [WIZnet ioLibrary_Driver](https://github.com/Wiznet/ioLibrary_Driver)
- Создано для [Flipper Zero OFW](https://github.com/flipperdevices/flipperzero-firmware)

## Лицензия

MIT License. Подробности в файле [LICENSE](../../LICENSE).
