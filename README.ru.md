# Goloom

[English version](README.md)

Goloom — VPN, маскирующий WireGuard под медиа-поток видеоконференции. Для сетевого наблюдателя устройство выглядит как участник видеозвонка в публичном сервисе (Яндекс Телемост, Wildberries Stream, VK Звонки); на самом деле оно обменивается WireGuard-датаграммами с Goloom-сервером.

В этом репозитории:

| Компонент | Путь | Что это |
|---|---|---|
| **Сервер** | [`cmd/goloom-wg-server`](cmd/goloom-wg-server) | Демон для Linux VPS. Присоединяется к звонку, разворачивает WireGuard-датаграммы из медиа, передаёт их в kernel WG, NAT'ит в интернет. |
| **GUI-клиент Windows** | [`cmd/goloom-wg-gui`](cmd/goloom-wg-gui) | Десктоп на Wails: профили, встроенный userspace WireGuard, подключение в один клик. |
| **CLI-клиент Windows** | [`cmd/goloom-wg-client`](cmd/goloom-wg-client) | Headless reference-клиент для Linux/Windows/macOS. Через kernel/userspace WireGuard. |
| **Mobile SDK** | [`mobile`](mobile) | Gomobile-bridge — собирает `goloom.aar` (Android) и `Goloom.xcframework` (iOS). Userspace WireGuard внутри — внешние `wireguard-android` / `WireGuardKit` не нужны. |
| **Reference Android app** | [Pinnss/goloom-android](https://github.com/Pinnss/goloom-android) | Compose UI — импорт/экспорт профилей, per-app split tunnel, логи, авто-реконнект. |

## Поддерживаемые транспорты

| Транспорт | Статус | Замечания |
|---|---|---|
| **Яндекс Телемост** | Стабильный | WireGuard едет в VP8-видеокадрах. |
| **Wildberries Stream** (LiveKit) | Стабильный | DataChannel; нужны cookies, captured вручную оператором (см. [USAGE.ru.md](docs/USAGE.ru.md#wb-stream-auth)). |
| **VK Звонки** | Стабильный | VP8 поверх anonymous-peer join; клиент один раз решает капчу в WebView и реиспользует профиль. |
| **VK TURN SRTP** | Стабильный — **рекомендуется** | Заворачивает WireGuard в WebRTC-медиа (RTP/SRTP) и ретранслирует через *собственные* TURN-серверы VK. Goloom-сервер — это просто «второй участник» звонка, свой TURN он не поднимает. Обходит шейп-политику VK: ~30–40 Мбит/с против ~2 Мбит/с на легаси-пути. |
| **VK TURN (legacy DTLS)** | Устарел | DTLS + WireGuard поверх VK TURN. С 2026-05 VK режет этот путь до ~7–9 КБ/с; оставлено только для старых клиентов. |

> Первые три транспорта присоединяются к конференции как скрытый участник. Два транспорта **VK TURN** вместо этого ретранслируют WireGuard через собственную TURN-инфраструктуру VK — свой TURN-сервер поднимать **не нужно**, ретранслятором выступает VK, и именно это делает трафик трудноблокируемым. См. [USAGE.ru.md → VK TURN SRTP](docs/USAGE.ru.md#vk-turn-srtp).

## Быстрый старт

### Поднять сервер

Полный гайд: [`docs/INSTALL.ru.md`](docs/INSTALL.ru.md) ([EN](docs/INSTALL.md)). Короткая версия на свежей Debian/Ubuntu VPS:

```bash
# Скачай бинарь сервера из релизов:
wget -O goloom-wg-server https://github.com/Pinnss/goloom-server/releases/latest/download/goloom-wg-server-linux-amd64
chmod +x goloom-wg-server

# Положи рядом пример конфига и install-скрипт:
wget https://github.com/Pinnss/goloom-server/raw/main/goloom-wg-server.yaml.example -O goloom-wg-server.yaml
mkdir deploy && cd deploy
wget https://github.com/Pinnss/goloom-server/raw/main/deploy/install.sh
wget https://github.com/Pinnss/goloom-server/raw/main/deploy/goloom-wg-server.service
cd ..

# Запусти инсталлер (нужен root + WireGuard + iptables):
sudo bash deploy/install.sh
sudo systemctl start goloom-wg-server
```

При первом запуске в журнал выводится одноразовый пароль admin — забери его из `journalctl -u goloom-wg-server`. Затем открой `https://<vps-ip>:9443`, войди, смени пароль и создай первый inbound. Панель отдаст `goloom://...` connection string (и QR), который импортируется в клиент.

### Подключить клиент

- **Windows GUI**: скачай `goloom-wg-gui-windows-amd64.zip` из [Releases](https://github.com/Pinnss/goloom-server/releases), распакуй, запусти `goloom-wg-gui.exe` от администратора, вставь connstr, жми Connect.
- **Android**: скачай последний APK из [goloom-android Releases](https://github.com/Pinnss/goloom-android/releases), установи, сканируй QR или вставь connstr.

Подробности: создание inbound'ов, ловля WB Stream cookies, особенности разных клиентов — в [`docs/USAGE.ru.md`](docs/USAGE.ru.md) ([EN](docs/USAGE.md)).

## Собрать из исходников

```bash
git clone https://github.com/Pinnss/goloom-server.git
cd goloom-server
go build ./cmd/goloom-wg-server     # Linux server
go build ./cmd/goloom-wg-client     # CLI client
```

Wails GUI — см. [`cmd/goloom-wg-gui/README.md`](cmd/goloom-wg-gui/README.md). Mobile SDK — [`mobile/README.md`](mobile/README.md).

## Лицензия

Apache-2.0.
