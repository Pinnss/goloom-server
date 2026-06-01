# Установка сервера

[English version](INSTALL.md)

Полный гайд установки `goloom-wg-server` на свежую Debian/Ubuntu VPS.

## Требования

- VPS с публичным IPv4 (1 vCPU / 1 GB RAM хватит)
- Root SSH-доступ
- Открытые порты: TCP 9443 (admin-панель), UDP 51820+ (по одному на WireGuard-интерфейс). Для **VK TURN SRTP** inbound'а нужен ещё один публичный UDP-порт под relay-листенер (например, 56001) — открой его в фаерволе провайдера.
- Для VK Звонков inbound: либо desktop-сессия на VPS, либо режим капчи `admin-webview` (без GUI; см. [USAGE.ru.md](USAGE.ru.md))

## 1. Скачать бинарь сервера

С [страницы Releases](https://github.com/Pinnss/goloom-server/releases) возьми бинарь для архитектуры VPS:

```bash
# amd64 (большинство VPS):
wget -O goloom-wg-server \
  https://github.com/Pinnss/goloom-server/releases/latest/download/goloom-wg-server-linux-amd64
chmod +x goloom-wg-server

# arm64 (Hetzner CAX, Oracle Ampere, AWS Graviton, …):
wget -O goloom-wg-server \
  https://github.com/Pinnss/goloom-server/releases/latest/download/goloom-wg-server-linux-arm64
chmod +x goloom-wg-server
```

Или собрать из исходников:

```bash
git clone https://github.com/Pinnss/goloom-server.git
cd goloom-server
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" \
  -o goloom-wg-server ./cmd/goloom-wg-server
scp goloom-wg-server root@your-vps:/root/
```

## 2. Подготовка системы на VPS

```bash
# WireGuard tools
apt update
apt install -y wireguard wireguard-tools iptables

# IP forwarding (persistent)
echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-goloom.conf
sysctl -p /etc/sysctl.d/99-goloom.conf
```

## 3. Bootstrap WireGuard

systemd-юнит `goloom-wg-server` требует, чтобы `wg-quick@wg0.service` был активен до старта. Создай минимальный `/etc/wireguard/wg0.conf`:

```ini
[Interface]
PrivateKey = <вывод `wg genkey`>
Address    = 10.66.0.1/24
ListenPort = 51820
```

Установи права и подними:

```bash
chmod 600 /etc/wireguard/wg0.conf
systemctl enable --now wg-quick@wg0
```

Admin-панель сама создаёт `wg<N>.conf` для каждого inbound — `wg0` нужен только как placeholder.

## 4. Установка goloom-wg-server

В директории, где лежит бинарь, пример конфига и deploy-ассеты:

```bash
# Подготовь рабочий layout:
mkdir -p deploy
wget -O goloom-wg-server.yaml \
  https://github.com/Pinnss/goloom-server/raw/main/goloom-wg-server.yaml.example
wget -O deploy/install.sh \
  https://github.com/Pinnss/goloom-server/raw/main/deploy/install.sh
wget -O deploy/goloom-wg-server.service \
  https://github.com/Pinnss/goloom-server/raw/main/deploy/goloom-wg-server.service

# (Опционально) поправь goloom-wg-server.yaml — дефолты подходят для
# большинства случаев. Типичные правки: admin.listen, network.wg_subnet_base.

# Запусти инсталлер (копирует бинарь в /opt/goloom, кладёт systemd unit,
# включает сервис):
bash deploy/install.sh
systemctl start goloom-wg-server
journalctl -u goloom-wg-server -n 50
```

При первом запуске печатается одноразовый пароль admin:

```
ADMIN bootstrap credentials → username=admin  password=abc123def456...
```

Запиши его (печатается один раз) и открой `https://<vps-ip>:9443` в браузере. Будет предупреждение о self-signed серте — прими. Войди и сразу смени пароль через "⚙ Аккаунт".

## 5. Создать первый inbound

В дашборде нажми **+ Создать inbound**:

- **Tag** — название, например `home`
- **Transport** — `Telemost`, `WB Stream` или `VK Calls`
- **Meeting URL** — ссылка на конференцию (для VK — call link, для WB — room URL)
- **Captcha mode** (только VK) — `admin-webview` для headless серверов; панель сама проксирует капчу в твой браузер

Сохрани. Панель отдаст `goloom://...` connection string + QR. Передай это клиенту.

Для WB Stream inbound'ов нужно один раз вытащить cookies из браузера — см. [USAGE.ru.md → WB Stream auth](USAGE.ru.md#wb-stream-auth).

### VK TURN SRTP inbound (рекомендуется)

Транспорт **VK TURN SRTP** — самый быстрый и трудноблокируемый путь: WireGuard ретранслируется через собственные TURN-серверы VK под видом WebRTC-медиа. Свой TURN-сервер поднимать **не нужно** — ретранслятором выступает VK, а Goloom-сервер это всего лишь «второй участник» звонка.

1. **+ Создать inbound** → **Transport** = `VK TURN SRTP`.
2. **VK Call link** — ссылка вида `https://vk.com/call/join/<id>`. По ней клиент получает TURN-креды от VK; сам сервер в звонок не заходит.
3. **Listen address (UDP)** — публичный UDP-порт, который слушает relay этого inbound'а, например `0.0.0.0:56001`. Уникален на каждый inbound и **открыт в фаерволе провайдера**.
4. Оставь **авто-провижн WG** включённым. Сохрани.
5. На карточке inbound'а жми **📋 vkturnproxy://** (или сканируй QR), получи ссылку для клиента и передай её — приложение Goloom для Android или клиент anton48/Moroka8 (build125+). Капчу на сервере для этого транспорта решать не нужно.

## 6. Обновление

При новом релизе:

```bash
wget -O /tmp/goloom-wg-server.new \
  https://github.com/Pinnss/goloom-server/releases/latest/download/goloom-wg-server-linux-amd64
chmod +x /tmp/goloom-wg-server.new
systemctl stop goloom-wg-server
mv /tmp/goloom-wg-server.new /opt/goloom/goloom-wg-server
systemctl start goloom-wg-server
```

Существующие inbound'ы и их `goloom://...` строки продолжают работать после обновления.

## Troubleshooting

| Симптом | Причина | Решение |
|---|---|---|
| Admin-панель не открывается | Порт 9443 закрыт в фаерволе провайдера | Открой в настройках фаервола |
| Клиент подключился, но интернет не работает | Нет MASQUERADE правила | `wg-quick down wg<N> && wg-quick up wg<N>` — PostUp перенакатит |
| Ошибки `peer initiated re-handshake` | Старое peer state после краша клиента | Пересоздай inbound через панель, переимпортируй на клиенте |
| VK inbound висит на `auth_pending` | Нужно решить капчу | Жми бейдж 🛡 в дашборде, реши в один клик |
| WB Stream inbound на `auth_required` | Cookies протухли (~14 дней) | Перезапусти bookmarklet, вставь новые токены (см. USAGE.ru.md) |
