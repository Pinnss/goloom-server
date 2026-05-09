# Использование

[English version](USAGE.md)

Гайд по ежедневной работе оператора и юзера после установки сервера (см. [INSTALL.ru.md](INSTALL.ru.md)).

## Создание inbound'а

Каждому туннелируемому клиенту даётся отдельный **inbound** — свой WireGuard-интерфейс, своя connection string и своя ссылка на конференцию.

1. Открой `https://<vps-ip>:9443`, войди.
2. Жми **+ Создать inbound**.
3. Выбери **Transport**:
   - **Telemost** — вставь ссылку на встречу Яндекс Телемост (`https://telemost.yandex.ru/j/...`).
   - **WB Stream** — вставь URL комнаты Wildberries Stream. Понадобятся cookies из браузерной сессии (см. [WB Stream auth](#wb-stream-auth) ниже).
   - **VK Calls** — вставь ссылку на VK звонок (`https://vk.com/call/join/...`). Выбери captcha mode:
     - `admin-webview` (по умолчанию) — admin-панель проксирует капчу VK в твой браузер. Работает на headless VPS.
     - `auto` — сервер открывает капчу в системном браузере. Нужна desktop-сессия на VPS.
     - `none` — фейл при первой же капче.
4. Жми **Создать**. Панель отдаст `goloom://...` строку и QR.
5. Передай QR / строку клиенту.

## VK Calls captcha (для оператора)

При первом запуске VK inbound'а VK требует решить капчу. С режимом `admin-webview`:

1. В шапке дашборда появляется бейдж 🛡. Клик.
2. Выбери pending challenge → откроется окно с капчей в новой вкладке.
3. Жми **Я не робот**. Окно само закроется, когда токен будет захвачен.
4. Inbound переходит в `waiting_for_client`.

VK-токен `success_token` одноразовый (~60 сек), поэтому каждый VK-реконнект сервера запрашивает капчу заново. Для долгоживущих inbound'ов панель обрабатывает это автоматически — бейдж появится только когда нужно человеческое вмешательство.

## WB Stream auth

WB Stream защищён Cloudflare Turnstile, который Go HTTP-клиент не пройдёт. Прагматичный обход — один раз в браузере захватить cookies, дальше ~14 дней работа без вмешательства.

### Первичная настройка

1. Открой `https://stream.wb.ru/room/<id>` в десктопном браузере.
2. Жми **Войти как гость** → display name → ToS → Подключиться. Должен оказаться в комнате.
3. Жми bookmarklet ниже. Появится textarea с JSON-блоком (автоматически копируется в clipboard).
4. Вставь JSON в форму **WB Stream → Auth** для inbound'а в admin-панели. Сохрани.

### Bookmarklet

Перетащи на панель закладок (или вставь как URL новой закладки):

```javascript
javascript:(async function(){
  try {
    const slice = JSON.parse(localStorage.getItem('wb_auth_auth_slice') || '{}');
    if (!slice.accessToken) throw new Error('no accessToken — are you signed in as guest?');
    const cookies = await cookieStore.getAll();
    const cookieHeader = cookies.map(c => c.name + '=' + c.value).join('; ');
    const earliest = Math.min(...cookies.filter(c => c.expires).map(c => c.expires)) || null;
    const blob = {
      accessToken: slice.accessToken,
      cookies: cookieHeader,
      cookies_expire_at: earliest ? new Date(earliest).toISOString() : null,
      captured_at: new Date().toISOString(),
      room_url: location.origin + location.pathname,
    };
    const ta = document.createElement('textarea');
    ta.value = JSON.stringify(blob, null, 2);
    ta.style.cssText = 'position:fixed;top:5%;left:5%;width:90%;height:80%;z-index:99999;font:12px monospace;background:#fff;color:#000;border:2px solid #4CD964;padding:8px';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    alert('Tokens copied. Paste into Goloom admin → Inbound → WB Stream auth.\n\nClick the textarea to dismiss.');
    ta.addEventListener('click', () => ta.remove());
  } catch (e) { alert('goloom-bookmarklet error: ' + e.message); }
})();
```

### Повторная авторизация (раз в ~14 дней)

Дашборд покажет alert "WB cookies expire tomorrow — please re-auth" за сутки до expiry. Тот же bookmarklet, новый JSON поверх старого, сохрани.

## Подключение клиентов

### Windows GUI

1. Скачай `goloom-wg-gui-windows-amd64.zip` из [Releases](https://github.com/Pinnss/goloom-server/releases).
2. Распакуй (например в `C:\Program Files\Goloom\`).
3. Правый клик → **Запуск от администратора** (нужно для split-tunnel routes).
4. Жми **+** → вставь `goloom://...` connstr → имя профиля → Save.
5. Для VK Calls профилей вставь VK call link в поле **VK Call link** (на ту же ссылку звонка приходит сервер).
6. Жми **Connect**.

### Windows CLI

Создай `goloom-wg-client.yaml`:

```yaml
transport: "vk-calls"          # или "telemost", "livekit-wb-stream"
meeting:   "https://vk.com/call/join/..."
display_name: "alice-laptop"
listen_addr: "127.0.0.1:51820"
```

Запусти от администратора:

```powershell
.\goloom-wg-client.exe -config goloom-wg-client.yaml
```

Затем направь любой WireGuard-клиент (официальное Windows-приложение и т.п.) на `127.0.0.1:51820`.

### Android

1. Скачай последний APK из [goloom-android Releases](https://github.com/Pinnss/goloom-android/releases).
2. Установи. Открой приложение, дай VPN permission.
3. Тап **+ Add profile** → вставь connstr или сканируй QR.
4. Для VK Calls профилей заполни поле **VK Call link**.
5. Тап на профиль → подключение. Первый VK Calls connect покажет WebView с капчей — реши один раз. Клиент сохранит fingerprint и при реконнекте решает капчу автоматически.

## Эксплуатационные заметки

- **Рестарт сервера**: `systemctl restart goloom-wg-server`. Inbound'ы и connstr'ы переживают рестарт.
- **Логи**: `journalctl -u goloom-wg-server -f`. Уровень повышается через `log_level: "debug"` в yaml.
- **Отключить inbound**: переключатель на карточке в дашборде. Connstr остаётся валидным, но подключиться нельзя пока выключен.
- **Удалить inbound**: дашборд → ✕ на карточке. `wg<N>.conf` и маршруты удаляются, connstr перестаёт работать сразу.
