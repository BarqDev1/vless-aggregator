# ⚡ Multi-Protocol VPN Aggregator

Автоматический сборщик, валидатор, дедупликатор и чекер VPN-конфигов из открытых источников.
Поддерживаются **VLESS**, **Trojan** и **Hysteria 2**. Флаги стран нормализуются для балансировщиков Remnawave.

> **VMess и Shadowsocks намеренно исключены.** VMess — по политике проекта, Shadowsocks — из-за нестабильности за TSPU.

## ✨ Возможности

- 🌐 **Протоколы:** `vless://`, `trojan://`, `hysteria2://` (`hy2://` приводится к `hysteria2`).
- ✅ **Валидация до проверки:** UUID (VLESS), `pbk` для Reality, непустой пароль Trojan, корректные host/port.
- ⚡ **Двухступенчатая проверка:**
  - быстрый префильтр: TCP connect для VLESS/Trojan, QUIC v1 handshake (ALPN `h3`) для Hysteria2;
  - **E2E-проверка** (в CI включена): реальный клиент `Xray`/`sing-box` поднимает туннель и запрашивает
    `http://www.gstatic.com/generate_204` через HTTP-прокси. Нода попадает в подписку только при `204/200`.
- 🧹 **Точная дедупликация:** ключ включает протокол, хост, порт, учётные данные, SNI и все параметры транспорта
  (`type`, `security`, `path`, `flow` …). Разные UUID на одном сервере **не** схлопываются.
  На один эндпоинт (`протокол + host:port + SNI`) публикуется не больше `MAX_PER_ENDPOINT` вариантов.
- 🌍 **Разнообразие:** после проверки ограничивается число нод на `/24` (`MAX_PER_SUBNET`) и на домен
  (`MAX_PER_DOMAIN`), чтобы один хостер не занимал всю подписку.
- 📈 **Сортировка по задержке:** ноды сортируются по времени E2E-запроса (или handshake, если E2E выключен);
  p50/p90 пишутся в `stats.json`.
- 🩺 **Атрибуция источников:** `stats.json` показывает `raw / unique / alive / yield` по каждому источнику.
  Источник с нулевой отдачей 3 прогона подряд уходит в карантин на 24 часа (`source_health.json`).
- 🏳️ **Флаги стран:** эмодзи или ISO-код в remark → нормализованный флаг для группировки в Remnawave.
- 🛡️ **Защита от деградации:** общий и **per-protocol** guard: падение больше `MAX_DROP_RATIO`
  или исчезновение протокола (при прошлом количестве ≥ `PROTOCOL_MIN_ALIVE`) останавливает публикацию.
  Первый прогон с включённым E2E задаёт новый baseline и не сравнивается со старым protocol-only набором.
- 📊 **Статистика прогона** в `stats.json` + состояние источников в `source_health.json`.
- 🚨 **Алерты:** при падении workflow создаётся/обновляется GitHub Issue.
- 🤖 **GitHub Actions:** линт + тесты, затем обновление **каждый час** (`cron: 0 * * * *`) и при изменении `sources.txt`.
  Сгенерированные файлы проверяются тестами до коммита; действия закреплены по SHA,
  параллельные запуски запрещены, `stats.json` коммитится только вместе с изменением данных.

---

## 🔗 Готовые ссылки для подключения (Raw GitHub)

| Файл | Описание | Для чего использовать |
|---|---|---|
| **`vless_universal.txt`** | Только VLESS | **Для балансировщиков в Remnawave** («Сгруппировать в балансировщики» **ВКЛ**) |
| **`hysteria2.txt`** | Только Hysteria 2 | Для прямого добавления в подписку («Сгруппировать в балансировщики» **ВЫКЛ**) |
| **`all_universal.txt`** | Все проверенные ноды (VLESS + Trojan + Hy2) | Для прямого добавления всех протоколов |
| **`stats.json`** | Статистика последнего прогона | Для мониторинга качества |
| **`source_health.json`** | Состояние источников и карантин | Для диагностики и ручного снятия карантина |

### Прямые URL:

```text
https://raw.githubusercontent.com/BarqDev1/vless-aggregator/main/vless_universal.txt
https://raw.githubusercontent.com/BarqDev1/vless-aggregator/main/hysteria2.txt
https://raw.githubusercontent.com/BarqDev1/vless-aggregator/main/all_universal.txt
https://raw.githubusercontent.com/BarqDev1/vless-aggregator/main/stats.json
```

---

## ✅ Что именно значит «проверенная нода»

| Режим | Проверка | Что подтверждается |
|---|---|---|
| Префильтр VLESS/Trojan | TCP connect | Порт принимает соединения |
| Префильтр Hysteria2 | QUIC v1 handshake, ALPN `h3` | На UDP-порту отвечает QUIC/Hysteria2-сервер |
| **E2E (CI)** | Xray туннель + HTTP-запрос | UUID/пароль/Reality-ключи рабочие, есть выход в интернет |
| **E2E (CI)** | sing-box туннель + HTTP-запрос | Hysteria2-аутентификация рабочая, есть выход в интернет |

В CI (`E2E_VERIFY=1`) публикуются только ноды, прошедшие E2E: `http://www.gstatic.com/generate_204`
возвращает `204/200` через туннель. Если E2E выключен, остаётся только protocol-level проверка.
Один неподдерживаемый транспорт может остаться с protocol-level статусом — это видно в `stats.json`
(`e2e.unsupported`).

E2E-клиенты: **Xray-core v26.10.21** и **sing-box v1.14.4**.
Ссылки нормализуются под новое ядро Xray: `insecure`/`allowInsecure` удаляются, для самоподписанных TLS-нод
добавляется `pcs=<sha256>` (pinned certificate), а plaintext-VLESS без TLS/Reality не публикуется.

### Совместимость с Xray 26 / INCY 3.7.9+
- `allowInsecure` и `insecure` в VLESS/Trojan больше не используются — новое ядро их не принимает.
- TLS-ноды с валидным CA-сертификатом проверяются штатно.
- Самоподписанные TLS-ноды получают `pcs=<sha256>` — официальный аналог `allowInsecure` в share-link.
- VLESS без TLS/Reality отбрасывается: Xray 26 не запускает такой публичный outbound.
- Hysteria2 сохраняет `insecure=1` — это параметр sing-box, а не Xray TLS.

---

## ➕ Как добавлять новые источники

Откройте `sources.txt` и добавьте одну ссылку на строку:

```text
# Git-репозиторий (клонируется рекурсивно, без API-лимитов)
git+https://gitlab.com/.../repo.git

# Raw-файл или подписка (текст либо base64)
https://raw.githubusercontent.com/.../some_list.txt
https://domain.com/sub/token
```

Строки, начинающиеся с `#`, игнорируются. После изменения `sources.txt` GitHub Actions
автоматически запустит тесты и обновит файлы.

---

## ⚙️ Переменные окружения

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `SOURCES_FILE` | `sources.txt` | Список источников |
| `VLESS_OUTPUT` | `vless_universal.txt` | Выход VLESS |
| `HY2_OUTPUT` | `hysteria2.txt` | Выход Hysteria2 |
| `ALL_OUTPUT` | `all_universal.txt` | Выход всех протоколов |
| `STATS_OUTPUT` | `stats.json` | Статистика |
| `PING_TIMEOUT` | `3.0` | Таймаут TCP-проверки, сек |
| `QUIC_TIMEOUT` | `5.0` | Таймаут QUIC-handshake, сек |
| `CHECK_ATTEMPTS` | `2` | Попыток проверки на ноду |
| `CONCURRENCY` | `60` | Параллельных проверок |
| `FETCH_TIMEOUT` | `20.0` | Таймаут загрузки источника, сек |
| `FETCH_ATTEMPTS` | `3` | Попыток загрузки источника |
| `MIN_ALIVE` | `10` | Минимум живых нод для публикации |
| `MAX_DROP_RATIO` | `0.5` | Максимальное падение относительно прошлого прогона |
| `PROTOCOL_MIN_ALIVE` | `3` | С какого количества включается per-protocol guard |
| `PROTOCOL_MAX_DROP` | `0.7` | Максимальное падение отдельного протокола |
| `MAX_PER_ENDPOINT` | `3` | Максимум вариантов на один `протокол + host:port + SNI` |
| `MAX_PER_SUBNET` | `3` | Максимум нод на IPv4 `/24` или IPv6 `/48` |
| `MAX_PER_DOMAIN` | `10` | Максимум нод на registrable domain |
| `MAX_REMARK_LEN` | `120` | Максимальная длина remark |
| `SOURCE_HEALTH_FILE` | `source_health.json` | Состояние источников и карантина |
| `SOURCE_FAILURE_THRESHOLD` | `3` | Прогонов с нулевой отдачей до карантина |
| `SOURCE_QUARANTINE_HOURS` | `24` | Длительность карантина, часы |
| `E2E_VERIFY` | `0` | Включить E2E-проверку (`1` в CI) |
| `E2E_CONCURRENCY` | `6` | Параллельных E2E-клиентов |
| `E2E_TIMEOUT` | `7.0` | Таймаут HTTP-запроса через туннель, сек |
| `XRAY_BIN` | `xray` | Путь к бинарнику Xray |
| `SING_BOX_BIN` | `sing-box` | Путь к бинарнику sing-box |
| `BASELINE_RESET` | `0` | Пропустить drop-guard при намеренном изменении набора источников |

---

## 🚀 Локальный запуск

Требуется Python 3.12+.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt

# Быстрый прогон без E2E (по умолчанию)
python collector.py

# Полный прогон с E2E (нужны бинарники Xray 25.3.6 и sing-box 1.14.4)
E2E_VERIFY=1 XRAY_BIN=/path/to/xray SING_BOX_BIN=/path/to/sing-box python collector.py

pytest
ruff check .
```

Коды возврата коллектора:

- `0` — успех;
- `1` — сработала защита (файлы не изменены);
- `2` — нет источников, ни одной валидной ноды или E2E включён, но бинарники недоступны.
