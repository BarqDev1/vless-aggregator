# ⚡ Multi-Protocol VPN Aggregator

[![nodes](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2FBarqDev1%2Fvless-aggregator%2Fmain%2Fstate%2Fstats.json&query=%24.alive&label=nodes&color=brightgreen&cacheSeconds=300)](https://github.com/BarqDev1/vless-aggregator)
[![vless](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2FBarqDev1%2Fvless-aggregator%2Fmain%2Fstate%2Fstats.json&query=%24.alive_by_protocol.vless&label=vless&color=blue&cacheSeconds=300)](https://github.com/BarqDev1/vless-aggregator)
[![hy2](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2FBarqDev1%2Fvless-aggregator%2Fmain%2Fstate%2Fstats.json&query=%24.alive_by_protocol.hysteria2&label=hy2&color=purple&cacheSeconds=300)](https://github.com/BarqDev1/vless-aggregator)
[![p50](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2FBarqDev1%2Fvless-aggregator%2Fmain%2Fstate%2Fstats.json&query=%24.latency_ms.p50&label=p50%20ms&color=orange&cacheSeconds=300)](https://github.com/BarqDev1/vless-aggregator)

Автоматический сборщик, валидатор, дедупликатор и чекер VPN-конфигов из открытых источников.
Поддерживаются **VLESS**, **Trojan** и **Hysteria 2**. Флаги стран нормализуются для балансировщиков Remnawave.

> **VMess и Shadowsocks намеренно исключены.** VMess — по политике проекта, Shadowsocks — из-за нестабильности за TSPU.

## ✨ Возможности

- 🌐 **Протоколы:** `vless://`, `trojan://`, `hysteria2://` (`hy2://` приводится к `hysteria2`).
- ✅ **Валидация до проверки:** UUID (VLESS), `pbk` для Reality, непустой пароль Trojan, корректные host/port.
- ⚡ **Двухступенчатая проверка:**
  - быстрый префильтр: TCP connect для VLESS/Trojan, QUIC v1 handshake (ALPN `h3`) для Hysteria2;
  - **E2E-проверка** (в CI включена): реальный клиент `Xray` поднимает туннель и запрашивает
    `http://www.gstatic.com/generate_204` через HTTP-прокси. Нода попадает в подписку только при `204/200`.
- ⏱️ **Быстрые прогоны:** результат E2E кешируется на `E2E_CACHE_MINUTES` (60 минут), поэтому
  каждые 10 минут проверяются только новые/просроченные ноды. Источники кешируются по ETag/Last-Modified.
  Полное обновление E2E — раз в час, обычный прогон — десятки секунд.
- 🧹 **Точная дедупликация:** ключ включает протокол, хост, порт, учётные данные, SNI и все параметры транспорта
  (`type`, `security`, `path`, `flow` …). Разные UUID на одном сервере **не** схлопываются.
  На один эндпоинт (`протокол + host:port`) тестируется до `MAX_PER_ENDPOINT` вариантов,
  но публикуется только `PUBLISH_PER_ENDPOINT` (по умолчанию 1) — самый быстрый. Поэтому одинаковых
  копий одной ноды в подписке нет.
- 🧱 **Стабильность 2 из 3:** новая нода публикуется после **2 успешных прогонов из последних 3**.
  Существующая нода переживает одно падение в истории и возвращается после следующего успеха.
  Состояние — в `state/node_history.json`.
- 🌍 **Разнообразие:** после проверки ограничивается число нод на `/24` (`MAX_PER_SUBNET`) и на домен
  (`MAX_PER_DOMAIN`), чтобы один хостер не занимал всю подписку.
- 📈 **Сортировка по задержке:** ноды сортируются по времени E2E-запроса (или handshake, если E2E выключен);
  p50/p90 пишутся в `state/stats.json`.
- 🩺 **Атрибуция источников:** `state/stats.json` показывает `raw / unique / alive / yield` по каждому источнику.
  Источник с нулевой отдачей 3 прогона подряд уходит в карантин на 24 часа (`state/source_health.json`).
- 🏳️ **Флаги стран:** эмодзи или ISO-код в remark → нормализованный флаг для группировки в Remnawave.
- 🛡️ **Защита от деградации:** общий и **per-protocol** guard: падение больше `MAX_DROP_RATIO`
  Если стабильность/капсы уменьшили публикацию, но **verified-нод достаточно**, guard не блокирует прогон —
  публикуется проверенный набор, а не старые данные.
  или исчезновение протокола (при прошлом количестве ≥ `PROTOCOL_MIN_ALIVE`) останавливает публикацию.
  Первый прогон с включённым E2E задаёт новый baseline и не сравнивается со старым protocol-only набором.
- 📊 **Статистика прогона** в `state/stats.json` + история в `state/history.json` + состояние источников в `state/source_health.json`.
- 🧾 **Метаданные подписки** в `state/meta.json` (`profile-title`, интервал обновления, support URL, ссылки).
- 🚨 **Алерты:** при падении workflow создаётся/обновляется GitHub Issue.
- 🤖 **GitHub Actions:** линт, `mypy`, тесты с coverage ≥50%, `pip-audit`, затем обновление
  **каждые 30 минут** (`cron: */30 * * * *`) и при изменении `config/sources.txt`.
  Зависимости зафиксированы в `requirements.lock`, обновления — через Dependabot.
  Сгенерированные файлы проверяются тестами до коммита; действия закреплены по SHA,
  параллельные запуски запрещены, история и метаданные коммитятся вместе с прогоном.

---

## 📁 Структура проекта

```text
.
├── config/sources.txt          # список источников
├── src/vpn_aggregator/         # код
│   ├── collector.py
│   ├── e2e.py
│   ├── __init__.py
│   └── __main__.py
├── state/                     # состояние (коммитится)
│   ├── stats.json
│   ├── meta.json
│   ├── history.json
│   ├── node_history.json
│   ├── source_health.json
│   └── source_cache.json
├── tests/
├── vless_universal.txt        # публичные подписки — намеренно в корне,
├── hysteria2.txt              # чтобы старые raw-URL не ломались
└── all_universal.txt
```

Запуск: `PYTHONPATH=src python -m vpn_aggregator`.

---


| Файл | Описание | Для чего использовать |
|---|---|---|
| **`vless_universal.txt`** | Только VLESS | **Для балансировщиков в Remnawave** («Сгруппировать в балансировщики» **ВКЛ**) |
| **`hysteria2.txt`** | Только Hysteria 2 | Для прямого добавления в подписку («Сгруппировать в балансировщики» **ВЫКЛ**) |
| **`all_universal.txt`** | Все проверенные ноды (VLESS + Trojan + Hy2) | Для прямого добавления всех протоколов |
| **`state/stats.json`** | Статистика последнего прогона | Для мониторинга качества |
| **`state/history.json`** | История прогонов (alive, latency, delta) | Для графиков и бейджей |
| **`state/meta.json`** | Метаданные подписки | Для nginx/Remnawave/клиентов |
| **`state/node_history.json`** | История стабильности нод (2 из 3) | Для диагностики |
| **`state/source_health.json`** | Состояние источников и карантин | Для диагностики и ручного снятия карантина |
| **`state/source_cache.json`** | ETag-кеш источников | Для быстрых повторных запусков |

> ⚠️ Не добавляйте одновременно `all_universal.txt` и `vless_universal.txt` в один клиент:
> `all` уже содержит все VLESS, поэтому в списке появятся визуальные дубликаты.
> Для одного клиента используйте **один** файл. Старую подписку перед повторным импортом удаляйте.

### Прямые URL:

```text
https://raw.githubusercontent.com/BarqDev1/vless-aggregator/main/vless_universal.txt
https://raw.githubusercontent.com/BarqDev1/vless-aggregator/main/hysteria2.txt
https://raw.githubusercontent.com/BarqDev1/vless-aggregator/main/all_universal.txt
https://raw.githubusercontent.com/BarqDev1/vless-aggregator/main/state/stats.json
https://raw.githubusercontent.com/BarqDev1/vless-aggregator/main/state/meta.json
https://raw.githubusercontent.com/BarqDev1/vless-aggregator/main/state/history.json
```

---

## 🧾 Метаданные подписки

`state/meta.json` содержит значения, которые обычно отдаются HTTP-заголовками:

```json
{
  "profile_title": "BarqDev Multi-Protocol VPN",
  "profile_update_interval": 1,
  "support_url": "https://github.com/BarqDev1/vless-aggregator/issues",
  "home_url": "https://github.com/BarqDev1/vless-aggregator",
  "subscriptions": {
    "all": ".../all_universal.txt",
    "vless": ".../vless_universal.txt",
    "hysteria2": ".../hysteria2.txt"
  }
}
```

GitHub raw **не позволяет задавать HTTP-заголовки**, поэтому `profile-title` и
`profile-update-interval` нельзя отдать напрямую. Если подписку раздаёт nginx/Remnawave,
проксируйте файл и добавляйте заголовки:

```nginx
add_header profile-title "BarqDev Multi-Protocol VPN";
add_header profile-update-interval 1;
add_header support-url "https://github.com/BarqDev1/vless-aggregator/issues";
```

## 📈 История и наблюдаемость

- `state/history.json` — по одной записи на прогон: `alive`, `protocols`, `delta`, `latency_p50`,
  `e2e_verified`, `e2e_cached`, `e2e_cached_failed`, `held_back`, `sources_active`.
- `state/node_history.json` — хешированные ID нод и последние 3 результата (2 из 3).
- Бейджи в шапке README обновляются из `state/stats.json` через shields.io.

---

## ✅ Что именно значит «проверенная нода»

| Режим | Проверка | Что подтверждается |
|---|---|---|
| Префильтр VLESS/Trojan | TCP connect | Порт принимает соединения |
| Префильтр Hysteria2 | QUIC v1 handshake, ALPN `h3` | На UDP-порту отвечает QUIC/Hysteria2-сервер |
| **E2E (CI)** | Xray туннель + HTTP-запрос | UUID/пароль/Reality-ключи рабочие, есть выход в интернет |
| **E2E (CI)** | Xray Hysteria2-туннель + HTTP-запрос | Hysteria2-аутентификация рабочая, есть выход в интернет |

В CI (`E2E_VERIFY=1`) публикуются только ноды, прошедшие E2E: `http://www.gstatic.com/generate_204`
возвращает `204/200` через туннель. Если E2E выключен, остаётся только protocol-level проверка.
Один неподдерживаемый транспорт может остаться с protocol-level статусом — это видно в `state/stats.json`
(`e2e.unsupported`).

E2E-клиент: **Xray-core v26.10.21**.
Ссылки нормализуются под новое ядро Xray: `insecure`/`allowInsecure` удаляются, для самоподписанных TLS-нод
добавляется `pcs=<sha256>` (pinned certificate), а plaintext-VLESS без TLS/Reality не публикуется.

### Совместимость с Xray 26 / INCY 3.7.9+
- `allowInsecure` и `insecure` в VLESS/Trojan больше не используются — новое ядро их не принимает.
- TLS-ноды с валидным CA-сертификатом проверяются штатно.
- Самоподписанные TLS-ноды получают `pcs=<sha256>` — официальный аналог `allowInsecure` в share-link.
- VLESS без TLS/Reality отбрасывается: Xray 26 не запускает такой публичный outbound.
- Hysteria2-ноды пинятся параметром `pinSHA256=<sha256>`; `insecure=1` больше не публикуется.

---

## ➕ Как добавлять новые источники

Откройте `config/sources.txt` и добавьте одну ссылку на строку:

```text
# Git-репозиторий (клонируется рекурсивно, без API-лимитов)
git+https://gitlab.com/.../repo.git

# Raw-файл или подписка (текст либо base64)
https://raw.githubusercontent.com/.../some_list.txt
https://domain.com/sub/token
```

Строки, начинающиеся с `#`, игнорируются. После изменения `config/sources.txt` GitHub Actions
автоматически запустит тесты и обновит файлы.

---

## ⚙️ Переменные окружения

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `SOURCES_FILE` | `config/sources.txt` | Список источников |
| `VLESS_OUTPUT` | `vless_universal.txt` | Выход VLESS |
| `HY2_OUTPUT` | `hysteria2.txt` | Выход Hysteria2 |
| `ALL_OUTPUT` | `all_universal.txt` | Выход всех протоколов |
| `STATS_OUTPUT` | `state/stats.json` | Статистика |
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
| `MAX_PER_ENDPOINT` | `3` | Сколько вариантов на `протокол + host:port` проверять через E2E |
| `PUBLISH_PER_ENDPOINT` | `1` | Сколько вариантов на `протокол + host:port` публиковать |
| `MAX_PER_SUBNET` | `3` | Максимум нод на IPv4 `/24` или IPv6 `/48` |
| `MAX_PER_DOMAIN` | `10` | Максимум нод на registrable domain |
| `MAX_REMARK_LEN` | `120` | Максимальная длина remark |
| `SOURCE_HEALTH_FILE` | `state/source_health.json` | Состояние источников и карантина |
| `SOURCE_CACHE_FILE` | `state/source_cache.json` | ETag/Last-Modified кеш источников |
| `FETCH_CONCURRENCY` | `16` | Параллельных загрузок источников |
| `E2E_CACHE_MINUTES` | `60` | Сколько минут доверять успешному E2E-результату |
| `E2E_FAILURE_CACHE_MINUTES` | `15` | Сколько минут не перепроверять упавший E2E |
| `SOURCE_FAILURE_THRESHOLD` | `3` | Прогонов с нулевой отдачей до карантина |
| `SOURCE_QUARANTINE_HOURS` | `24` | Длительность карантина, часы |
| `NODE_HISTORY_FILE` | `state/node_history.json` | История стабильности нод |
| `NODE_MIN_RECENT_SUCCESS` | `2` | Сколько успехов нужно в окне |
| `NODE_RECENT_WINDOW` | `3` | Размер окна проверок |
| `NODE_HISTORY_TTL_DAYS` | `30` | Сколько дней хранить историю нод |
| `HISTORY_FILE` | `state/history.json` | История прогонов |
| `HISTORY_MAX_RUNS` | `1440` | Максимум записей истории (30 дней при 30-мин интервале) |
| `META_FILE` | `state/meta.json` | Метаданные подписки |
| `PROFILE_TITLE` | `BarqDev Multi-Protocol VPN` | Название профиля |
| `PROFILE_UPDATE_INTERVAL` | `0.5` | Интервал обновления, часы (30 минут) |
| `SUPPORT_URL` | GitHub Issues | Support URL |
| `HOME_URL` | GitHub репозиторий | Home URL |
| `E2E_VERIFY` | `0` | Включить E2E-проверку (`1` в CI) |
| `E2E_CONCURRENCY` | `10` | Параллельных E2E-клиентов |
| `E2E_TIMEOUT` | `5.0` | Таймаут HTTP-запроса через туннель, сек |
| `XRAY_BIN` | `xray` | Путь к бинарнику Xray |
| `BASELINE_RESET` | `0` | Пропустить drop-guard при намеренном изменении набора источников |

---

## 🚀 Локальный запуск

Требуется Python 3.12+.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt

# Быстрый прогон без E2E (по умолчанию)
PYTHONPATH=src python -m vpn_aggregator

# Полный прогон с E2E (нужен бинарник Xray 26.10.21)
E2E_VERIFY=1 XRAY_BIN=/path/to/xray PYTHONPATH=src python -m vpn_aggregator

pytest
ruff check .
```

Коды возврата коллектора:

- `0` — успех;
- `1` — сработала защита (файлы не изменены);
- `2` — нет источников, ни одной валидной ноды или E2E включён, но бинарники недоступны.
