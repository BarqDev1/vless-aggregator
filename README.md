# ⚡ Multi-Protocol VPN Aggregator

Автоматический сборщик, валидатор, дедупликатор и чекер VPN-конфигов из открытых источников.
Поддерживаются **VLESS**, **Trojan** и **Hysteria 2**. Флаги стран нормализуются для балансировщиков Remnawave.

> **VMess и Shadowsocks намеренно исключены.** VMess — по политике проекта, Shadowsocks — из-за нестабильности за TSPU.

## ✨ Возможности

- 🌐 **Протоколы:** `vless://`, `trojan://`, `hysteria2://` (`hy2://` приводится к `hysteria2`).
- ✅ **Валидация до проверки:** UUID (VLESS), `pbk` для Reality, непустой пароль Trojan, корректные host/port.
- ⚡ **Честная проверка доступности:**
  - VLESS / Trojan — TCP-подключение (3 с, 2 попытки);
  - Hysteria2 — QUIC v1 handshake с ALPN `h3` (5 с, 2 попытки), а не «DNS резолвится».
- 🧹 **Точная дедупликация:** ключ включает протокол, хост, порт, учётные данные, SNI и все параметры транспорта
  (`type`, `security`, `path`, `flow` …). Разные UUID на одном сервере **не** схлопываются.
  Дополнительно на один эндпоинт (`протокол + host:port + SNI`) публикуется не больше `MAX_PER_ENDPOINT` вариантов —
  чтобы один сервер с сотней паролей не забивал подписку.
- 🏳️ **Флаги стран:** эмодзи или ISO-код в remark → нормализованный флаг для группировки в Remnawave.
- 🛡️ **Защита от стирания подписки:** если живых нод меньше `MIN_ALIVE` или падение больше `MAX_DROP_RATIO`,
  коллектор завершается с кодом `1`, а предыдущие файлы остаются нетронутыми. Запись — атомарная.
- 📊 **Статистика прогона** в `stats.json`.
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

### Прямые URL:

```text
https://raw.githubusercontent.com/BarqDev1/vless-aggregator/main/vless_universal.txt
https://raw.githubusercontent.com/BarqDev1/vless-aggregator/main/hysteria2.txt
https://raw.githubusercontent.com/BarqDev1/vless-aggregator/main/all_universal.txt
https://raw.githubusercontent.com/BarqDev1/vless-aggregator/main/stats.json
```

---

## ✅ Что именно значит «проверенная нода»

| Протокол | Проверка | Что подтверждается |
|---|---|---|
| VLESS | TCP connect | Порт принимает соединения |
| Trojan | TCP connect | Порт принимает соединения |
| Hysteria2 | QUIC v1 handshake, ALPN `h3` | На UDP-порту действительно отвечает QUIC/Hysteria2-сервер |

Это **проверка сетевой доступности на уровне протокола**, а не полный тест туннеля:
пароль/UUID и выход в интернет не проверяются. Такой подход быстрый и не требует запуска `sing-box` на каждую ноду.

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
| `MAX_PER_ENDPOINT` | `3` | Максимум вариантов на один `протокол + host:port + SNI` |
| `MAX_REMARK_LEN` | `120` | Максимальная длина remark |

---

## 🚀 Локальный запуск

Требуется Python 3.12+.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
python collector.py
pytest
ruff check .
```

Коды возврата коллектора:

- `0` — успех;
- `1` — сработала защита (файлы не изменены);
- `2` — нет источников или ни одной валидной ноды.
