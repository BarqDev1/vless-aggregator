# ⚡ Multi-Protocol VPN Aggregator

Автоматический сборщик, дедупликатор и чекер VPN серверов из любых открытых источников. Поддерживает **VLESS**, **Trojan**, **Hysteria 2**, **VMess** и автоматически нормализует флаги стран для балансировщиков Remnawave.

## ✨ Возможности
- 🌐 **Мультипротокольность:** собирает и проверяет `vless://`, `trojan://`, `hysteria2://` (`hy2://`), `vmess://`.
- ⚡ **Двойная проверка доступности:** асинхронный TCP Ping (для VLESS, Trojan, VMess) и UDP DNS/route test (для Hysteria 2).
- 🧹 **Умная дедупликация:** фильтрует дубликаты по `scheme:host:port:sni`.
- 🏳️ **Флаги стран:** автоматически определяет и нормализует флаги (`🇷🇺`, `🇩🇪`, `🇳🇱` и др.), чтобы Remnawave корректно группировал их в балансировщики.
- 🤖 **GitHub Actions:** автоматически обновляет файлы **каждый час** (`cron: 0 * * * *`) и при любом изменении `sources.txt`.

---

## 🔗 Готовые ссылки для подключения (Raw GitHub)

| Ссылка | Описание | Для чего использовать |
|---|---|---|
| **`vless_universal.txt`** | Только чистый VLESS (Reality, WS, XHTTP) | **Для балансировщиков в Remnawave** («Сгруппировать в балансировщики» **ВКЛ**) |
| **`hysteria2.txt`** | Высокоскоростные Hysteria 2 ноды | Для прямого добавления в подписку («Сгруппировать в балансировщики» **ВЫКЛ**) |
| **`all_universal.txt`** | Все проверенные серверы всех протоколов | Для прямого добавления всех протоколов в подписку |

### Прямые URL:
```text
https://raw.githubusercontent.com/BarqDev1/vless-aggregator/main/vless_universal.txt
https://raw.githubusercontent.com/BarqDev1/vless-aggregator/main/hysteria2.txt
https://raw.githubusercontent.com/BarqDev1/vless-aggregator/main/all_universal.txt
```

---

## ➕ Как добавлять новые ссылки

Откройте файл `sources.txt` (локально или прямо на сайте GitHub) и допишите нужную ссылку новой строкой:
```text
git+https://gitlab.com/.../*.git
https://raw.githubusercontent.com/.../some_list.txt
https://domain.com/sub/token
```
После сохранения GitHub Actions автоматически запустит сборщик и обновит все три файла.
