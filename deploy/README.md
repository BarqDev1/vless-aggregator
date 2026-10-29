# 🔒 Приватный репозиторий + Cloudflare Worker

Если сделать `vless-aggregator` приватным, обычные raw-ссылки перестанут работать:

```text
https://raw.githubusercontent.com/BarqDev1/vless-aggregator/main/all_universal.txt
```

Приватный raw требует авторизацию, а INCY/Remnawave не умеют подставлять GitHub-токен.
Решение — маленький Worker, который хранит PAT и отдаёт подписки по секретному URL.

```text
INCY / Remnawave
      │
      ▼
https://sub.example.com/<SUB_KEY>/all
      │
      ▼
Cloudflare Worker (GH_TOKEN)
      │
      ▼
GitHub API → private vless-aggregator
```

---

## 1. Создать PAT

GitHub → **Settings → Developer settings → Fine-grained tokens → Generate new token**.

- Repository access: **Only select repositories** → `vless-aggregator`
- Permissions: **Contents: Read-only**
- Expiration: 90 дней или больше

Токен понадобится только Worker'у.

---

## 2. Установить Wrangler

```bash
npm install -g wrangler
# или
npx wrangler@latest --version
```

Логин:

```bash
wrangler login
```

---

## 3. Задеплоить Worker

Из папки `deploy`:

```bash
cd deploy
wrangler deploy
```

Wrangler покажет URL вида:

```text
https://vpn-aggregator-subscriptions.<ваш-субдомен>.workers.dev
```

---

## 4. Добавить секреты

```bash
cd deploy

wrangler secret put GH_TOKEN
# вставить fine-grained PAT

wrangler secret put SUB_KEY
# вставить случайную строку, например:
# openssl rand -hex 24
```

`SUB_KEY` — это часть URL. Он должен быть длинным и случайным.

---

## 5. Проверить

```bash
curl -i "https://vpn-aggregator-subscriptions.<sub>.workers.dev/<SUB_KEY>/all"
curl -i "https://vpn-aggregator-subscriptions.<sub>.workers.dev/<SUB_KEY>/vless"
```

Должен быть `200` и список ссылок.

Проверка служебного эндпоинта:

```bash
curl "https://vpn-aggregator-subscriptions.<sub>.workers.dev/health"
# ok
```

---

## 6. Сделать репозиторий приватным

Только после того, как Worker проверен:

```text
GitHub → Settings → General → Danger Zone → Change visibility → Make private
```

После этого старые raw-URL начнут отдавать `404` — это ожидаемо.

---

## 7. Заменить ссылки в клиентах

```text
https://vpn-aggregator-subscriptions.<sub>.workers.dev/<SUB_KEY>/all
https://vpn-aggregator-subscriptions.<sub>.workers.dev/<SUB_KEY>/vless
https://vpn-aggregator-subscriptions.<sub>.workers.dev/<SUB_KEY>/hy2
https://vpn-aggregator-subscriptions.<sub>.workers.dev/<SUB_KEY>/ss
```

В INCY: удалить старую подписку, добавить новый URL.

Если используете Remnawave:

1. Импортировать Worker-URL как источник.
2. Раздавать пользователям **Remnawave-ссылку**, а не Worker-URL.
3. Тогда можно отзывать доступ пользователям.

---

## 8. Свой домен (опционально)

В `deploy/wrangler.toml`:

```toml
routes = [
  { pattern = "sub.example.com/*", zone_name = "example.com" }
]
```

Затем:

```bash
cd deploy
wrangler deploy
```

---

## ⚠️ GitHub Actions минуты

Публичный репозиторий = Actions бесплатно.  
Приватный = расходуются минуты.

При cron **каждые 30 минут**:

```text
48 запусков/день × ~2–3 минуты × 30 дней ≈ 2900–4300 минут/месяц
```

Бесплатный лимит обычно **2000 минут**. Варианты:

- cron раз в час;
- cron раз в 2–3 часа;
- self-hosted runner;
- платный план GitHub.

Можно оставить репозиторий публичным, а приватным сделать только Worker/подписку.

---

## 🔐 Безопасность

- Не коммитьте `GH_TOKEN` и `SUB_KEY` в репозиторий.
- `SUB_KEY` — не пароль, а секретный путь. Если он утёк — rotate:
  ```bash
  wrangler secret put SUB_KEY
  ```
- PAT хранится только в Cloudflare Secrets.
- Fine-grained PAT с `Contents: Read` достаточно.
- Worker кеширует ответы на 60 секунд.
- Ротируйте PAT и `SUB_KEY` при подозрении на утечку.

---

## 🧯 Если не работает

| Симптом | Проверка |
|---|---|
| `404` | неверный `SUB_KEY` или имя файла |
| `502` | PAT истёк / нет доступа к repo |
| `500 Worker is not configured` | не заданы `GH_TOKEN`/`SUB_KEY` |
| Пустой ответ | проверьте, что файл существует в `main` |
| `wrangler deploy` не видит config | запускайте из папки `deploy` |

Логи:

```bash
cd deploy
wrangler tail
```

---

## Альтернатива: VPS + nginx

Если не хотите Cloudflare:

1. Cron на VPS скачивает файлы через GitHub API с PAT.
2. Nginx отдаёт их по секретному пути:

```nginx
location /<SUB_KEY>/ {
    alias /srv/vpn-subscriptions/;
    add_header profile-title "BarqDev Multi-Protocol VPN";
    add_header profile-update-interval 0.5;
}
```

3. Клиенты используют `https://sub.example.com/<SUB_KEY>/all`.

Это тот же принцип, только без Cloudflare.
