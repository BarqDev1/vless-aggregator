# ☁️ Деплой на Oracle Cloud Always Free (4 OCPU ARM64 / 24 GB RAM)

Проект полностью адаптирован под круглосуточную работу на бесплатном инстансе **Oracle Cloud Ampere A1** (`aarch64`/`arm64`, 4 OCPU, 24 GB RAM) — с пакетным Xray E2E (`E2E_BATCH_SIZE=32`), встроенным HTTP-сервером подписок и циклом обновления каждые **15 минут**.

---

## Что изменилось для сервера

| Компонент | GitHub Actions (раньше) | Oracle Cloud (теперь) |
|---|---|---|
| Интервал обновлений | Раз в 5–11 часов | Строго каждые **15 минут** |
| E2E-проверка | 1 процесс `xray` + 1 `curl` на ноду | **Батч по 32 ноды** на 1 процесс Xray + async `aiohttp` (`48` воркеров) |
| Кэш E2E (`45 мин`) | Не работал из-за редкого cron | **Работает**, прогон занимает **20–40 сек** |
| Раздача подписок | GitHub Raw (кэш 5 мин, нет заголовков) | Встроенный HTTP-сервер с нативными заголовками (`profile-title`, `Base64`) |
| Пинг и рейтинг | Одиночный срез | **EMA-задержка** + бонус за серию успехов (`streak >= 3`) |

---

## Вариант 1: Быстрая установка на Ubuntu (`systemd`, рекомендуется)

1. Подключитесь по SSH к инстансу Oracle Cloud и склонируйте репозиторий:

```bash
git clone https://github.com/BarqDev1/vless-aggregator.git /opt/vless-aggregator
cd /opt/vless-aggregator
sudo bash deploy/oracle/install.sh
```

Скрипт автоматически:
- установит `Xray-core v26.7.28` под `arm64` (или `amd64`) с проверкой SHA-256;
- создаст `.venv` и пользователя `aggregator`;
- сгенерирует случайный `SUB_KEY` в `/etc/vpn-aggregator.env` (`chmod 600`);
- запустит службу `vpn-aggregator.service`.

2. Откройте порты в **двух** местах (особенность Oracle Cloud!):
   - **Oracle Cloud Console:** `Networking → Virtual Cloud Networks → Subnet → Security Lists → Add Ingress Rules` (TCP `8080`, либо `80`/`443` при использовании Caddy).
   - **Внутри Ubuntu (iptables по умолчанию блокирует всё кроме 22!):**
     ```bash
     sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 8080 -j ACCEPT
     sudo netfilter-persistent save
     ```

3. Проверка:

```bash
curl http://127.0.0.1:8080/health
sudo journalctl -u vpn-aggregator -f
```

---

## Вариант 2: Docker Compose (+ авто-HTTPS через Caddy)

```bash
cd /opt/vless-aggregator/deploy/oracle
cp .env.example .env
# Впишите свой SUB_KEY (openssl rand -hex 24) и DOMAIN (если есть домен)
nano .env

# Только HTTP на порту 8080 (для теста с BIND_ADDR=0.0.0.0):
BIND_ADDR=0.0.0.0 docker compose up -d --build

# С доменом и автоматическим HTTPS (Let's Encrypt через Caddy):
docker compose --profile tls up -d --build
```

---

## Эндпоинты сервера

- `GET /health` — статус (`alive`, `updated_at`, `running`) без раскрытия подписок.
- `GET /<SUB_KEY>/all` — все проверенные ноды (VLESS + Hy2 + Trojan).
- `GET /<SUB_KEY>/vless` — только VLESS.
- `GET /<SUB_KEY>/hy2` — только Hysteria 2.
- `GET /<SUB_KEY>/all/base64` (или `?format=base64`) — Base64-подписка для клиентов, которым нужен Base64.
- `GET /<SUB_KEY>/stats`, `/meta`, `/history` — JSON-метрики.
- `POST /<SUB_KEY>/refresh` — ручной внеочередной запуск обновления (кулдаун 60 сек).

---

## Безопасность

- Без `SUB_KEY` длиной ≥ 16 символов сервер **не запустится** (fail-closed, если явно не задать `ALLOW_PUBLIC_SUBS=1`).
- Сравнение ключа выполняется в constant-time (`hmac.compare_digest`), неверный ключ отдаёт `404`.
- Включены per-IP rate limiting (`RATE_LIMIT_PER_MINUTE=60`), блокировка `.*` путей (`404`) и строгие HTTP-заголовки (`CSP`, `nosniff`, `HSTS`, `X-Frame-Options: DENY`).
