# ⚡ VLESS Aggregator

Автоматический сборщик, дедупликатор и чекер VLESS Reality серверов из нескольких источников. Объединяет любые внешние подписки в один единый файл `vless_universal.txt` для Remnawave и других VPN-панелей.

## ✨ Возможности
- 📥 **Поддержка любых источников:** raw ссылки GitHub, обычные текстовые списки, base64-подписки.
- 🧹 **Умная дедупликация:** исключает повторяющиеся серверы (по IP, порту и SNI).
- ⚡ **TCP Ping Check:** асинхронно пингует каждый сервер перед добавлением и отсеивает мёртвые ноды.
- 🏳️ **Флаги стран:** автоматически определяет и добавляет флаги стран (`🇷🇺`, `🇩🇪`, `🇳🇱` и т.д.), чтобы Remnawave автоматически группировал их в балансировщики.
- 🤖 **GitHub Actions:** каждые 2 часа сам скачивает свежие списки, проверяет их и пушит обновленный файл в репозиторий.

---

## 🚀 Быстрый старт: Публикация на GitHub

1. **Создайте новый пустой репозиторий на GitHub:**
   - Назовите его, например: `vless-aggregator` (публичный — `Public`).
   - Не добавляйте README и .gitignore (они уже есть здесь).

2. **В терминале в папке этого проекта выполните:**
   ```bash
   cd /Users/barqdev/Desktop/MY_APPS/vless-aggregator
   git init
   git branch -M main
   git add .
   git commit -m "feat: initial commit of vless aggregator"
   git remote add origin https://github.com/BarqDev1/vless-aggregator.git
   git push -u origin main
   ```

3. **Включите права для GitHub Actions (важно!):**
   - Перейдите в ваш репозиторий на GitHub: `Settings` → `Actions` → `General`.
   - Прокрутите до блока **Workflow permissions**.
   - Выберите **Read and write permissions** и нажмите **Save**.

---

## 🔗 Как подключить к панели Remnawave

1. Ваша единая итоговая ссылка будет:
   ```text
   https://raw.githubusercontent.com/BarqDev1/vless-aggregator/main/vless_universal.txt
   ```
2. Откройте панель администратора Remnawave → **Внешние подписки**.
3. В блоке **ДОБАВИТЬ НОВУЮ ССЫЛКУ**:
   - Тумблер **«Сгруппировать в балансировщики»**: **ВКЛ**
   - **Название в VPN-приложении (Окончание)**: `Белые списки — LTE`
   - **URL ссылки**: вставьте вашу ссылку `https://raw.githubusercontent.com/BarqDev1/vless-aggregator/main/vless_universal.txt`
   - Нажмите **«+ Сгенерировать»**.
4. Включите **«ФОНОВОЕ АВТООБНОВЛЕНИЕ»**.

Теперь панель будет автоматически брать все проверенные серверы из вашего репозитория и наполнять 4 балансировщика!

---

## ➕ Как добавлять новые ссылки

Просто откройте файл `sources.txt` (на компьютере или прямо на сайте GitHub) и допишите новую ссылку новой строкой:
```text
https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt
https://raw.githubusercontent.com/.../another_list.txt
```
После сохранения GitHub Actions автоматически запустит сборку и обновит файл.
