# VLESS Parser

[![Update CFG](https://github.com/r2d4m0/vless-parser/actions/workflows/auto_update.yml/badge.svg)](https://github.com/r2d4m0/vless-parser/actions/workflows/auto_update.yml)

Минималистичный `VLESS` parser для белых списков.
fork https://github.com/AvenCores/goida-vpn-configs

Скрипт обновляет два файла:
- `githubmirror/whitelist-vless.txt` — полный whitelist-список
- `githubmirror/ru-sni-best-vless.txt` — более жёстко отфильтрованный shortlist с русским `SNI`

Что делает parser:
- ходит только во внешние whitelist-источники
- оставляет только `vless://`
- отбрасывает конфиги с `allowinsecure`
- оставляет только `security=reality` или `security=tls`
- требует наличие `sni` или `host`
- удаляет дубли по серверным параметрам
- сортирует основной файл стабильно, чтобы он не дёргался без причины
- сравнивает текущее и новое содержимое и пишет в лог: изменился файл или нет, сколько строк добавилось и удалилось
- добавляет metadata-шапку с названием профиля, описанием `Parsed by VLESS Parser` и временем последнего обновления содержимого

`ru-sni-best-vless.txt` — это не гарантия, а эвристический shortlist. Туда попадают только более жёстко отобранные конфиги: с русским `SNI`, `security=reality`, `pbk`, нормальным transport и без явных слабых признаков вроде `fp=randomized` или IPv6.

## Источники

Используются только whitelist-источники:
- `WHITE-CIDR-RU-all.txt`
- `WHITE-SNI-RU-all.txt`
- `zieng2/wl`
- `EtoNeYaProject`
- `ByeWhiteLists2`
- `white-lists.vercel.app`
- `wlrus.lol`

Если часть источников временно недоступна, parser продолжает работу по тем, которые ответили. Если не ответил ни один источник, существующий `githubmirror/whitelist-vless.txt` не перезаписывается.

## Локальный запуск

```bash
git clone https://github.com/<you>/<repo>.git
cd <repo>
python -m pip install -r source/requirements.txt
echo GITHUB_TOKEN=<your_token> > .env
python source/main.py
```

Файл результата:

```text
githubmirror/whitelist-vless.txt
githubmirror/ru-sni-best-vless.txt
```

Дополнительные параметры:

```bash
python source/main.py --output githubmirror/whitelist-vless.txt --reliable-output githubmirror/ru-sni-best-vless.txt --timeout 8 --max-attempts 2 --max-workers 8 --reliable-limit 200
```

## GitHub Actions

Workflow в [.github/workflows/auto_update.yml](./.github/workflows/auto_update.yml) делает только две вещи:
1. запускает parser
2. коммитит `githubmirror/whitelist-vless.txt` и `githubmirror/ru-sni-best-vless.txt`, если они изменились

Python-скрипт больше не пушит в git и не зависит от `MY_TOKEN`.

## Структура

```text
.github/workflows/auto_update.yml  - автообновление каждые 9 минут
githubmirror/whitelist-vless.txt   - итоговая whitelist VLESS-подписка
githubmirror/ru-sni-best-vless.txt - shortlist более жёстко отобранных RU-SNI конфигов
source/main.py                     - parser
source/requirements.txt            - зависимости
```

## Примечание

Это whitelist-only fork. Автоматизация обновляет `githubmirror/whitelist-vless.txt` и `githubmirror/ru-sni-best-vless.txt`.

`GITHUB_TOKEN` в корневом `.env` необязателен, но если он задан, parser будет использовать его только для запросов к GitHub-хостам.
