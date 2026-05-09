# Rust WAF Interceptor

`Rust WAF Interceptor` — это учебный Web Application Firewall на Rust для защиты уязвимого веб-приложения `OWASP Juice Shop`.

Проект реализован как монолитный сервис, который:
- принимает HTTPS-трафик от клиента;
- анализирует запросы на признаки атак;
- блокирует или логирует их в зависимости от режима работы;
- проксирует разрешенные запросы в защищаемое приложение;
- предоставляет web-интерфейс администратора для управления правилами, политиками и журналом атак.

## Что делает проект

WAF покрывает несколько основных задач:
- reverse proxy перед `Juice Shop`;
- сигнатурный анализ атак;
- positive security model для endpoint-ов;
- IP allow/deny lists;
- журналирование атак в `SQLite`;
- admin API и web-панель;
- TLS termination на стороне WAF.

Поддерживаемые векторы атак:
- SQL Injection;
- XSS;
- Path Traversal;
- ошибки конфигурации безопасности на уровне gateway response headers.

## Как работает WAF

Поток запроса выглядит так:

1. Клиент отправляет HTTPS-запрос на WAF.
2. Interceptor в `src/runtime/proxy.rs` принимает запрос и завершает TLS.
3. Из запроса собирается `AnalysisRequest`.
4. Analyzer в `src/core/analyzer.rs` выполняет:
   - проверку по IP-спискам;
   - проверку по security policies;
   - нормализацию входных данных;
   - сигнатурный анализ по precompiled regex-правилам.
5. Если запрос вредоносный:
   - в `active` режиме он блокируется;
   - в `passive` режиме он пропускается, но логируется.
6. Если запрос разрешен, WAF проксирует его в `Juice Shop`.
7. Ответ от backend возвращается клиенту через WAF с внедрением защитных HTTP-заголовков.
8. Информация об атаках сохраняется в `SQLite` и отображается в admin panel.

## Структура данных

Проект использует:
- `data/config.json` — основная конфигурация WAF;
- `data/rules.json` — сигнатурные правила;
- `data/sec_policies.json` — политики безопасности;
- `waf.db` — журнал атак, пользователи и IP-списки.

В Docker-сценарии:
- `config.json`, `rules.json`, `sec_policies.json` подключаются как bind mount;
- `waf.db` хранится в Docker volume;
- TLS-ключи и сертификаты подключаются как read-only bind mount.

## Развертывание через Docker

### 1. Подготовьте сертификаты

Для локальной разработки ожидаются файлы:
- `data/certs/waf.local.pem`
- `data/certs/waf.local-key.pem`

Их можно выпустить через `mkcert`:

```powershell
mkcert -install
mkcert -cert-file .\data\certs\waf.local.pem -key-file .\data\certs\waf.local-key.pem waf.local localhost 127.0.0.1
```

При необходимости добавьте в `hosts`:

```text
127.0.0.1 waf.local
```

### 2. Проверьте конфигурационные файлы

Убедитесь, что в корневой папке `data/` существуют:

```text
data/
├─ config.json
├─ rules.json
├─ sec_policies.json
└─ certs/
   ├─ waf.local.pem
   └─ waf.local-key.pem
```

### 3. Запустите контейнеры

Из корня проекта:

```powershell
docker compose up --build
```

Будут подняты:
- `rust-waf` — контейнер WAF;
- `juice-shop` — backend-контейнер во внутренней сети.

### 4. Доступ к сервисам

После запуска:
- WAF: `https://waf.local/`
- Admin panel: `http://localhost:8081/admin/`

Учетные данные admin по умолчанию:

```text
username: admin
password: admin123
```

## Docker-схема сети

Используются две сети:
- `public` — внешняя сеть, в которой опубликованы порты WAF;
- `waf-internal` — приватная внутренняя сеть между WAF и `Juice Shop`.

Особенности:
- `WAF` подключен к обеим сетям;
- `Juice Shop` подключен только к `waf-internal`;
- `Juice Shop` не публикует порт на host-машину;
- backend доступен WAF по имени контейнера `http://juice-shop:3000`.

## Переменные окружения

Основные env-переменные контейнера WAF:

| Переменная | Значение по умолчанию | Назначение |
| --- | --- | --- |
| `WAF_MODE` | `active` | Режим работы WAF: `active` или `passive` |
| `TARGET_URL` | `http://juice-shop:3000` | Upstream-адрес защищаемого приложения |
| `ADMIN_PORT` | `8081` | Порт admin API и admin panel |
| `TLS_PRIVATE` | `/etc/ssl/private/waf.local-key.pem` | Путь к приватному TLS-ключу в контейнере |
| `TLS_PUBLIC` | `/etc/ssl/certs/waf.local.pem` | Путь к публичному TLS-сертификату в контейнере |
| `WAF_CONFIG_PATH` | `/app/config/config.json` | Путь к `config.json` |
| `WAF_RULES_PATH` | `/app/config/rules.json` | Путь к `rules.json` |
| `WAF_SEC_POLICIES_PATH` | `/app/config/sec_policies.json` | Путь к `sec_policies.json` |
| `WAF_DB_PATH` | `/var/lib/rust-waf/waf.db` | Путь к SQLite-базе |

## Volumes и bind mounts

В `docker-compose.yml` используются:

### Docker volume

```text
waf-db:/var/lib/rust-waf
```

Назначение:
- постоянное хранение `waf.db`.

### Bind mounts

```text
./data/config.json:/app/config/config.json
./data/rules.json:/app/config/rules.json
./data/sec_policies.json:/app/config/sec_policies.json
./data/certs/waf.local-key.pem:/etc/ssl/private/waf.local-key.pem:ro
./data/certs/waf.local.pem:/etc/ssl/certs/waf.local.pem:ro
```

Назначение:
- редактируемые конфигурации WAF снаружи контейнера;
- TLS-материалы в режиме `read-only`.

## Полезные команды

Пересобрать и поднять проект:

```powershell
docker compose up --build
```

Остановить контейнеры:

```powershell
docker compose down
```

Остановить контейнеры с удалением volume:

```powershell
docker compose down -v
```

Посмотреть логи WAF:

```powershell
docker compose logs -f waf
```

## Локальный запуск без Docker

Если нужен локальный запуск:

```powershell
cargo run
```

При таком сценарии:
- `Juice Shop` должен быть доступен отдельно;
- `data/*.json` и TLS-файлы используются из корня проекта;
- SQLite создается в `data/waf.db`.

## Дополнительная документация

См. также:
- [Documentation/architecture.md](</C:/BSU/Курсовая работа/Documentation/architecture.md:1>)
- [Documentation/api-schema.md](</C:/BSU/Курсовая работа/Documentation/api-schema.md:1>)
