# KeepPAM

On-prem Privileged Access Management platform.

## Quick start

```bash
make up
# UI:  http://localhost:5173
# API: http://localhost:8080
# SSH: localhost:2222
# bootstrap admin / ChangeMeNow!1
```

Фронтенд и API собираются на хосте (`npm` / `go`), Docker только запускает контейнеры. Это не требует доступа к Docker Hub для `node`/`golang` образов (актуально при проблемах с IPv6).

Первый запуск API-образа `deploy-api:latest` нужен при наличии сети; дальше `make up` обновляет бинарник через volume.

### SSH gateway

```bash
ssh -p 2222 admin@localhost
# password или ключ → TOTP (если включён) → меню целей

ssh -i ~/.ssh/id_ed25519 -p 2222 admin@localhost -t 'myhost/root'
ssh -A -p 2222 admin@localhost   # agent forwarding на цель
```

Публичные ключи: Пользователи → редактирование → «SSH-ключи».  
Host key цели (TOFU): Активы → карточка актива → fingerprint / сброс.

Классический SSH слушает **session-worker** (`KEEPPAM_MODE=ssh`); API — только HTTP (`KEEPPAM_MODE=api`).

Нужны: право `sessions.connect`, завершённый MFA setup в UI, ACL на актив (admin обходит ACL).

Smoke test against running API:

```bash
make smoke
```

## Layout

- `services/auth` — Go identity/auth API (`KEEPPAM_MODE=api`) + SSH session-worker (`KEEPPAM_MODE=ssh`)
- `web` — React admin UI (SSH terminal + RDP/VNC desktop via Guacamole)
- `deploy/docker-compose.yml` — api, session-worker :2222, guacd, web, postgres, redis
- `docs/` — architecture notes (`prod-infra.txt` — mTLS / S3 / data-key provider)

### RDP / VNC

Актив с протоколом `rdp` (порт 3389) или `vnc` (5900) → кнопка на карточке актива → HTML5 desktop через `guacd`.

Нужны: `guacd` в compose, ACL/`sessions.connect`, учётка с паролем.