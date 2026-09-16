KeepPAM — патч host-порта API 8080 → 8008
==========================================

На сервере :8080 уже занят чужим сервисом. KeepPAM внутри Docker
по-прежнему слушает :8080 (web nginx → api:8080). На хост публикуется 8008.

Применение на уже распакованном бандле (keeppam-1.0.8-offline-core и т.п.):

  cd /path/to/keeppam-1.0.8-offline-core
  chmod +x deploy/patches/api-host-8008/apply.sh
  ./deploy/patches/api-host-8008/apply.sh

Другой порт:

  PORT=8008 ./deploy/patches/api-host-8008/apply.sh

Если каталога patches нет в старом архиве — скопируйте эту папку
в deploy/patches/api-host-8008/ на сервер и запустите apply.sh из корня бандла.

После патча:

  Портал  http://<host>:5173     (без изменений)
  API     http://<host>:8008     (вместо :8080)

Если :5173 connection refused — compose оборвался на :8080, контейнер web
создан, но не запущен. Из каталога бандла (не из папки патча):

  cd /path/to/keeppam-1.0.8-offline-core/deploy
  docker compose --env-file .env up -d --no-build
  docker compose ps
  curl -I http://127.0.0.1:5173
  curl -sf http://127.0.0.1:8008/readyz

Новые установки: в deploy/.env строка

  KEEPPAM_API_HOST_PORT=8008

затем ./install.sh (compose подставляет порт сам).
