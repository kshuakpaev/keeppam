# Статика собирается на хосте: make web-build (нужен Node.js).
# Так не тянем node-образ из Docker Hub.
FROM nginx:alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY dist /usr/share/nginx/html
EXPOSE 80
