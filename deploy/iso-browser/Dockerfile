FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        chromium \
        xvfb \
        x11vnc \
        x11-utils \
        fonts-liberation \
        fonts-dejavu-core \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY start.sh /start.sh
RUN chmod +x /start.sh
EXPOSE 5900
ENV START_URL=about:blank
CMD ["/start.sh"]
