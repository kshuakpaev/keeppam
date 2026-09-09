FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        xvfb \
        x11vnc \
        x11-utils \
        xrdp \
        freerdp2-x11 \
        ca-certificates \
        fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /etc/xrdp/startwm.sh \
    && xrdp-keygen xrdp auto >/dev/null 2>&1 || true
COPY xrdp.ini /etc/xrdp/xrdp.ini
COPY start.sh /start.sh
RUN chmod +x /start.sh
EXPOSE 3389 5900
CMD ["/start.sh"]
