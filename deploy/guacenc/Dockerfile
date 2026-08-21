FROM debian:bookworm-slim AS build

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl build-essential autoconf libtool-bin pkg-config \
    libcairo2-dev libjpeg62-turbo-dev libpng-dev libossp-uuid-dev \
    libavcodec-dev libavformat-dev libavutil-dev libswscale-dev \
    libpango1.0-dev libssh2-1-dev libtelnet-dev libvncserver-dev \
    libssl-dev libvorbis-dev libwebp-dev freerdp2-dev libpulse-dev \
    && rm -rf /var/lib/apt/lists/*

ARG GUAC_VER=1.5.5
WORKDIR /src
RUN curl -fsSL "https://archive.apache.org/dist/guacamole/${GUAC_VER}/source/guacamole-server-${GUAC_VER}.tar.gz" \
    -o guac.tar.gz \
 && tar -xzf guac.tar.gz \
 && cd guacamole-server-${GUAC_VER} \
 && ./configure --prefix=/usr/local \
 && make -C src/libguac -j"$(nproc)" \
 && make -C src/libguac install \
 && make -C src/guacenc -j"$(nproc)" \
 && make -C src/guacenc install

FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive \
    LD_LIBRARY_PATH=/usr/local/lib
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates ffmpeg python3 tesseract-ocr tesseract-ocr-eng tesseract-ocr-rus \
    libcairo2 libjpeg62-turbo libpng16-16 libossp-uuid16 \
    libavcodec59 libavformat59 libavutil57 libswscale6 \
    libpango-1.0-0 libpangocairo-1.0-0 libwebp7 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /usr/local/bin/guacenc /usr/local/bin/guacenc
COPY --from=build /usr/local/lib/ /usr/local/lib/
COPY encode_server.py /app/encode_server.py
RUN ldconfig && guacenc --help >/dev/null 2>&1 || guacenc -h >/dev/null 2>&1 || true

WORKDIR /app
EXPOSE 8099
CMD ["python3", "/app/encode_server.py"]
