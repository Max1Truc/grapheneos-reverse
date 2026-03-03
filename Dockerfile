FROM alpine:edge
RUN echo https://dl-cdn.alpinelinux.org/alpine/edge/testing >> /etc/apk/repositories
RUN apk add \
  android-tools \
  cpio \
  dtc \
  e2fsprogs-extra \
  file \
  jadx \
  lz4 \
  wabt \
  xxd \
  --no-cache
