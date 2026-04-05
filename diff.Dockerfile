FROM alpine:edge
RUN echo https://dl-cdn.alpinelinux.org/alpine/edge/testing >> /etc/apk/repositories
RUN adduser -D reprodiffer
RUN apk add \
  android-tools \
  cpio \
  dtc \
  e2fsprogs-extra \
  file \
  jadx \
  lz4 \
  py3-elftools \
  wabt \
  xxd \
  --no-cache

COPY ./diff.py /usr/local/bin

WORKDIR /work

USER reprodiffer
