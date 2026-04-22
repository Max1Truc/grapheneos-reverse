FROM alpine:edge
RUN echo https://dl-cdn.alpinelinux.org/alpine/edge/testing >> /etc/apk/repositories
RUN adduser -D reprodiffer
RUN apk add \
  android-tools \
  apktool \
  cpio \
  dtc \
  e2fsprogs-extra \
  file \
  lz4 \
  py3-elftools \
  wabt \
  xxd \
  --no-cache

COPY ./scripts/diff.py /usr/local/bin

WORKDIR /work

USER reprodiffer
