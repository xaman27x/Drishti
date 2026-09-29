FROM golang:1.24.8-bookworm AS build
ARG MINIO_RELEASE=RELEASE.2025-10-15T17-29-55Z
WORKDIR /src
RUN git clone --depth 1 --branch "${MINIO_RELEASE}" https://github.com/minio/minio.git . \
    && CGO_ENABLED=0 go build -trimpath -o /minio .

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /minio /usr/local/bin/minio
EXPOSE 9000 9001
ENTRYPOINT ["minio"]
