# Linux builder for SignTools: SignTools-Builder (built from this repository)
# + linux/sign.py, which signs with rcodesign (apple-codesign) instead of macOS codesign.
#
#   docker build -f linux/Dockerfile -t signtools-builder-linux .     (from the repository root)

FROM golang:1.26-bookworm AS gobuild
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -buildvcs=false -o /SignTools-Builder

FROM python:3.12-slim-bookworm
ARG RCODESIGN_VERSION=0.29.0

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl unzip zip binutils openssl nodejs npm \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir "cryptography>=42" "lief>=0.16"

RUN set -eux; \
    arch="$(uname -m)"; \
    case "$arch" in x86_64|aarch64) ;; *) echo "unsupported arch $arch"; exit 1;; esac; \
    curl -fsSL "https://github.com/indygreg/apple-platform-rs/releases/download/apple-codesign%2F${RCODESIGN_VERSION}/apple-codesign-${RCODESIGN_VERSION}-${arch}-unknown-linux-musl.tar.gz" \
      | tar -xz -C /tmp; \
    install -m 0755 /tmp/apple-codesign-*/rcodesign /usr/local/bin/rcodesign; \
    rm -rf /tmp/apple-codesign-*; \
    rcodesign --version

COPY --from=gobuild /SignTools-Builder /usr/local/bin/SignTools-Builder

# "signing files": copied into a fresh job dir under /work for every job by SignTools-Builder
COPY linux/sign.py /signfiles/sign.py
COPY linux/node-utils /signfiles/node-utils
COPY linux/libsubstrate /signfiles/libsubstrate
RUN chmod +x /signfiles/sign.py \
 && cd /signfiles/node-utils && npm ci --omit=dev --no-audit --no-fund

# Jobs are extracted and re-packed in the working dir: it needs room for ~2x your largest IPA.
# docker-compose.yml sets it to /data/work, inside the volume shared with the service.
WORKDIR /work
EXPOSE 8090
# BUILDER_KEY: shared secret, must match builder.selfhosted.key in the service's signer-cfg.yml
ENV BUILDER_KEY="" BUILDER_TIMEOUT_MINS=60
ENTRYPOINT ["/bin/sh", "-c", "exec SignTools-Builder -key \"$BUILDER_KEY\" -files /signfiles -timeout \"$BUILDER_TIMEOUT_MINS\" \"$@\"", "--"]
