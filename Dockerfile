# Build the Go API.
FROM golang:1.26-bookworm AS builder
WORKDIR /app
COPY hsmservice/ ./
RUN go mod tidy \
    && go build -o /usr/local/bin/hsm-api .

# Single image: SoftHSM2 (PKCS#11) + the HTTP API.
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# softhsm2              -> PKCS#11 library (libsofthsm2.so) + softhsm2-util
# opensc                -> pkcs11-tool (management/testing)
# openssl + engine      -> CLI signing via OpenSSL PKCS#11 engine
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        softhsm2 \
        opensc \
        openssl \
        libengine-pkcs11-openssl \
    && rm -rf /var/lib/apt/lists/*

# Run as an unprivileged user; uid 1000 keeps bind mounts simple.
# (The softhsm2 package already creates a 'softhsm' system user, so we use a
# distinct name to avoid a useradd/groupadd collision.)
RUN useradd --create-home --uid 1000 --shell /bin/sh hsm

# Token store directory (persisted via a volume).
RUN mkdir -p /home/hsm/tokens \
    && chown -R hsm:hsm /home/hsm/tokens

COPY softhsm2.conf /etc/softhsm/softhsm2.conf
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY --from=builder /usr/local/bin/hsm-api /usr/local/bin/hsm-api

# Normalize line endings (Windows CRLF -> LF) and fix permissions so the
# unprivileged user can read the config and run the binaries.
RUN sed -i 's/\r$//' /usr/local/bin/entrypoint.sh /etc/softhsm/softhsm2.conf \
    && chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/hsm-api \
    && chmod 0755 /etc/softhsm \
    && chmod 0644 /etc/softhsm/softhsm2.conf

ENV SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf
ENV PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so
ENV PORT=8080

USER hsm
EXPOSE 8080

# Initialize the token on first run, then start the HTTP API.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["/usr/local/bin/hsm-api"]
