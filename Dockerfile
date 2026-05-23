# ─────────────────────────────────────────────────────────────────────────
# Stiglitz — containerized recon & adaptive scanning pipeline
#
# Ships the core scan path (recon + adaptive Nuclei + TLS + JS analysis +
# report/SARIF). Heavy/optional engines — OWASP ZAP, Metasploit, sqlmap,
# hydra — are intentionally NOT bundled to keep the image lean; the scripts
# detect missing tools and skip those phases gracefully.
#
#   docker build -t stiglitz .
#   docker run --rm -v "$PWD/output:/scans" stiglitz https://target.com
# ─────────────────────────────────────────────────────────────────────────

# ── Stage 1: build the ProjectDiscovery / Go tooling ─────────────────────
FROM golang:1.24-bookworm AS gobuild
ENV GOBIN=/out CGO_ENABLED=0 GOTOOLCHAIN=auto
RUN mkdir -p /out && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/ffuf/ffuf/v2@latest && \
    go install -v github.com/hahwul/dalfox/v2@latest

# ── Stage 2: lean runtime ────────────────────────────────────────────────
FROM debian:bookworm-slim

LABEL org.opencontainers.image.title="Stiglitz" \
      org.opencontainers.image.description="All-in-one offensive security pipeline" \
      org.opencontainers.image.source="https://github.com/trickMeister1337/Stiglitz" \
      org.opencontainers.image.licenses="MIT"

ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/usr/local/bin:/opt/testssl.sh:${PATH}" \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip \
        nmap jq curl git ca-certificates dnsutils openssl bsdmainutils procps \
    && rm -rf /var/lib/apt/lists/*

# ProjectDiscovery / Go binaries from the build stage
COPY --from=gobuild /out/ /usr/local/bin/

# testssl.sh (TLS phase)
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh

# Python deps (report generator + probes use stdlib; requests/wafw00f optional helpers)
COPY requirements-dev.txt /tmp/requirements-dev.txt
RUN pip3 install --no-cache-dir --break-system-packages requests wafw00f && \
    pip3 install --no-cache-dir --break-system-packages -r /tmp/requirements-dev.txt

# Nuclei templates (best-effort; image still works offline without an update).
# Seed the daily-cache marker so the first in-container scan reuses these.
RUN nuclei -update-templates 2>/dev/null || true; \
    mkdir -p /root/.cache/stiglitz && touch /root/.cache/stiglitz/nuclei_templates_updated

# Project files (kept tiny via .dockerignore)
COPY . /opt/stiglitz
WORKDIR /scans

ENTRYPOINT ["/opt/stiglitz/stiglitz.sh"]
CMD ["--help"]
