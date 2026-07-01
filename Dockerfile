# Security Audit Tool (hotdogspy) — web dashboard + CLI in one image.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app \
    DEBIAN_FRONTEND=noninteractive

# System tools the scanners rely on:
#   nmap    -> Module A (recon)
#   tshark  -> Module B (optional live capture); libpcap/tcpdump for scapy
# Preseed wireshark so tshark installs non-interactively without setuid dumpcap.
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        nmap \
        tshark \
        tcpdump \
        libpcap0.8 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first for better layer caching.
COPY requirements.txt pyproject.toml README.md ./
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy the project and install the `hotdogspy` console script (editable keeps
# file-relative paths — config/, data/, web/frontend — resolving to /app).
COPY . .
RUN pip install -e .

EXPOSE 8000

# Default: run the web dashboard. Override the command to use the CLI, e.g.
#   docker exec -it hotdogspy hotdogspy scan 93.184.216.34
CMD ["hotdogspy", "serve", "--host", "0.0.0.0", "--port", "8000"]
