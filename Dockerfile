# Dark Recon Framework v4 - Docker Image
# Multi-stage build for minimal image size

# Stage 1: Build environment
FROM ubuntu:22.04 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    git \
    build-essential \
    python3 \
    python3-pip \
    golang-go \
    jq \
    bc \
    nmap \
    dnsutils \
    whois \
    unzip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Go tools
ENV GOPATH=/go
ENV PATH=$PATH:/go/bin

RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install github.com/projectdiscovery/katana/cmd/katana@latest \
    && go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
    && go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
    && go install github.com/tomnomnom/unfurl@latest \
    && go install github.com/tomnomnom/assetfinder@latest \
    && go install github.com/tomnomnom/anew@latest \
    && go install github.com/tomnomnom/waybackurls@latest \
    && go install github.com/tomnomnom/gf@latest \
    && go install github.com/ffuf/ffuf/v2@latest \
    && go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest \
    && go install github.com/d3mondev/puredns/v2@latest

# Stage 2: Runtime environment
FROM ubuntu:22.04

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    curl \
    wget \
    git \
    python3 \
    python3-pip \
    python3-requests \
    jq \
    bc \
    nmap \
    dnsutils \
    whois \
    unzip \
    ca-certificates \
    sqlite3 \
    libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

# Copy Go tools from builder
COPY --from=builder /go/bin /usr/local/bin

# Create non-root user
RUN groupadd -r darkrecon && useradd -r -g darkrecon -d /app -s /bin/bash darkrecon

# Set up application directory
WORKDIR /app

# Copy framework files
COPY --chown=darkrecon:darkrecon . /app/

# Make scripts executable
RUN chmod +x /app/dark_recon_framework.sh /app/darkness_recon.sh /app/darkness_recon_v2.sh /app/dark_recon_framework_v2.sh 2>/dev/null || true
RUN chmod +x /app/phases/*.sh /app/core/*.sh 2>/dev/null || true

# Create necessary directories
RUN mkdir -p /app/cache /app/output /app/logs /app/config/profiles

# Set environment variables
ENV PATH="/usr/local/bin:${PATH}"
ENV GOPATH=/go
ENV DARK_RECON_HOME=/app

# Switch to non-root user
USER darkrecon

# Default entrypoint
ENTRYPOINT ["/app/dark_recon_framework.sh"]
CMD ["--help"]
