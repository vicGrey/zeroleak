FROM python:3.11-slim

# Install system dependencies:
# - curl & tar for fetching Conftest
# - libcairo2, libpango, libgdk-pixbuf for WeasyPrint PDF report generation
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    tar \
    ca-certificates \
    libcairo2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    shared-mime-info \
    fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

# Install Conftest binary (pinned stable release, multi-arch support for x86_64 and arm64/Apple Silicon)
ENV CONFTEST_VERSION="0.56.0"
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then CONFTEST_ARCH="x86_64"; \
    elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then CONFTEST_ARCH="arm64"; \
    else CONFTEST_ARCH="x86_64"; fi && \
    curl -sSL "https://github.com/open-policy-agent/conftest/releases/download/v${CONFTEST_VERSION}/conftest_${CONFTEST_VERSION}_Linux_${CONFTEST_ARCH}.tar.gz" | tar -xz -C /tmp \
    && mv /tmp/conftest /usr/local/bin/conftest \
    && chmod +x /usr/local/bin/conftest \
    && rm -rf /tmp/*

WORKDIR /app

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .

# Expose Streamlit port
EXPOSE 8501

HEALTHCHECK CMD curl --fail http://localhost:8501/_stcore/health || exit 1

ENTRYPOINT ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
