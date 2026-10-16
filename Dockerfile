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
    && rm -rf /var/lib/apt/lists/*

# Install Conftest binary (pinned stable release)
ENV CONFTEST_VERSION="0.56.0"
RUN curl -sSL "https://github.com/open-policy-agent/conftest/releases/download/v${CONFTEST_VERSION}/conftest_${CONFTEST_VERSION}_Linux_x86_64.tar.gz" | tar -xz -C /tmp \
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
