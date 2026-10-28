FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive

# Install essential pentesting utilities & Python runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    nmap \
    nikto \
    whatweb \
    sqlmap \
    uniscan \
    curl \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency specifications
COPY requirements.txt requirements-dev.txt /app/
RUN python3 -m pip install --break-system-packages -r requirements-dev.txt

# Copy source tree
COPY . /app

# Install CLI wrapper
RUN python3 -m pip install --break-system-packages -e .

ENTRYPOINT ["python3", "-m", "vapt_framework.cli"]
CMD ["info"]
