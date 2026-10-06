FROM ubuntu:22.04

# Install necessary tools for penetration testing and network analysis
# Split into multiple install commands for better reliability

# Install basic networking tools
RUN apt-get update && apt-get install -y \
    openssh-client \
    curl \
    wget \
    netcat-openbsd \
    telnet \
    net-tools \
    iputils-ping \
    traceroute \
    && rm -rf /var/lib/apt/lists/*

# Install penetration testing tools
RUN apt-get update && apt-get install -y \
    nmap \
    hydra \
    medusa \
    john \
    hashcat \
    && rm -rf /var/lib/apt/lists/*

# Install Python and development tools
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    vim \
    nano \
    htop \
    && rm -rf /var/lib/apt/lists/*

# Install network analysis tools
RUN apt-get update && apt-get install -y tcpdump && rm -rf /var/lib/apt/lists/*
# RUN apt-get update && apt-get install -y wireshark-common && rm -rf /var/lib/apt/lists/*
# RUN apt-get update && apt-get install -y tshark && rm -rf /var/lib/apt/lists/*

# Install MySQL client tools
RUN apt-get update && apt-get install -y \
    mysql-client \
    default-mysql-client \
    && rm -rf /var/lib/apt/lists/*

# Install additional Python tools
RUN pip3 install \
    paramiko \
    scapy \
    requests \
    beautifulsoup4

# Create a working directory
WORKDIR /app

# Copy attack scripts
COPY attack_scripts/ /app/attack_scripts/
COPY requirements.txt /app/

# Make scripts executable
RUN chmod +x /app/attack_scripts/*.py

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Default command
CMD ["/bin/bash"]
