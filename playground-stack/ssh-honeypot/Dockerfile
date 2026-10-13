FROM ubuntu:20.04

# Set timezone to avoid interactive prompt
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Install SSH server and monitoring tools
RUN apt-get update && apt-get install -y \
    openssh-server \
    openssh-client \
    python3 \
    python3-pip \
    dnsutils \
    curl \
    vim \
    nano \
    tzdata \
    net-tools \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip3 install --no-cache-dir paramiko requests

# Create app directory
WORKDIR /app

# Copy SSH honeypot monitoring script
COPY ssh_honeypot.py .
COPY startup.sh .

# Make startup script executable
RUN chmod +x startup.sh

# Create logs directory
RUN mkdir -p /app/logs

# Configure SSH server
RUN ssh-keygen -A

# Create users and set passwords (ignore if users already exist)
RUN (useradd -m -s /bin/bash admin || true) && \
    (useradd -m -s /bin/bash user || true) && \
    (useradd -m -s /bin/bash maria || true) && \
    (useradd -m -s /bin/bash juan || true) && \
    (useradd -m -s /bin/bash pedro || true) && \
    (useradd -m -s /bin/bash backup || true) && \
    echo 'root:toor' | chpasswd && \
    echo 'admin:admin123' | chpasswd && \
    echo 'user:user123' | chpasswd && \
    echo 'maria:maria123' | chpasswd && \
    echo 'juan:juan123' | chpasswd && \
    echo 'pedro:pedro123' | chpasswd && \
    echo 'backup:backup123' | chpasswd

# Configure SSH server settings
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
RUN sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
RUN sed -i 's/#LogLevel INFO/LogLevel VERBOSE/' /etc/ssh/sshd_config
RUN sed -i 's/#SyslogFacility AUTH/SyslogFacility AUTH/' /etc/ssh/sshd_config

# Create monitoring script
RUN echo '#!/bin/bash' > /monitor.sh && \
    echo 'tail -f /var/log/auth.log | python3 /app/ssh_honeypot.py' >> /monitor.sh && \
    chmod +x /monitor.sh

# Expose SSH port
EXPOSE 22

# Run the startup script
CMD ["./startup.sh"]
