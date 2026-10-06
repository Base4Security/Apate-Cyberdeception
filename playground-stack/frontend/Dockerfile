FROM node:18-alpine

# Install SSH client, bash, and other utilities
RUN apk add --no-cache \
    openssh-client \
    bash \
    curl \
    vim \
    nano \
    sshpass \
    inotify-tools \
    procps \
    && rm -rf /var/cache/apk/*

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy application files
COPY . .

# Create logs directory
RUN mkdir -p /app/logs
RUN mkdir -p /var/log/frontend

# Copy and setup APT monitoring script
COPY apk-monitor.sh /usr/local/bin/apk-monitor.sh
COPY start-with-monitor.sh /usr/local/bin/start-with-monitor.sh
RUN chmod +x /usr/local/bin/apk-monitor.sh
RUN chmod +x /usr/local/bin/start-with-monitor.sh

# Copy and setup cat interceptor for impossible deception level
COPY cat-interceptor.sh /usr/local/bin/cat-interceptor.sh
COPY setup-deception.sh /usr/local/bin/setup-deception.sh
RUN chmod +x /usr/local/bin/cat-interceptor.sh
RUN chmod +x /usr/local/bin/setup-deception.sh

# Expose port
EXPOSE 3000

# Set environment variables
ENV NODE_ENV=production
ENV DB_HOST=mysql
ENV DB_USER=root
ENV DB_PASSWORD=vulnerable_password
ENV DB_NAME=vulnerable_app

# Start the application with monitoring
CMD ["/usr/local/bin/start-with-monitor.sh"]
