FROM docker.elastic.co/beats/filebeat:8.11.0

# Copy the configuration file with proper permissions
COPY filebeat.yml /usr/share/filebeat/filebeat.yml

# Set proper permissions for the config file
RUN chmod 644 /usr/share/filebeat/filebeat.yml && \
    chown root:root /usr/share/filebeat/filebeat.yml

# Create log directory
RUN mkdir -p /var/log/filebeat && \
    chown root:root /var/log/filebeat

# Set the working directory
WORKDIR /usr/share/filebeat

# Use the filebeat user
USER root

# Start filebeat
CMD ["filebeat", "-e", "-c", "filebeat.yml"]
