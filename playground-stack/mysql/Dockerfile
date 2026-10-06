FROM mysql:8.0

# Set environment variables
ENV MYSQL_ROOT_PASSWORD=vulnerable_password
ENV MYSQL_DATABASE=andesfinance_db
ENV MYSQL_USER=app_user
ENV MYSQL_PASSWORD=app_password

# Copy all init files
COPY init.sql /tmp/init-none.sql
COPY init-basic.sql /tmp/init-basic.sql
COPY init-complete.sql /tmp/init-complete.sql
COPY init-impossible.sql /tmp/init-impossible.sql

# Copy the selection script
COPY select-init.sh /usr/local/bin/select-init.sh
RUN chmod +x /usr/local/bin/select-init.sh

# Ensure the script uses bash explicitly
RUN sed -i '1s|^#!/bin/bash|#!/bin/bash|' /usr/local/bin/select-init.sh

# Set the custom entrypoint
ENTRYPOINT ["/bin/bash", "/usr/local/bin/select-init.sh"]
CMD ["mysqld"]
