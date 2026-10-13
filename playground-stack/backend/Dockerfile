FROM node:18-alpine

# Install system dependencies
RUN apk add --no-cache nmap

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy application files
COPY . .

# Create uploads directory
RUN mkdir -p /app/uploads
RUN mkdir -p /var/log/backend

# Expose port
EXPOSE 3001

# Set environment variables
ENV NODE_ENV=production
ENV DB_HOST=mysql
ENV DB_USER=root
ENV DB_PASSWORD=vulnerable_password
ENV DB_NAME=vulnerable_app

# Start the application
CMD ["npm", "start"]
