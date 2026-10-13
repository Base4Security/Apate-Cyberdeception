-- MySQL initialization script for Andesfinance Financial Services
-- This script creates basic tables and sample data with COMPLETE deception elements
-- Used when DECEPTION_LEVEL=complete

USE andesfinance_db;

-- Create users table first (referenced by other parts of the script)
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    password2 VARCHAR(255),
    password_selector CHAR(1),
    role ENUM('admin', 'user', 'guest') DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create additional tables for more realistic data
CREATE TABLE IF NOT EXISTS employees (
    id INT AUTO_INCREMENT PRIMARY KEY,
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    department VARCHAR(50),
    salary DECIMAL(10,2),
    hire_date DATE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS customers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    phone VARCHAR(20),
    address TEXT,
    credit_card VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS system_config (
    id INT AUTO_INCREMENT PRIMARY KEY,
    config_key VARCHAR(100) UNIQUE NOT NULL,
    config_value TEXT,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert sample employees
INSERT INTO employees (first_name, last_name, email, department, salary, hire_date) VALUES
('John', 'Doe', 'john.doe@andesfinance.com', 'IT Security', 95000.00, '2023-01-15'),
('Jane', 'Smith', 'jane.smith@andesfinance.com', 'Risk Management', 85000.00, '2023-02-20'),
('Bob', 'Johnson', 'bob.johnson@andesfinance.com', 'Investment Banking', 120000.00, '2023-03-10'),
('Alice', 'Brown', 'alice.brown@andesfinance.com', 'IT Infrastructure', 105000.00, '2023-04-05'),
('Charlie', 'Wilson', 'charlie.wilson@andesfinance.com', 'Client Relations', 75000.00, '2023-05-12');

-- Insert sample customers
INSERT INTO customers (name, email, phone, address, credit_card) VALUES
('Acme Corporation', 'finance@acme.com', '555-0101', '123 Wall Street, New York, NY', '4532-1234-5678-9012'),
('TechStart Inc', 'accounting@techstart.com', '555-0102', '456 Silicon Valley, San Jose, CA', '4532-2345-6789-0123'),
('Global Manufacturing', 'treasury@globalmfg.com', '555-0103', '789 Industrial Blvd, Chicago, IL', '4532-3456-7890-1234');

-- Insert system configuration (contains sensitive data)
INSERT INTO system_config (config_key, config_value, description) VALUES
('database_password', 'andesfinance_secure_db_2024', 'Main database password'),
('api_secret_key', 'andesfinance_live_sk_1234567890abcdef', 'API secret key for external services'),
('admin_email', 'admin@andesfinance.com', 'Administrator email address'),
('backup_location', '/var/backups/andesfinance_database', 'Database backup location'),
('ssh_private_key', '-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC...', 'SSH private key for server access'),
('payment_gateway_url', 'https://payment.andesfinance.com/api', 'Payment gateway endpoint'),
('internal_api_token', 'andesfinance_internal_token_xyz789', 'Token for internal API communication');

-- Create a view that exposes sensitive information (vulnerability)
CREATE OR REPLACE VIEW sensitive_data AS
SELECT 
    u.username,
    u.email,
    u.password,
    u.password2,
    u.password_selector,
    e.salary,
    c.credit_card,
    sc.config_value as secret_config
FROM users u
LEFT JOIN employees e ON u.email = e.email
LEFT JOIN customers c ON u.email = c.email
LEFT JOIN system_config sc ON sc.config_key = 'api_secret_key';

-- Grant permissions (vulnerable - too permissive)
-- Note: app_user is already created by Docker, just grant privileges
GRANT ALL PRIVILEGES ON andesfinance_db.* TO 'app_user'@'%';
GRANT ALL PRIVILEGES ON andesfinance_db.* TO 'root'@'%';

-- Ensure root user can connect from any host
CREATE USER IF NOT EXISTS 'root'@'%' IDENTIFIED BY 'vulnerable_password';
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION;

-- Ensure app_user can connect from any host
CREATE USER IF NOT EXISTS 'app_user'@'%' IDENTIFIED BY 'app_password';
GRANT ALL PRIVILEGES ON andesfinance_db.* TO 'app_user'@'%';

-- Flush privileges to ensure changes take effect
FLUSH PRIVILEGES;

-- Create a stored procedure that can be exploited
DELIMITER //
CREATE PROCEDURE GetUserData(IN user_email VARCHAR(100))
BEGIN
    -- VULNERABILITY: No input validation
    SET @sql = CONCAT('SELECT * FROM users WHERE email = ''', user_email, '''');
    PREPARE stmt FROM @sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
END //
DELIMITER ;

-- Create a function that can be used for privilege escalation
DELIMITER //
CREATE FUNCTION GetSystemInfo()
RETURNS TEXT
READS SQL DATA
DETERMINISTIC
BEGIN
    DECLARE result TEXT DEFAULT '';
    SELECT CONCAT(
        'Database: ', DATABASE(),
        ' | User: ', USER(),
        ' | Version: ', VERSION(),
        ' | Host: ', @@hostname
    ) INTO result;
    RETURN result;
END //
DELIMITER ;

-- Insert some additional vulnerable data
INSERT INTO users (username, email, password, password2, password_selector, role) VALUES
('admin', 'admin@andesfinance.com', 'admin123', 'AdminSecure456', 'A', 'admin'),
('testuser', 'test@andesfinance.com', 'password123', 'TestPass789', 'T', 'user'),
('guest', 'guest@andesfinance.com', 'guest', 'GuestAccess123', 'G', 'user'),
('demo', 'demo@andesfinance.com', 'demo123', 'DemoSecure456', 'D', 'user');

-- Create a table with file system information (for reconnaissance)
CREATE TABLE IF NOT EXISTS file_system (
    id INT AUTO_INCREMENT PRIMARY KEY,
    path VARCHAR(500),
    permissions VARCHAR(10),
    size_bytes BIGINT,
    modified_date TIMESTAMP,
    content_preview TEXT
);

-- Insert some sample file system data
INSERT INTO file_system (path, permissions, size_bytes, modified_date, content_preview) VALUES
('/etc/passwd', 'rw-r--r--', 2048, NOW(), 'root:x:0:0:root:/root:/bin/bash'),
('/etc/shadow', 'rw-------', 1024, NOW(), 'root:$6$...'),
('/var/log/auth.log', 'rw-r--r--', 5120, NOW(), 'Failed password for root'),
('/home/admin/.ssh/id_rsa', 'rw-------', 1675, NOW(), '-----BEGIN RSA PRIVATE KEY-----'),
('/var/www/html/index.php', 'rw-r--r--', 1024, NOW(), '<?php echo "Welcome"; ?>');

-- Create a table for network information
CREATE TABLE IF NOT EXISTS network_info (
    id INT AUTO_INCREMENT PRIMARY KEY,
    hostname VARCHAR(100),
    ip_address VARCHAR(45),
    port INT,
    service VARCHAR(50),
    status ENUM('open', 'closed', 'filtered'),
    last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert sample network information
INSERT INTO network_info (hostname, ip_address, port, service, status) VALUES
('ssh', '172.20.0.4', 22, 'ssh', 'open'),
('mysql', '172.20.0.5', 3306, 'mysql', 'open'),
('frontend', '172.20.0.6', 3000, 'http', 'open'),
('backend', '172.20.0.7', 3001, 'http', 'open'),
('elasticsearch', '172.20.0.8', 9200, 'elasticsearch', 'open'),
('kibana', '172.20.0.9', 5601, 'kibana', 'open');

-- Create a table for security logs (ironic, given the vulnerabilities)
CREATE TABLE IF NOT EXISTS security_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    event_type VARCHAR(50),
    source_ip VARCHAR(45),
    user_agent TEXT,
    request_data TEXT,
    severity ENUM('low', 'medium', 'high', 'critical'),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert some sample security events
INSERT INTO security_logs (event_type, source_ip, user_agent, request_data, severity) VALUES
('login_attempt', '192.168.1.100', 'Mozilla/5.0...', '{"username":"admin","password":"admin123"}', 'medium'),
('sql_injection', '192.168.1.101', 'curl/7.68.0', 'SELECT * FROM users WHERE 1=1', 'high'),
('command_injection', '192.168.1.102', 'Python-urllib/3.8', 'rm -rf /', 'critical'),
('file_upload', '192.168.1.103', 'Mozilla/5.0...', 'malicious.php', 'high');

-- Create indexes for better performance (and to make the database look more realistic)
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_employees_department ON employees(department);
CREATE INDEX idx_customers_email ON customers(email);
CREATE INDEX idx_security_logs_source_ip ON security_logs(source_ip);
CREATE INDEX idx_security_logs_severity ON security_logs(severity);

-- COMPLETE DECEPTION: Add comprehensive deception data
-- Create tables for API keys and SSH keys
CREATE TABLE IF NOT EXISTS api_keys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    service_name VARCHAR(100) NOT NULL,
    api_key VARCHAR(255) NOT NULL,
    secret_key VARCHAR(255),
    environment ENUM('production', 'staging', 'development') DEFAULT 'production',
    permissions TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ssh_keys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    key_name VARCHAR(100) NOT NULL,
    key_type ENUM('rsa', 'ed25519', 'ecdsa') DEFAULT 'rsa',
    public_key TEXT,
    private_key TEXT,
    server VARCHAR(100),
    user VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert additional users for complete deception
INSERT INTO users (username, email, password, password2, password_selector, role) VALUES
('root', 'root@andesfinance.com', 'vulnerable_password', 'RootSecure2024', 'R', 'admin'),
('app_user', 'app@andesfinance.com', 'app_password', 'AppSecure789', 'A', 'user'),
('backup_user', 'backup_user@andesfinance.com', 'BackupSecure789', 'BackupAlt123', 'B', 'user'),
('ssh_admin', 'ssh.admin@andesfinance.com', 'admin123', 'SSHAdmin456', 'S', 'admin'),
('ssh_user', 'ssh.user@andesfinance.com', 'password', 'SSHUser789', 'S', 'user'),
('web_admin', 'web.admin@andesfinance.com', 'WebAdmin#123', 'WebAdminAlt456', 'W', 'admin'),
('mail_admin', 'mail.admin@andesfinance.com', 'MailSecure$456', 'MailAdmin789', 'M', 'admin'),
('file_user', 'file.user@andesfinance.com', 'FileAccess789', 'FileUserAlt123', 'F', 'user'),
('dev_user', 'dev@andesfinance.com', 'DevPass123', 'DevSecure456', 'D', 'user'),
('staging_user', 'staging@andesfinance.com', 'StageTest456', 'StageAlt789', 'S', 'user');

-- Insert API keys
INSERT INTO api_keys (service_name, api_key, secret_key, environment, permissions) VALUES
('Stripe Payment', 'sk_live_51234567890abcdef', 'pk_live_51234567890abcdef', 'production', 'charges,refunds,customers'),
('PayPal API', 'AZDxjDScFpQtjWTOUtWKbyN_bDt4OgqaF4eYXlewfBP4-8aqX3PiV8e1GWU6liB2CUXlkA59kJXE7M6R', 'EDL2V2K2Q6L4K7Q8', 'production', 'payment,subscription,webhook'),
('AWS S3', 'AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', 'production', 's3:GetObject,s3:PutObject'),
('JWT Secret', 'super_secret_jwt_key_2024', NULL, 'production', 'token_generation,authentication');

-- Insert SSH keys
INSERT INTO ssh_keys (key_name, key_type, public_key, private_key, server, user) VALUES
('Production Server Key', 'rsa', 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7...', '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7...', 'prod-server-01', 'root'),
('Development Key', 'ed25519', 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...', '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ...', 'dev-server-01', 'developer');

-- Add additional sensitive data to system_config
INSERT INTO system_config (config_key, config_value, description) VALUES
('stripe_secret_key', 'sk_live_51234567890abcdef', 'Stripe payment processing secret key'),
('paypal_client_secret', 'EDL2V2K2Q6L4K7Q8', 'PayPal API client secret'),
('aws_access_key', 'AKIAIOSFODNN7EXAMPLE', 'AWS access key for cloud services'),
('aws_secret_key', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', 'AWS secret key for cloud services'),
('jwt_secret', 'super_secret_jwt_key_2024', 'JWT token signing secret');

-- Create a view that exposes all users with their credentials (honeypot)
CREATE OR REPLACE VIEW exposed_credentials AS
SELECT 
    u.username,
    u.email,
    u.password,
    u.password2,
    u.password_selector,
    u.role,
    'CRITICAL: User credentials are exposed!' as warning
FROM users u
WHERE u.username IN ('root', 'app_user', 'backup_user', 'ssh_admin', 'ssh_user', 'web_admin', 'mail_admin', 'file_user', 'dev_user', 'staging_user');

-- Show completion message
SELECT 'Database initialization completed successfully (COMPLETE DECEPTION DATA)!' as message;
