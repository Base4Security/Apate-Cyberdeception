const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

// Import deception endpoints module
const { createDeceptionEndpoints } = require('./deception-endpoints');

const app = express();
const PORT = process.env.PORT || 3001;

// Create logs directory if it doesn't exist
const logDir = '/var/log/backend';
if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
}

// Security-focused logging function
function writeLog(level, message, data = {}) {
    const timestamp = new Date().toISOString();
    const logEntry = {
        timestamp,
        level,
        service: 'backend',
        message,
        data,
        security_indicators: detectSecurityIndicators(data),
        risk_score: calculateRiskScore(level, data),
        deception_level: process.env.DECEPTION_LEVEL || 'none'
    };
    
    const logLine = JSON.stringify(logEntry) + '\n';
    const logFile = path.join(logDir, `backend-${new Date().toISOString().split('T')[0]}.log`);
    
    fs.appendFile(logFile, logLine, (err) => {
        if (err) console.error('Error writing to log file:', err);
    });
    
    // Enhanced console logging for deception levels
    if (process.env.DECEPTION_LEVEL === 'complete' || process.env.DECEPTION_LEVEL === 'impossible') {
        console.log(`[${level.toUpperCase()}] [DECEPTION-${process.env.DECEPTION_LEVEL.toUpperCase()}] ${message}`, data);
        
        // Alert for high-risk activities
        if (logEntry.risk_score >= 7) {
            console.log(`🚨 [HIGH RISK ALERT] Risk Score: ${logEntry.risk_score} - ${message}`);
        }
    } else {
        console.log(`[${level.toUpperCase()}] ${message}`, data);
    }
}

// Detect security indicators in the data
function detectSecurityIndicators(data) {
    const indicators = [];
    
    if (data.query || data.sql) {
        const query = data.query || data.sql;
        // SQL Injection detection
        const sqlInjectionPatterns = [
            /union\s+select/i,
            /or\s+1\s*=\s*1/i,
            /'\s*or\s*'\s*=\s*'/i,
            /drop\s+table/i,
            /delete\s+from/i,
            /insert\s+into/i,
            /update\s+set/i,
            /--/,
            /\/\*/,
            /xp_cmdshell/i,
            /exec\s*\(/i,
            /script\s*>/i,
            /<script/i
        ];
        
        sqlInjectionPatterns.forEach(pattern => {
            if (pattern.test(query)) {
                indicators.push('SQL_INJECTION_ATTEMPT');
            }
        });
    }
    
    if (data.command) {
        // Command injection detection
        const dangerousCommands = [
            /rm\s+-rf/i,
            /cat\s+\/etc\/passwd/i,
            /whoami/i,
            /id/i,
            /ps\s+aux/i,
            /netstat/i,
            /wget/i,
            /curl/i,
            /nc\s+/i,
            /ncat/i,
            /python\s+-c/i,
            /perl\s+-e/i,
            /bash\s+-c/i,
            /sh\s+-c/i
        ];
        
        dangerousCommands.forEach(pattern => {
            if (pattern.test(data.command)) {
                indicators.push('DANGEROUS_COMMAND');
            }
        });
    }
    
    if (data.filename) {
        // Path traversal detection
        if (data.filename.includes('..') || data.filename.includes('/etc/') || data.filename.includes('/proc/')) {
            indicators.push('PATH_TRAVERSAL_ATTEMPT');
        }
    }
    
    return indicators;
}

// Calculate risk score based on level and data
function calculateRiskScore(level, data) {
    let score = 0;
    
    // Base score by level
    switch (level) {
        case 'error': score += 3; break;
        case 'warn': score += 2; break;
        case 'info': score += 1; break;
    }
    
    // Additional score for security indicators
    const indicators = detectSecurityIndicators(data);
    score += indicators.length * 2;
    
    // High score for critical vulnerabilities
    if (data.critical_vulnerability) score += 5;
    if (data.potential_attack) score += 4;
    if (data.command) score += 3;
    
    return Math.min(score, 10); // Cap at 10
}

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// File upload configuration (vulnerable)
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        // VULNERABILITY: No file validation
        cb(null, file.originalname);
    }
});
const upload = multer({ storage });

// Create uploads directory
if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads');
}

// Database connection
const db = mysql.createConnection({
    host: process.env.DB_HOST || 'mysql',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || 'vulnerable_password',
    database: process.env.DB_NAME || 'andesfinance_db',
    port: process.env.DB_PORT || 3306
});

// Connect to database with retry logic
const { waitForMySQL } = require('./wait-for-mysql');

waitForMySQL()
    .then(() => {
        db.connect((err) => {
            if (err) {
                writeLog('error', 'Database connection failed', { error: err.message });
                process.exit(1);
            } else {
                writeLog('info', 'Connected to MySQL database');
                initializeDatabase();
            }
        });
    })
    .catch((error) => {
        writeLog('error', 'Failed to establish MySQL connection', { error: error.message });
        process.exit(1);
    });

// Initialize database tables
function initializeDatabase() {
    const createProductsTable = `
        CREATE TABLE IF NOT EXISTS products (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            description TEXT,
            price DECIMAL(10,2),
            category VARCHAR(50),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `;
    
    const createOrdersTable = `
        CREATE TABLE IF NOT EXISTS orders (
            id INT AUTO_INCREMENT PRIMARY KEY,
            customer_name VARCHAR(100) NOT NULL,
            customer_email VARCHAR(100),
            total_amount DECIMAL(10,2),
            status ENUM('pending', 'processing', 'shipped', 'delivered') DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `;
    
    const createLogsTable = `
        CREATE TABLE IF NOT EXISTS api_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            endpoint VARCHAR(200),
            method VARCHAR(10),
            ip_address VARCHAR(45),
            user_agent TEXT,
            request_data TEXT,
            response_data TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `;
    
    db.query(createProductsTable, (err) => {
        if (err) console.error('Error creating products table:', err);
    });
    
    db.query(createOrdersTable, (err) => {
        if (err) console.error('Error creating orders table:', err);
    });
    
    db.query(createLogsTable, (err) => {
        if (err) console.error('Error creating logs table:', err);
    });
    
    // Insert sample data
    insertSampleData();
}

function insertSampleData() {
    const sampleProducts = [
        ['Investment Portfolio', 'Premium investment management service', 2500.00, 'Financial Services'],
        ['Business Loan', 'Commercial lending solution', 50000.00, 'Lending'],
        ['Credit Card', 'Elite rewards credit card', 150.00, 'Credit Products'],
        ['Insurance Policy', 'Comprehensive business insurance', 1200.00, 'Insurance']
    ];
    
    sampleProducts.forEach(product => {
        const query = 'INSERT IGNORE INTO products (name, description, price, category) VALUES (?, ?, ?, ?)';
        db.query(query, product, (err) => {
            if (err) console.error('Error inserting sample product:', err);
        });
    });
    
    // Ensure admin user exists with plain text password for demo purposes
    const insertAdmin = `
        INSERT INTO users (username, email, password, role) 
        VALUES ('admin', 'admin@andesfinance.com', 'admin123', 'admin')
        ON DUPLICATE KEY UPDATE password = 'admin123'
    `;
    db.query(insertAdmin, (err) => {
        if (err) {
            console.error('Error inserting admin user:', err);
        } else {
            console.log('Admin user created/updated with plain text password for demo purposes');
        }
    });
}

// Logging middleware (vulnerable - logs sensitive data)
function logRequest(req, res, next) {
    const logData = {
        endpoint: req.originalUrl,
        method: req.method,
        ip: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent'),
        body: req.body,
        query: req.query
    };
    
    // VULNERABILITY: Logs sensitive data in plain text
    console.log(`[API LOG] ${JSON.stringify(logData)}`);
    
    // Store in database
    const query = `
        INSERT INTO api_logs (endpoint, method, ip_address, user_agent, request_data, response_data) 
        VALUES (?, ?, ?, ?, ?, ?)
    `;
    db.query(query, [
        req.originalUrl,
        req.method,
        req.ip || req.connection.remoteAddress,
        req.get('User-Agent'),
        JSON.stringify(req.body),
        JSON.stringify({ timestamp: new Date().toISOString() })
    ], (err) => {
        if (err) console.error('Error logging request:', err);
    });
    
    next();
}

app.use(logRequest);

// Initialize deception endpoints based on DECEPTION_LEVEL
const DECEPTION_LEVEL = process.env.DECEPTION_LEVEL || 'none';

if (DECEPTION_LEVEL === 'complete' || DECEPTION_LEVEL === 'impossible') {
    console.log(`[DECEPTION] Loading deception endpoints for level: ${DECEPTION_LEVEL}`);
    
    // Add deception endpoints
    app.use('/', createDeceptionEndpoints());
    
    // Log deception endpoints activation
    writeLog('info', 'Deception endpoints activated', {
        level: DECEPTION_LEVEL,
        endpoints_count: 25,
        monitoring_enabled: true
    });
} else {
    console.log(`[DECEPTION] Deception endpoints disabled for level: ${DECEPTION_LEVEL}`);
}

// Routes

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// Get all products (vulnerable to SQL injection)
app.get('/products', (req, res) => {
    const { category, search } = req.query;
    
    let query = 'SELECT * FROM products';
    let params = [];
    
    if (category) {
        // VULNERABILITY: SQL Injection
        query += ` WHERE category = '${category}'`;
    }
    
    if (search) {
        // VULNERABILITY: SQL Injection
        query += category ? ` AND name LIKE '%${search}%'` : ` WHERE name LIKE '%${search}%'`;
    }
    
    console.log(`[PRODUCTS QUERY] ${query}`);
    
    db.query(query, (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        
        res.json(results);
    });
});

// Create product (vulnerable)
app.post('/products', (req, res) => {
    const { name, description, price, category } = req.body;
    
    // VULNERABILITY: SQL Injection
    const query = `INSERT INTO products (name, description, price, category) VALUES ('${name}', '${description}', ${price}, '${category}')`;
    
    console.log(`[CREATE PRODUCT] ${query}`);
    
    db.query(query, (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        
        res.json({ success: true, id: results.insertId });
    });
});

// Get orders (vulnerable)
app.get('/orders', (req, res) => {
    const { customer_email } = req.query;
    
    let query = 'SELECT * FROM orders';
    if (customer_email) {
        // VULNERABILITY: SQL Injection
        query += ` WHERE customer_email = '${customer_email}'`;
    }
    
    console.log(`[ORDERS QUERY] ${query}`);
    
    db.query(query, (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        
        res.json(results);
    });
});

// Create order (vulnerable)
app.post('/orders', (req, res) => {
    const { customer_name, customer_email, total_amount } = req.body;
    
    // VULNERABILITY: SQL Injection
    const query = `INSERT INTO orders (customer_name, customer_email, total_amount) VALUES ('${customer_name}', '${customer_email}', ${total_amount})`;
    
    console.log(`[CREATE ORDER] ${query}`);
    
    db.query(query, (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        
        res.json({ success: true, id: results.insertId });
    });
});

// File upload endpoint (vulnerable)
app.post('/upload', upload.single('file'), (req, res) => {
    // VULNERABILITY: No file validation, no authentication
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }
    
    console.log(`[FILE UPLOAD] ${req.file.originalname} uploaded to ${req.file.path}`);
    
    res.json({
        success: true,
        filename: req.file.filename,
        path: req.file.path,
        size: req.file.size
    });
});

// Command execution endpoint (CRITICAL VULNERABILITY)
app.post('/execute', (req, res) => {
    const { command } = req.body;
    
    const commandData = {
        command,
        ip: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent'),
        timestamp: new Date().toISOString(),
        critical_vulnerability: true,
        endpoint: '/execute'
    };
    
    writeLog('warn', 'CRITICAL: Command execution attempt', commandData);
    
    // VULNERABILITY: Command injection
    exec(command, (error, stdout, stderr) => {
        if (error) {
            writeLog('error', 'Command execution failed', {
                command,
                error: error.message,
                ip: req.ip,
                command_failed: true,
                critical_vulnerability: true
            });
            return res.json({ success: false, error: error.message });
        }
        
        writeLog('warn', 'Command executed successfully', {
            command,
            output_length: stdout ? stdout.length : 0,
            stderr_length: stderr ? stderr.length : 0,
            ip: req.ip,
            command_success: true,
            potential_attack: true,
            critical_vulnerability: true
        });
        
        res.json({
            success: true,
            output: stdout,
            error: stderr
        });
    });
});

// Database query endpoint (vulnerable)
app.post('/query', (req, res) => {
    const { sql } = req.body;
    
    const queryData = {
        sql,
        ip: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent'),
        timestamp: new Date().toISOString(),
        critical_vulnerability: true,
        endpoint: '/query'
    };
    
    writeLog('warn', 'CRITICAL: Direct SQL execution attempt', queryData);
    
    // VULNERABILITY: Direct SQL execution
    db.query(sql, (err, results) => {
        if (err) {
            writeLog('error', 'SQL execution failed', {
                sql,
                error: err.message,
                ip: req.ip,
                sql_error: true,
                critical_vulnerability: true
            });
            return res.status(500).json({ error: err.message });
        }
        
        writeLog('warn', 'SQL executed successfully', {
            sql,
            results_count: results ? results.length : 0,
            ip: req.ip,
            sql_success: true,
            potential_attack: true,
            critical_vulnerability: true
        });
        
        res.json({ success: true, results });
    });
});

// System information endpoint
app.get('/system', (req, res) => {
    // VULNERABILITY: Exposes system information
    const systemInfo = {
        platform: process.platform,
        nodeVersion: process.version,
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        environment: process.env.NODE_ENV || 'development',
        database: {
            host: process.env.DB_HOST || 'mysql',
            user: process.env.DB_USER || 'root',
            database: process.env.DB_NAME || 'andesfinance_db'
        },
        files: fs.readdirSync('.'),
        processes: 'Use /execute endpoint to run ps aux'
    };
    
    res.json(systemInfo);
});

// Network scan endpoint
app.get('/scan', (req, res) => {
    const { target, ports } = req.query;
    
    if (!target) {
        return res.json({ error: 'Target parameter required' });
    }
    
    const portList = ports || '22,23,80,443,3306,22,2223';
    
    // VULNERABILITY: Allows network scanning
    exec(`nmap -p ${portList} ${target}`, (error, stdout, stderr) => {
        res.json({
            target,
            ports: portList,
            success: !error,
            output: stdout,
            error: stderr
        });
    });
});

// Get API logs (vulnerable - no authentication)
app.get('/logs', (req, res) => {
    const { limit = 100 } = req.query;
    
    // VULNERABILITY: No authentication, exposes all logs
    const query = `SELECT * FROM api_logs ORDER BY created_at DESC LIMIT ${limit}`;
    
    db.query(query, (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        
        res.json(results);
    });
});

// Download file endpoint (vulnerable)
app.get('/download/:filename', (req, res) => {
    const filename = req.params.filename;
    
    // VULNERABILITY: Path traversal possible
    const filePath = path.join(__dirname, 'uploads', filename);
    
    if (fs.existsSync(filePath)) {
        res.download(filePath);
    } else {
        res.status(404).json({ error: 'File not found' });
    }
});

// API Routes for Frontend Integration

// User login endpoint
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    // VULNERABILITY: SQL Injection - no parameterized queries
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    
    console.log(`[LOGIN ATTEMPT] Username: ${username}, Query: ${query}`);
    
    db.query(query, (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        
        if (results.length > 0) {
            const user = results[0];
            const token = jwt.sign(
                { id: user.id, username: user.username, role: user.role },
                'vulnerable_secret_key', // VULNERABILITY: Weak JWT secret
                { expiresIn: '24h' }
            );
            
            res.json({
                success: true,
                token,
                user: { id: user.id, username: user.username, role: user.role }
            });
        } else {
            res.json({ success: false, message: 'Invalid credentials' });
        }
    });
});

// User registration endpoint
app.post('/api/register', (req, res) => {
    const { username, email, password } = req.body;
    
    // VULNERABILITY: SQL Injection
    const query = `INSERT INTO users (username, email, password) VALUES ('${username}', '${email}', '${password}')`;
    
    console.log(`[REGISTER ATTEMPT] Username: ${username}, Email: ${email}, Query: ${query}`);
    
    db.query(query, (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        
        res.json({ success: true, message: 'User registered successfully' });
    });
});

// Get all users endpoint
app.get('/api/users', (req, res) => {
    // VULNERABILITY: No authentication required
    const query = 'SELECT id, username, email, role, created_at FROM users';
    
    db.query(query, (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        
        res.json(results);
    });
});

// Command execution endpoint
app.post('/api/execute', (req, res) => {
    const { command } = req.body;
    
    console.log(`[COMMAND EXECUTION] Command: ${command}`);
    
    // VULNERABILITY: Command injection - no input validation
    exec(command, (error, stdout, stderr) => {
        if (error) {
            console.error('Command execution failed:', error);
            return res.json({ success: false, error: error.message });
        }
        
        res.json({
            success: true,
            output: stdout,
            error: stderr
        });
    });
});

// Database query endpoint
app.post('/api/query', (req, res) => {
    const { sql } = req.body;
    
    console.log(`[SQL QUERY] Query: ${sql}`);
    
    // VULNERABILITY: Direct SQL execution
    db.query(sql, (err, results) => {
        if (err) {
            console.error('SQL error:', err);
            return res.status(500).json({ error: err.message });
        }
        
        res.json({ success: true, results });
    });
});

// System information endpoint
app.get('/api/system', (req, res) => {
    // VULNERABILITY: Exposes system information
    const systemInfo = {
        platform: process.platform,
        nodeVersion: process.version,
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        environment: process.env.NODE_ENV || 'development',
        database: {
            host: process.env.DB_HOST || 'mysql',
            user: process.env.DB_USER || 'root',
            database: process.env.DB_NAME || 'andesfinance_db'
        }
    };
    
    res.json(systemInfo);
});

// Network scan endpoint
app.get('/api/network', (req, res) => {
    const { target } = req.query;
    
    if (!target) {
        return res.json({ error: 'Target parameter required' });
    }
    
    // VULNERABILITY: Allows network scanning
    exec(`ping -c 1 ${target}`, (error, stdout, stderr) => {
        res.json({
            target,
            success: !error,
            output: stdout,
            error: stderr
        });
    });
});

// API Routes for Frontend Integration

// User login endpoint
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    // VULNERABILITY: SQL Injection - no parameterized queries
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    
    console.log(`[LOGIN ATTEMPT] Username: ${username}, Query: ${query}`);
    
    db.query(query, (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        
        if (results.length > 0) {
            const user = results[0];
            const token = jwt.sign(
                { id: user.id, username: user.username, role: user.role },
                'vulnerable_secret_key', // VULNERABILITY: Weak JWT secret
                { expiresIn: '24h' }
            );
            
            res.json({
                success: true,
                token,
                user: { id: user.id, username: user.username, role: user.role }
            });
        } else {
            res.json({ success: false, message: 'Invalid credentials' });
        }
    });
});

// User registration endpoint
app.post('/api/register', (req, res) => {
    const { username, email, password } = req.body;
    
    // VULNERABILITY: SQL Injection
    const query = `INSERT INTO users (username, email, password) VALUES ('${username}', '${email}', '${password}')`;
    
    console.log(`[REGISTER ATTEMPT] Username: ${username}, Email: ${email}, Query: ${query}`);
    
    db.query(query, (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        
        res.json({ success: true, message: 'User registered successfully' });
    });
});

// Get all users endpoint
app.get('/api/users', (req, res) => {
    // VULNERABILITY: No authentication required
    const query = 'SELECT id, username, email, role, created_at FROM users';
    
    db.query(query, (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        
        res.json(results);
    });
});

// Command execution endpoint
app.post('/api/execute', (req, res) => {
    const { command } = req.body;
    
    console.log(`[COMMAND EXECUTION] Command: ${command}`);
    
    // VULNERABILITY: Command injection - no input validation
    exec(command, (error, stdout, stderr) => {
        if (error) {
            console.error('Command execution failed:', error);
            return res.json({ success: false, error: error.message });
        }
        
        res.json({
            success: true,
            output: stdout,
            error: stderr
        });
    });
});

// Database query endpoint
app.post('/api/query', (req, res) => {
    const { sql } = req.body;
    
    console.log(`[SQL QUERY] Query: ${sql}`);
    
    // VULNERABILITY: Direct SQL execution
    db.query(sql, (err, results) => {
        if (err) {
            console.error('SQL error:', err);
            return res.status(500).json({ error: err.message });
        }
        
        res.json({ success: true, results });
    });
});

// System information endpoint
app.get('/api/system', (req, res) => {
    // VULNERABILITY: Exposes system information
    const systemInfo = {
        platform: process.platform,
        nodeVersion: process.version,
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        environment: process.env.NODE_ENV || 'development',
        database: {
            host: process.env.DB_HOST || 'mysql',
            user: process.env.DB_USER || 'root',
            database: process.env.DB_NAME || 'andesfinance_db'
        }
    };
    
    res.json(systemInfo);
});

// Network scan endpoint
app.get('/api/network', (req, res) => {
    const { target } = req.query;
    
    if (!target) {
        return res.json({ error: 'Target parameter required' });
    }
    
    // VULNERABILITY: Allows network scanning
    exec(`ping -c 1 ${target}`, (error, stdout, stderr) => {
        res.json({
            target,
            success: !error,
            output: stdout,
            error: stderr
        });
    });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
    writeLog('info', 'Andesfinance Backend API Server started', { port: PORT });
    console.log(`Andesfinance Backend API Server running on port ${PORT}`);
    console.log('Andesfinance Financial Services - Internal API System');
    
    // Display available endpoints based on deception level
    if (DECEPTION_LEVEL === 'complete' || DECEPTION_LEVEL === 'impossible') {
        console.log('\n🎯 [JUICY TARGETS ACTIVE]');
        console.log('Monitoring access to high-value endpoints:');
        console.log('  Multi-path: /admin/backup, /admin/execute, /internal/config, /internal/secrets');
        console.log('  Single-path: /admin, /root, /config, /backup, /database, /shell');
        console.log('  Single-path: /debug, /test, /upload, /files, /logs, /system, /execute');
        console.log(`\n📊 Deception Level: ${DECEPTION_LEVEL.toUpperCase()}`);
        console.log('🎯 Only access attempts to juicy targets will be logged');
    } else {
        console.log(`\n📊 Deception Level: ${DECEPTION_LEVEL.toUpperCase()} - Juicy targets disabled`);
    }
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('Shutting down Andesfinance backend server...');
    db.end();
    process.exit(0);
});
