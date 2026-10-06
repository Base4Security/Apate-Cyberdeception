const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const { exec } = require('child_process');
const fs = require('fs');
const fetch = require('node-fetch');

const app = express();
const PORT = process.env.PORT || 3000;

// Create logs directory if it doesn't exist
const logDir = '/var/log/frontend';
if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
}

// Security-focused logging function
function writeLog(level, message, data = {}) {
    const timestamp = new Date().toISOString();
    const logEntry = {
        timestamp,
        level,
        service: 'frontend',
        message,
        data,
        security_indicators: detectSecurityIndicators(data),
        risk_score: calculateRiskScore(level, data)
    };
    
    const logLine = JSON.stringify(logEntry) + '\n';
    const logFile = path.join(logDir, `frontend-${new Date().toISOString().split('T')[0]}.log`);
    
    fs.appendFile(logFile, logLine, (err) => {
        if (err) console.error('Error writing to log file:', err);
    });
    
    // Also log to console for development
    console.log(`[${level.toUpperCase()}] ${message}`, data);
}

// Detect security indicators in the data
function detectSecurityIndicators(data) {
    const indicators = [];
    
    if (data.query) {
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
            if (pattern.test(data.query)) {
                indicators.push('SQL_INJECTION_ATTEMPT');
            }
        });
    }
    
    
    if (data.username) {
        // Suspicious username patterns
        const suspiciousUsernames = [
            /admin/i,
            /root/i,
            /administrator/i,
            /test/i,
            /guest/i,
            /user/i,
            /'or'1'='1/i,
            /admin'--/i
        ];
        
        suspiciousUsernames.forEach(pattern => {
            if (pattern.test(data.username)) {
                indicators.push('SUSPICIOUS_USERNAME');
            }
        });
    }
    
    if (data.ip) {
        // Check for suspicious IP patterns (internal, localhost, etc.)
        if (data.ip === '127.0.0.1' || data.ip === '::1' || data.ip.startsWith('192.168.') || data.ip.startsWith('10.')) {
            indicators.push('INTERNAL_IP_ACCESS');
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
    
    // High score for SQL injection attempts
    if (data.query && /union\s+select|or\s+1\s*=\s*1|'\s*or\s*'\s*=\s*'/i.test(data.query)) {
        score += 5;
    }
    
    return Math.min(score, 10); // Cap at 10
}

// Security middleware for enhanced logging
app.use((req, res, next) => {
    const securityData = {
        ip: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent'),
        referer: req.get('Referer'),
        method: req.method,
        url: req.originalUrl,
        headers: {
            'x-forwarded-for': req.get('X-Forwarded-For'),
            'x-real-ip': req.get('X-Real-IP'),
            'x-forwarded-proto': req.get('X-Forwarded-Proto')
        },
        body: req.method !== 'GET' ? req.body : null,
        query: req.query,
        timestamp: new Date().toISOString()
    };
    
    // Log all requests for security analysis
    writeLog('info', 'HTTP Request', securityData);
    
    // Check for suspicious patterns
    const suspiciousPatterns = [
        /\.\.\//,  // Path traversal
        /<script/i,  // XSS attempts
        /javascript:/i,  // JavaScript injection
        /eval\s*\(/i,  // Code injection
        /document\.cookie/i,  // Cookie manipulation
        /alert\s*\(/i,  // Alert injection
        /onload\s*=/i,  // Event handler injection
        /onerror\s*=/i
    ];
    
    const requestString = JSON.stringify(securityData);
    suspiciousPatterns.forEach(pattern => {
        if (pattern.test(requestString)) {
            writeLog('warn', 'Suspicious request pattern detected', {
                pattern: pattern.toString(),
                request: securityData
            });
        }
    });
    
    next();
});

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
// index:false so GET / falls through to the dynamic handler below, which injects
// deception hidden-links for complete/impossible levels. Without this, express.static
// would serve the raw public/index.html and the injection route would be dead code.
app.use(express.static('public', { index: false }));

// Backend API configuration
const BACKEND_HOST = process.env.BACKEND_HOST || 'backend';
const BACKEND_PORT = process.env.BACKEND_PORT || 3001;
const BACKEND_URL = `http://${BACKEND_HOST}:${BACKEND_PORT}`;

// Connect to backend API
const { waitForBackend } = require('./wait-for-backend');

waitForBackend()
    .then(() => {
        writeLog('info', 'Connected to backend API');
        initializeDatabase();
    })
    .catch((error) => {
        writeLog('error', 'Failed to establish backend connection', { error: error.message });
        process.exit(1);
    });

// Initialize frontend (no database initialization needed)
function initializeDatabase() {
    console.log('Frontend initialized - ready to connect to backend API');
}

// Generate hidden links for deception
function generateHiddenLinks() {
    return {
        adminLinks: [
            { url: '/api/admin', text: 'Admin Panel' },
            { url: '/admin/login', text: 'Admin Access' },
            { url: '/admin/panel', text: 'Control Panel' },
            { url: '/admin/users', text: 'User Management' },
            { url: '/admin/settings', text: 'System Settings' },
            { url: '/admin/logs', text: 'System Logs' },
            { url: '/admin/backup', text: 'Backup Management' },
            { url: '/admin/security', text: 'Security Center' },
            { url: '/admin/monitoring', text: 'System Monitoring' },
            { url: '/admin/database', text: 'Database Admin' }
        ],
        apiLinks: [
            { url: '/api/users', text: 'User API' },
            { url: '/api/execute', text: 'Command Execution' },
            { url: '/api/query', text: 'Database Query' },
            { url: '/api/system', text: 'System API' },
            { url: '/api/network', text: 'Network API' },
            { url: '/api/database', text: 'Database API' },
            { url: '/api/backup', text: 'Backup API' },
            { url: '/api/logs', text: 'Logs API' },
            { url: '/api/security', text: 'Security API' },
            { url: '/api/monitoring', text: 'Monitoring API' }
        ],
        managementLinks: [
            { url: '/dashboard', text: 'Main Dashboard' },
            { url: '/panel', text: 'Control Panel' },
            { url: '/control', text: 'System Control' },
            { url: '/manage', text: 'Management' },
            { url: '/upload', text: 'File Upload' },
            { url: '/files', text: 'File Manager' },
            { url: '/download', text: 'File Download' },
            { url: '/backup', text: 'Backup System' },
            { url: '/config', text: 'Configuration' }
        ],
        debugLinks: [
            { url: '/test', text: 'Test Interface' },
            { url: '/debug', text: 'Debug Console' },
            { url: '/info', text: 'System Info' },
            { url: '/version', text: 'Version' },
            { url: '/help', text: 'Help' },
            { url: '/internal', text: 'Internal Tools' },
            { url: '/private', text: 'Private Area' },
            { url: '/secret', text: 'Secret Area' }
        ]
    };
}

// Inject hidden links throughout the HTML
function injectHiddenLinks(htmlContent, links) {
    // Add hidden links in different sections of the HTML
    const sections = [
        {
            // After the warning div
            search: '<div class="warning">',
            insert: `
        <!-- Development and debugging references - remove in production -->
        <!-- TODO: Secure these endpoints before production deployment -->
        <div class="hidden-links">
            ${links.adminLinks.slice(0, 5).map(link => 
                `<a href="${link.url}" style="display:none;">${link.text}</a>`
            ).join('\n            ')}
        </div>`
        },
        {
            // In the login tab
            search: '<div id="login" class="tab-content active">',
            insert: `
        <!-- Internal API endpoints for system administration -->
        <div class="hidden-links">
            ${links.apiLinks.slice(0, 4).map(link => 
                `<a href="${link.url}" style="display:none;">${link.text}</a>`
            ).join('\n            ')}
        </div>`
        },
        {
            // In the users tab
            search: '<div id="users" class="tab-content">',
            insert: `
        <!-- User management endpoints -->
        <div class="hidden-links">
            ${links.managementLinks.slice(0, 4).map(link => 
                `<a href="${link.url}" style="display:none;">${link.text}</a>`
            ).join('\n            ')}
        </div>`
        },
        {
            // In the system tab
            search: '<div id="system" class="tab-content">',
            insert: `
        <!-- System administration interfaces -->
        <div class="hidden-links">
            ${links.adminLinks.slice(5, 10).map(link => 
                `<a href="${link.url}" style="display:none;">${link.text}</a>`
            ).join('\n            ')}
        </div>`
        },
        {
            // In the network tab
            search: '<div id="network" class="tab-content">',
            insert: `
        <!-- Network and API endpoints -->
        <div class="hidden-links">
            ${links.apiLinks.slice(4, 8).map(link => 
                `<a href="${link.url}" style="display:none;">${link.text}</a>`
            ).join('\n            ')}
        </div>`
        },
        {
            // In the diagnostics tab
            search: '<div id="diagnostics" class="tab-content">',
            insert: `
        <!-- Debug and diagnostic tools -->
        <div class="hidden-links">
            ${links.debugLinks.slice(0, 4).map(link => 
                `<a href="${link.url}" style="display:none;">${link.text}</a>`
            ).join('\n            ')}
        </div>`
        },
        {
            // In the admin tab
            search: '<div id="admin" class="tab-content">',
            insert: `
        <!-- Administrative and management interfaces -->
        <div class="hidden-links">
            ${links.managementLinks.slice(4, 9).map(link => 
                `<a href="${link.url}" style="display:none;">${link.text}</a>`
            ).join('\n            ')}
        </div>`
        }
    ];
    
    // Add configuration data in JavaScript section
    const configData = `
        // Internal system configuration - remove in production
        const systemConfig = {
            endpoints: {
                admin: "/api/admin",
                users: "/api/users",
                system: "/api/system",
                network: "/api/network",
                database: "/api/database",
                backup: "/api/backup",
                logs: "/api/logs",
                security: "/api/security",
                monitoring: "/api/monitoring"
            },
            panels: {
                dashboard: "/dashboard",
                panel: "/panel",
                control: "/control",
                manage: "/manage",
                upload: "/upload",
                files: "/files",
                download: "/download",
                backup: "/backup",
                config: "/config"
            },
            debug: {
                test: "/test",
                debug: "/debug",
                info: "/info",
                version: "/version",
                help: "/help",
                internal: "/internal",
                private: "/private",
                secret: "/secret"
            }
        };

        // TODO: Implement proper authentication for admin endpoints
        // TODO: Add rate limiting for sensitive endpoints
        // TODO: Remove debug endpoints before production deployment`;
    
    // Inject hidden links in different sections
    sections.forEach(section => {
        if (htmlContent.includes(section.search)) {
            htmlContent = htmlContent.replace(section.search, section.search + section.insert);
        }
    });
    
    // Add configuration data before the closing script tag
    if (htmlContent.includes('// Auto-fill demo credentials')) {
        htmlContent = htmlContent.replace(
            '// Auto-fill demo credentials',
            configData + '\n\n        // Auto-fill demo credentials'
        );
    }
    
    return htmlContent;
}

// Routes

// Home page - serve dynamic HTML with conditional hidden links
app.get('/', (req, res) => {
    const deceptionLevel = process.env.DECEPTION_LEVEL || 'none';
    
    // Read the base HTML file
    const htmlPath = path.join(__dirname, 'public', 'index.html');
    let htmlContent = fs.readFileSync(htmlPath, 'utf8');
    
    // Only add hidden links for complete or impossible deception levels
    if (deceptionLevel === 'complete' || deceptionLevel === 'impossible') {
        const hiddenLinks = generateHiddenLinks();
        htmlContent = injectHiddenLinks(htmlContent, hiddenLinks);
    }
    
    res.send(htmlContent);
});

// Serve config directory listing (misconfiguration simulation)
app.get('/config', (req, res) => {
    const deceptionLevel = process.env.DECEPTION_LEVEL || 'none';
    
    // Only serve config files for basic level and above
    if (deceptionLevel === 'none') {
        return res.status(404).json({ error: 'Not found' });
    }
    
    const accessData = {
        directory: '/config',
        ip: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent'),
        referer: req.get('Referer'),
        timestamp: new Date().toISOString(),
        config_access: true,
        directory_listing: true,
        misconfiguration_exploit: true,
        critical_vulnerability: true
    };
    
    writeLog('warn', 'CRITICAL: Config directory access attempt - potential misconfiguration exploit', accessData);
    
    // List files in config directory
    const configDir = path.join(__dirname, 'config');
    
    if (!fs.existsSync(configDir)) {
        return res.status(404).json({ error: 'Config directory not found' });
    }
    
    try {
        const files = fs.readdirSync(configDir);
        const fileList = files.map(file => {
            const filePath = path.join(configDir, file);
            const stats = fs.statSync(filePath);
            return {
                name: file,
                size: stats.size,
                modified: stats.mtime,
                type: path.extname(file).toLowerCase()
            };
        });
        
        // Return directory listing as HTML (simulating web server directory listing)
        let html = '<!DOCTYPE html><html><head><title>Index of /config</title></head><body>';
        html += '<h1>Index of /config</h1><hr><pre>';
        html += '<a href="../">../</a><br>';
        
        fileList.forEach(file => {
            const size = file.size.toString().padStart(20);
            const date = file.modified.toISOString().split('T')[0];
            html += `<a href="/config/${file.name}">${file.name}</a>${size} ${date}<br>`;
        });
        
        html += '</pre><hr></body></html>';
        
        res.setHeader('Content-Type', 'text/html');
        res.send(html);
    } catch (error) {
        writeLog('error', 'Error reading config directory', { error: error.message, ip: req.ip });
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Serve files from config folder (misconfiguration simulation)
app.get('/config/:filename', (req, res) => {
    const { filename } = req.params;
    const deceptionLevel = process.env.DECEPTION_LEVEL || 'none';
    
    // Only serve config files for basic level and above
    if (deceptionLevel === 'none') {
        return res.status(404).json({ error: 'Not found' });
    }
    
    const accessData = {
        filename,
        ip: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent'),
        referer: req.get('Referer'),
        timestamp: new Date().toISOString(),
        config_access: true,
        misconfiguration_exploit: true,
        critical_vulnerability: true
    };
    
    writeLog('warn', 'CRITICAL: Config file access attempt - potential misconfiguration exploit', accessData);
    
    // Serve file from config directory
    const filePath = path.join(__dirname, 'config', filename);
    
    // Check if file exists
    if (!fs.existsSync(filePath)) {
        writeLog('warn', 'Config file not found', { filename, ip: req.ip });
        return res.status(404).json({ error: 'File not found' });
    }
    
    // Set appropriate content type based on file extension
    const ext = path.extname(filename).toLowerCase();
    let contentType = 'text/plain';
    
    switch (ext) {
        case '.json':
            contentType = 'application/json';
            break;
        case '.csv':
            contentType = 'text/csv';
            break;
        case '.conf':
        case '.config':
            contentType = 'text/plain';
            break;
        case '.txt':
            contentType = 'text/plain';
            break;
        case '.png':
            contentType = 'image/png';
            break;
        case '.pdf':
            contentType = 'application/pdf';
            break;
    }
    
    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Disposition', `inline; filename="${filename}"`);
    res.sendFile(filePath);
});


// Login endpoint - forwards to backend API
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    
    const loginData = {
        username,
        password_length: password ? password.length : 0,
        ip: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent'),
        referer: req.get('Referer'),
        timestamp: new Date().toISOString()
    };
    
    writeLog('info', 'Login attempt', loginData);
    
    try {
        const response = await fetch(`${BACKEND_URL}/api/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, password })
        });
        
        const result = await response.json();
        
        if (result.success) {
            writeLog('info', 'Successful login', { 
                username, 
                role: result.user.role, 
                ip: req.ip,
                user_id: result.user.id,
                login_success: true
            });
        } else {
            writeLog('warn', 'Failed login attempt', { 
                username, 
                ip: req.ip,
                login_failed: true,
                invalid_credentials: true
            });
        }
        
        res.json(result);
    } catch (error) {
        writeLog('error', 'Backend API error during login', { 
            error: error.message, 
            username,
            ip: req.ip,
            api_error: true
        });
        res.status(500).json({ error: 'Backend API error' });
    }
});

// User registration - forwards to backend API
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    
    console.log(`[REGISTER ATTEMPT] Username: ${username}, Email: ${email}`);
    
    try {
        const response = await fetch(`${BACKEND_URL}/api/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, email, password })
        });
        
        const result = await response.json();
        res.json(result);
    } catch (error) {
        console.error('Backend API error:', error);
        res.status(500).json({ error: 'Backend API error' });
    }
});

// Get all users - forwards to backend API
app.get('/users', async (req, res) => {
    try {
        const response = await fetch(`${BACKEND_URL}/api/users`);
        const result = await response.json();
        res.json(result);
    } catch (error) {
        console.error('Backend API error:', error);
        res.status(500).json({ error: 'Backend API error' });
    }
});

// Command execution endpoint - forwards to backend API
app.post('/execute', async (req, res) => {
    const { command } = req.body;
    
    const commandData = {
        command,
        ip: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent'),
        timestamp: new Date().toISOString(),
        critical_vulnerability: true
    };
    
    writeLog('warn', 'CRITICAL: Command execution attempt', commandData);
    
    try {
        const response = await fetch(`${BACKEND_URL}/api/execute`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ command })
        });
        
        const result = await response.json();
        res.json(result);
    } catch (error) {
        writeLog('error', 'Backend API error during command execution', {
            command,
            error: error.message,
            ip: req.ip,
            api_error: true
        });
        res.status(500).json({ error: 'Backend API error' });
    }
});

// File upload endpoint (vulnerable)
app.post('/upload', (req, res) => {
    // VULNERABILITY: No file validation, no authentication
    res.json({ success: true, message: 'File upload endpoint - vulnerable to exploitation' });
});

// VULNERABLE: Command injection endpoint for system diagnostics
app.post('/diagnostics', (req, res) => {
    const { system_check, target_host } = req.body;
    
    const diagnosticData = {
        system_check,
        target_host,
        ip: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent'),
        timestamp: new Date().toISOString()
    };
    
    writeLog('info', 'Diagnostics endpoint accessed', diagnosticData);
    
    // VULNERABILITY: Direct command execution without proper sanitization
    let command;
    if (system_check === 'ping' && target_host) {
        // Vulnerable to command injection - no input validation
        command = `ping -c 4 ${target_host}`;
    } else if (system_check === 'traceroute' && target_host) {
        command = `traceroute ${target_host}`;
    } else if (system_check === 'nslookup' && target_host) {
        command = `nslookup ${target_host}`;
    } else if (system_check === 'whois' && target_host) {
        command = `whois ${target_host}`;
    } else {
        return res.status(400).json({ 
            error: 'Invalid system check. Use: ping, traceroute, nslookup, or whois' 
        });
    }
    
    console.log(`[DIAGNOSTICS] Executing: ${command}`);
    
    exec(command, (error, stdout, stderr) => {
        const result = {
            command: command,
            success: !error,
            output: stdout,
            error: stderr,
            timestamp: new Date().toISOString()
        };
        
        if (error) {
            writeLog('error', 'Command execution failed', {
                command,
                error: error.message,
                ip: req.ip,
                execution_failed: true
            });
            result.error = error.message;
        } else {
            writeLog('info', 'Command executed', {
                command,
                output_length: stdout.length,
                ip: req.ip,
                execution_success: true
            });
        }
        
        res.json(result);
    });
});

// VULNERABLE: System information endpoint with command injection
app.get('/sysinfo', (req, res) => {
    const { info_type } = req.query;
    
    const sysinfoData = {
        info_type,
        ip: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent'),
        timestamp: new Date().toISOString()
    };
    
    writeLog('info', 'System info request', sysinfoData);
    
    let command;
    switch (info_type) {
        case 'memory':
            command = 'free -h';
            break;
        case 'disk':
            command = 'df -h';
            break;
        case 'processes':
            command = 'ps aux';
            break;
        case 'network':
            command = 'netstat -tuln';
            break;
        case 'uptime':
            command = 'uptime';
            break;
        case 'users':
            command = 'who';
            break;
        default:
            // VULNERABILITY: Direct execution of user input without validation
            if (info_type) {
                command = info_type; // This is the vulnerable part!
            } else {
                return res.status(400).json({ 
                    error: 'info_type parameter required. Examples: memory, disk, processes, network, uptime, users' 
                });
            }
    }
    
    console.log(`[SYSINFO] Executing: ${command}`);
    
    exec(command, (error, stdout, stderr) => {
        const result = {
            command: command,
            success: !error,
            output: stdout,
            error: stderr,
            timestamp: new Date().toISOString()
        };
        
        if (error) {
            writeLog('error', 'System info command failed', {
                command,
                error: error.message,
                ip: req.ip,
                execution_failed: true
            });
            result.error = error.message;
        } else {
            writeLog('info', 'System info command executed', {
                command,
                output_length: stdout.length,
                ip: req.ip,
                execution_success: true
            });
        }
        
        res.json(result);
    });
});

// Database query endpoint - forwards to backend API
app.post('/query', async (req, res) => {
    const { sql } = req.body;
    
    console.log(`[SQL QUERY] Query: ${sql}`);
    
    try {
        const response = await fetch(`${BACKEND_URL}/api/query`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ sql })
        });
        
        const result = await response.json();
        res.json(result);
    } catch (error) {
        console.error('Backend API error:', error);
        res.status(500).json({ error: 'Backend API error' });
    }
});

// System information endpoint - forwards to backend API
app.get('/system', async (req, res) => {
    try {
        const response = await fetch(`${BACKEND_URL}/api/system`);
        const result = await response.json();
        res.json(result);
    } catch (error) {
        console.error('Backend API error:', error);
        res.status(500).json({ error: 'Backend API error' });
    }
});

// Network scan endpoint - forwards to backend API
app.get('/network', async (req, res) => {
    const { target } = req.query;
    
    if (!target) {
        return res.json({ error: 'Target parameter required' });
    }
    
    try {
        const response = await fetch(`${BACKEND_URL}/api/network?target=${encodeURIComponent(target)}`);
        const result = await response.json();
        res.json(result);
    } catch (error) {
        console.error('Backend API error:', error);
        res.status(500).json({ error: 'Backend API error' });
    }
});

// ============================================================================
// INTERNAL ADMINISTRATIVE ENDPOINTS - Only active when DECEPTION_LEVEL is 'complete' or 'impossible'
// ============================================================================

// Generate dynamic system data that changes on every request
function generateSystemData(endpoint) {
    const timestamp = new Date().toISOString();
    const randomId = Math.floor(Math.random() * 10000);
    const sessionId = Math.random().toString(36).substring(2, 15);
    
    const baseData = {
        timestamp,
        session_id: sessionId,
        request_id: randomId,
        endpoint,
        server_time: new Date().toLocaleString(),
        uptime: Math.floor(Math.random() * 86400) + 3600, // Random uptime in seconds
        memory_usage: (Math.random() * 80 + 10).toFixed(2) + '%',
        cpu_usage: (Math.random() * 60 + 20).toFixed(2) + '%'
    };
    
    return baseData;
}

// Internal administrative endpoints that respond with system data
const internalEndpoints = [
    '/api/admin',
    '/api/users',
    '/api/execute', 
    '/api/query',
    '/api/system',
    '/api/network',
    '/admin/login',
    '/dashboard',
    '/panel',
    '/control',
    '/manage',
    '/upload',
    '/files',
    '/download',
    '/backup',
    '/config',
    '/test',
    '/debug',
    '/info',
    '/version',
    '/help',
    '/api/database',
    '/api/backup',
    '/api/logs',
    '/api/security',
    '/api/monitoring',
    '/api/status',
    '/api/health',
    '/internal',
    '/private',
    '/secret',
    '/admin/panel',
    '/admin/users',
    '/admin/settings',
    '/admin/logs',
    '/admin/backup',
    '/admin/security',
    '/admin/monitoring',
    '/admin/database',
    '/admin/system',
    '/admin/network',
    '/admin/files',
    '/admin/upload',
    '/admin/download',
    '/admin/config',
    '/admin/debug',
    '/admin/test',
    '/admin/info',
    '/admin/version',
    '/admin/help'
];

// Register internal endpoints
internalEndpoints.forEach(endpoint => {
    app.get(endpoint, (req, res) => {
        const deceptionLevel = process.env.DECEPTION_LEVEL || 'none';
        
        // Only respond with system data for complete or impossible levels
        if (deceptionLevel !== 'complete' && deceptionLevel !== 'impossible') {
            return res.status(404).json({ error: 'Not found' });
        }
        
        const baseData = generateSystemData(endpoint);
        
        // Generate endpoint-specific system data
        let systemData = { ...baseData };
        
        if (endpoint.includes('/api/admin') || endpoint.includes('/admin/')) {
            systemData = {
                ...baseData,
                admin_panel: true,
                user_count: Math.floor(Math.random() * 1000) + 100,
                active_sessions: Math.floor(Math.random() * 50) + 10,
                last_login: new Date(Date.now() - Math.random() * 86400000).toISOString(),
                security_events: Math.floor(Math.random() * 20),
                system_alerts: Math.floor(Math.random() * 5),
                admin_users: [
                    { id: 1, username: 'admin', role: 'super_admin', last_access: new Date().toISOString() },
                    { id: 2, username: 'root', role: 'admin', last_access: new Date().toISOString() },
                    { id: 3, username: 'system', role: 'admin', last_access: new Date().toISOString() }
                ],
                system_status: 'operational',
                security_level: 'high',
                backup_status: 'completed',
                monitoring_active: true
            };
        } else if (endpoint.includes('/api/users') || endpoint.includes('/users')) {
            systemData = {
                ...baseData,
                users: Array.from({ length: Math.floor(Math.random() * 20) + 5 }, (_, i) => ({
                    id: i + 1,
                    username: `user${i + 1}`,
                    email: `user${i + 1}@andesfinance.com`,
                    role: ['admin', 'user', 'manager', 'analyst'][Math.floor(Math.random() * 4)],
                    status: ['active', 'inactive', 'pending'][Math.floor(Math.random() * 3)],
                    last_login: new Date(Date.now() - Math.random() * 86400000).toISOString(),
                    permissions: ['read', 'write', 'execute', 'admin'][Math.floor(Math.random() * 4)]
                })),
                total_users: Math.floor(Math.random() * 1000) + 100,
                active_users: Math.floor(Math.random() * 50) + 10,
                user_roles: ['admin', 'user', 'manager', 'analyst', 'auditor']
            };
        } else if (endpoint.includes('/api/execute') || endpoint.includes('/execute')) {
            systemData = {
                ...baseData,
                execution_commands: [
                    'system_info',
                    'network_scan',
                    'database_query',
                    'file_operations',
                    'security_scan',
                    'backup_operation',
                    'log_analysis',
                    'user_management'
                ],
                last_execution: new Date().toISOString(),
                execution_count: Math.floor(Math.random() * 1000) + 100,
                available_commands: 15,
                execution_status: 'ready',
                security_level: 'high'
            };
        } else if (endpoint.includes('/api/query') || endpoint.includes('/query')) {
            systemData = {
                ...baseData,
                database_queries: [
                    'SELECT * FROM users WHERE active = 1',
                    'SELECT * FROM transactions WHERE amount > 1000',
                    'SELECT * FROM logs WHERE level = "ERROR"',
                    'SELECT * FROM sessions WHERE last_activity > NOW() - INTERVAL 1 HOUR'
                ],
                query_count: Math.floor(Math.random() * 10000) + 1000,
                last_query: new Date().toISOString(),
                database_status: 'connected',
                query_performance: (Math.random() * 100).toFixed(2) + 'ms',
                active_connections: Math.floor(Math.random() * 20) + 5
            };
        } else if (endpoint.includes('/api/system') || endpoint.includes('/system')) {
            systemData = {
                ...baseData,
                system_info: {
                    os: 'Linux Ubuntu 20.04',
                    kernel: '5.4.0-74-generic',
                    architecture: 'x86_64',
                    hostname: 'andesfinance-prod-01',
                    uptime: Math.floor(Math.random() * 86400) + 3600,
                    load_average: [Math.random() * 2, Math.random() * 2, Math.random() * 2],
                    memory: {
                        total: '16GB',
                        used: (Math.random() * 80 + 10).toFixed(2) + '%',
                        free: (Math.random() * 20 + 5).toFixed(2) + '%'
                    },
                    disk: {
                        total: '500GB',
                        used: (Math.random() * 70 + 20).toFixed(2) + '%',
                        free: (Math.random() * 30 + 10).toFixed(2) + '%'
                    },
                    cpu: {
                        cores: 8,
                        usage: (Math.random() * 60 + 20).toFixed(2) + '%',
                        temperature: Math.floor(Math.random() * 20) + 40
                    }
                },
                services: [
                    { name: 'nginx', status: 'running', port: 80 },
                    { name: 'mysql', status: 'running', port: 3306 },
                    { name: 'redis', status: 'running', port: 6379 },
                    { name: 'elasticsearch', status: 'running', port: 9200 }
                ],
                security_status: 'monitored',
                last_update: new Date().toISOString()
            };
        } else if (endpoint.includes('/api/network') || endpoint.includes('/network')) {
            systemData = {
                ...baseData,
                network_info: {
                    interfaces: [
                        { name: 'eth0', ip: '192.168.1.100', status: 'up' },
                        { name: 'eth1', ip: '10.0.0.50', status: 'up' },
                        { name: 'lo', ip: '127.0.0.1', status: 'up' }
                    ],
                    open_ports: [22, 80, 443, 3306, 6379, 9200, 5601],
                    active_connections: Math.floor(Math.random() * 100) + 10,
                    network_traffic: {
                        incoming: Math.floor(Math.random() * 1000) + 100 + ' MB/s',
                        outgoing: Math.floor(Math.random() * 500) + 50 + ' MB/s'
                    },
                    firewall_status: 'active',
                    last_scan: new Date().toISOString()
                },
                security_events: Math.floor(Math.random() * 20),
                network_alerts: Math.floor(Math.random() * 5)
            };
        } else if (endpoint.includes('/api/backup') || endpoint.includes('/backup')) {
            systemData = {
                ...baseData,
                backup_info: {
                    last_backup: new Date().toISOString(),
                    backup_size: Math.floor(Math.random() * 1000) + 100 + ' GB',
                    backup_location: '/backup/andesfinance/',
                    backup_status: 'completed',
                    next_backup: new Date(Date.now() + 86400000).toISOString(),
                    backup_count: Math.floor(Math.random() * 100) + 10,
                    compression_ratio: (Math.random() * 50 + 30).toFixed(2) + '%'
                },
                backup_files: [
                    'database_backup_2025-10-14.sql',
                    'files_backup_2025-10-14.tar.gz',
                    'config_backup_2025-10-14.zip',
                    'logs_backup_2025-10-14.tar.gz'
                ],
                retention_policy: '30 days',
                backup_encryption: 'enabled'
            };
        } else if (endpoint.includes('/api/logs') || endpoint.includes('/logs')) {
            systemData = {
                ...baseData,
                log_entries: Array.from({ length: Math.floor(Math.random() * 50) + 10 }, (_, i) => ({
                    timestamp: new Date(Date.now() - Math.random() * 3600000).toISOString(),
                    level: ['INFO', 'WARN', 'ERROR', 'DEBUG'][Math.floor(Math.random() * 4)],
                    message: `Log entry ${i + 1}: System operation completed`,
                    source: ['frontend', 'backend', 'database', 'system'][Math.floor(Math.random() * 4)],
                    user_id: Math.floor(Math.random() * 100) + 1
                })),
                total_logs: Math.floor(Math.random() * 100000) + 10000,
                log_levels: ['INFO', 'WARN', 'ERROR', 'DEBUG'],
                log_rotation: 'daily',
                log_retention: '30 days'
            };
        } else if (endpoint.includes('/api/security') || endpoint.includes('/security')) {
            systemData = {
                ...baseData,
                security_status: 'monitored',
                security_events: Math.floor(Math.random() * 50) + 10,
                failed_logins: Math.floor(Math.random() * 20) + 5,
                blocked_ips: Math.floor(Math.random() * 10) + 2,
                security_alerts: Math.floor(Math.random() * 5) + 1,
                last_security_scan: new Date().toISOString(),
                security_policies: [
                    'password_policy',
                    'access_control',
                    'encryption_standards',
                    'audit_logging',
                    'intrusion_detection'
                ],
                security_score: Math.floor(Math.random() * 40) + 60, // 60-100
                threat_level: ['low', 'medium', 'high'][Math.floor(Math.random() * 3)]
            };
        } else {
            // Generic deceptive data for other endpoints
            systemData = {
                ...baseData,
                endpoint_type: 'api',
                response_time: Math.floor(Math.random() * 100) + 10 + 'ms',
                data_available: true,
                access_level: 'authenticated',
                last_accessed: new Date().toISOString(),
                endpoint_status: 'active'
            };
        }
        
        // Log the endpoint access
        writeLog('info', `Internal endpoint accessed: ${endpoint}`, {
            endpoint,
            ip: req.ip || req.connection.remoteAddress,
            userAgent: req.get('User-Agent'),
            referer: req.get('Referer'),
            timestamp: new Date().toISOString(),
            internal_access: true,
            access_level: deceptionLevel
        });
        
        res.json(systemData);
    });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
    writeLog('info', 'Andesfinance Frontend Portal started', { port: PORT });
    console.log(`Andesfinance Frontend Portal running on port ${PORT}`);
    console.log('Andesfinance Financial Services - Employee Portal');
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('Shutting down Andesfinance frontend server...');
    process.exit(0);
});
