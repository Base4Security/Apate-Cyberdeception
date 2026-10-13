const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

/**
 * Deception Endpoints Module
 * 
 * This module provides multiple unused endpoints designed to monitor and log
 * suspicious activity when deception levels are "complete" or "impossible".
 * These endpoints are intentionally vulnerable and designed to attract attackers
 * while providing comprehensive monitoring capabilities.
 */

// Simple logging for juicy target access attempts
function logSuspiciousActivity(endpoint, method, req, data = {}) {
    const timestamp = new Date().toISOString();
    const logEntry = {
        timestamp,
        type: 'JUICY_ENDPOINT_ACCESS',
        endpoint,
        method,
        ip: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent'),
        referer: req.get('Referer'),
        body: req.body,
        query: req.query,
        params: req.params,
        data,
        juicy_target: true
    };
    
    // Log to file
    const logDir = '/var/log/backend';
    const logFile = path.join(logDir, `juicy-targets-${new Date().toISOString().split('T')[0]}.log`);
    const logLine = JSON.stringify(logEntry) + '\n';
    
    fs.appendFile(logFile, logLine, (err) => {
        if (err) console.error('Error writing juicy target log:', err);
    });
    
    // Console output for immediate monitoring
    console.log(`🎯 [JUICY TARGET HIT] ${method} ${endpoint} - IP: ${req.ip}`);
}


// Create deception endpoints router - focused on juicy targets only
function createDeceptionEndpoints() {
    const router = express.Router();
    
    // ===== JUICY ADMIN ENDPOINTS =====
    
    // Admin backup - very attractive to attackers
    router.get('/admin/backup', (req, res) => {
        logSuspiciousActivity('/admin/backup', 'GET', req, { 
            action: 'backup_attempt'
        });
        
        res.json({
            success: true,
            message: 'Backup completed successfully',
            backup_file: '/backups/system_backup_' + Date.now() + '.tar.gz',
            timestamp: new Date().toISOString()
        });
    });
    
    // Admin command execution - extremely juicy
    router.post('/admin/execute', (req, res) => {
        const { command } = req.body;
        
        logSuspiciousActivity('/admin/execute', 'POST', req, { 
            action: 'admin_command_execution',
            command
        });
        
        exec(command, (error, stdout, stderr) => {
            res.json({
                success: !error,
                output: stdout,
                error: stderr,
                command,
                timestamp: new Date().toISOString()
            });
        });
    });
    
    // ===== JUICY INTERNAL ENDPOINTS =====
    
    // Internal configuration - very attractive
    router.get('/internal/config', (req, res) => {
        logSuspiciousActivity('/internal/config', 'GET', req, { 
            action: 'internal_config_access'
        });
        
        res.json({
            success: true,
            config: {
                database: {
                    host: process.env.DB_HOST || 'mysql',
                    user: process.env.DB_USER || 'root',
                    password: process.env.DB_PASSWORD || 'vulnerable_password',
                    database: process.env.DB_NAME || 'andesfinance_db'
                },
                jwt_secret: 'vulnerable_secret_key',
                api_key: 'internal_api_key_12345',
                encryption_key: 'weak_encryption_key'
            }
        });
    });
    
    // Internal secrets - extremely juicy
    router.get('/internal/secrets', (req, res) => {
        logSuspiciousActivity('/internal/secrets', 'GET', req, { 
            action: 'secrets_access'
        });
        
        res.json({
            success: true,
            secrets: {
                admin_password: 'admin123',
                database_password: 'vulnerable_password',
                api_secret: 'secret_api_key_98765',
                encryption_key: 'super_secret_key_123',
                backup_key: 'backup_secret_456'
            }
        });
    });
    
    // Internal file access - very attractive
    router.get('/internal/files/:filename', (req, res) => {
        const { filename } = req.params;
        
        logSuspiciousActivity('/internal/files/' + filename, 'GET', req, { 
            action: 'internal_file_access',
            filename
        });
        
        res.json({
            success: true,
            filename,
            content: 'Loading file content... please wait...',
            size: Math.floor(Math.random() * 10000)
        });
    });
    
    // ===== JUICY DEVELOPMENT ENDPOINTS =====
    
    // Development database browser - attractive to attackers
    router.post('/dev/database', (req, res) => {
        const { query } = req.body;
        
        logSuspiciousActivity('/dev/database', 'POST', req, { 
            action: 'dev_database_query',
            query
        });
        
        res.json({
            success: true,
            query,
            results: 'Query executed successfully',
            timestamp: new Date().toISOString()
        });
    });
    
    // ===== JUICY VULNERABILITY ENDPOINTS =====
    
    // SQL injection test - very attractive
    router.get('/test/sql', (req, res) => {
        const { query } = req.query;
        
        logSuspiciousActivity('/test/sql', 'GET', req, { 
            action: 'sql_injection_test',
            query
        });
        
        res.json({
            success: true,
            message: 'SQL test endpoint',
            query,
            vulnerable: true
        });
    });
    
    // Command injection test - extremely juicy
    router.post('/test/command', (req, res) => {
        const { command } = req.body;
        
        logSuspiciousActivity('/test/command', 'POST', req, { 
            action: 'command_injection_test',
            command
        });
        
        exec(command, (error, stdout, stderr) => {
            res.json({
                success: !error,
                output: stdout,
                error: stderr,
                vulnerable: true
            });
        });
    });
    
    // ===== SINGLE SLASH JUICY ENDPOINTS =====
    
    // Admin panel - very common target
    router.get('/admin', (req, res) => {
        logSuspiciousActivity('/admin', 'GET', req, { 
            action: 'admin_panel_access'
        });
        
        res.json({
            success: true,
            message: 'Admin panel access granted',
            admin_url: '/admin/dashboard',
            features: ['User Management', 'System Settings', 'Database Tools']
        });
    });
    
    // Root admin access
    router.get('/root', (req, res) => {
        logSuspiciousActivity('/root', 'GET', req, { 
            action: 'root_access_attempt'
        });
        
        res.json({
            success: true,
            message: 'Root access granted',
            privileges: 'Full system access',
            commands: 'All system commands available'
        });
    });
    
    // Configuration access
    router.get('/config', (req, res) => {
        logSuspiciousActivity('/config', 'GET', req, { 
            action: 'config_access'
        });
        
        res.json({
            success: true,
            config: {
                database: 'mysql://root:password@localhost:3306',
                api_key: 'config_api_key_12345',
                secret: 'configuration_secret_789'
            }
        });
    });
    
    // Backup access
    router.get('/backup', (req, res) => {
        logSuspiciousActivity('/backup', 'GET', req, { 
            action: 'backup_access'
        });
        
        res.json({
            success: true,
            message: 'Backup access granted',
            backup_files: ['system_backup.tar.gz', 'database_backup.sql'],
            download_url: '/download/backup_' + Date.now()
        });
    });
    
    // Database access
    router.get('/database', (req, res) => {
        logSuspiciousActivity('/database', 'GET', req, { 
            action: 'database_access'
        });
        
        res.json({
            success: true,
            databases: ['andesfinance_db', 'mysql', 'information_schema'],
            tables: ['users', 'products', 'orders', 'logs'],
            access_level: 'full'
        });
    });
    
    // Shell access
    router.get('/shell', (req, res) => {
        logSuspiciousActivity('/shell', 'GET', req, { 
            action: 'shell_access_attempt'
        });
        
        res.json({
            success: true,
            message: 'Shell access granted',
            terminal: 'Interactive shell available',
            commands: 'All system commands enabled'
        });
    });
    
    // Debug access
    router.get('/debug', (req, res) => {
        logSuspiciousActivity('/debug', 'GET', req, { 
            action: 'debug_access'
        });
        
        res.json({
            success: true,
            debug_mode: true,
            features: ['Variable inspection', 'Step debugging', 'Memory analysis'],
            access_level: 'developer'
        });
    });
    
    // Test access
    router.get('/test', (req, res) => {
        logSuspiciousActivity('/test', 'GET', req, { 
            action: 'test_access'
        });
        
        res.json({
            success: true,
            message: 'Test environment access',
            tools: ['SQL tester', 'Command tester', 'File uploader'],
            vulnerable: true
        });
    });
    
    // Upload access
    router.get('/upload', (req, res) => {
        logSuspiciousActivity('/upload', 'GET', req, { 
            action: 'upload_access'
        });
        
        res.json({
            success: true,
            message: 'File upload interface',
            allowed_types: ['php', 'jsp', 'asp', 'exe', 'bat', 'sh'],
            max_size: '100MB',
            vulnerable: true
        });
    });
    
    // Files access
    router.get('/files', (req, res) => {
        logSuspiciousActivity('/files', 'GET', req, { 
            action: 'files_access'
        });
        
        res.json({
            success: true,
            message: 'File system access',
            files: ['config.php', 'database.sql', 'backup.tar.gz'],
            path: '/var/www/html/',
            vulnerable: true
        });
    });
    
    // Logs access
    router.get('/logs', (req, res) => {
        logSuspiciousActivity('/logs', 'GET', req, { 
            action: 'logs_access'
        });
        
        res.json({
            success: true,
            logs: [
                'access.log',
                'error.log', 
                'security.log',
                'admin.log'
            ],
            access_level: 'full'
        });
    });
    
    // System access
    router.get('/system', (req, res) => {
        logSuspiciousActivity('/system', 'GET', req, { 
            action: 'system_access'
        });
        
        res.json({
            success: true,
            system_info: {
                platform: process.platform,
                uptime: process.uptime(),
                memory: process.memoryUsage(),
                processes: 'Use /execute to run ps aux'
            }
        });
    });
    
    // Execute access
    router.get('/execute', (req, res) => {
        logSuspiciousActivity('/execute', 'GET', req, { 
            action: 'execute_access'
        });
        
        res.json({
            success: true,
            message: 'Command execution interface',
            usage: 'POST to /execute with command parameter',
            vulnerable: true
        });
    });
    
    return router;
}

module.exports = {
    createDeceptionEndpoints,
    logSuspiciousActivity
};
