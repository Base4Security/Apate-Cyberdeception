const http = require('http');

function waitForBackend(maxAttempts = 30, delay = 2000) {
    return new Promise((resolve, reject) => {
        const BACKEND_HOST = process.env.BACKEND_HOST || 'backend';
        const BACKEND_PORT = process.env.BACKEND_PORT || 3001;
        
        let attempts = 0;
        
        const checkBackend = () => {
            attempts++;
            console.log(`[${new Date().toISOString()}] Attempting backend connection (attempt ${attempts}/${maxAttempts})...`);
            
            const options = {
                hostname: BACKEND_HOST,
                port: BACKEND_PORT,
                path: '/health',
                method: 'GET',
                timeout: 5000
            };
            
            const req = http.request(options, (res) => {
                if (res.statusCode === 200) {
                    console.log(`[${new Date().toISOString()}] Backend connection successful!`);
                    resolve();
                } else {
                    if (attempts < maxAttempts) {
                        console.log(`[${new Date().toISOString()}] Backend not ready, retrying in ${delay}ms...`);
                        setTimeout(checkBackend, delay);
                    } else {
                        reject(new Error('Backend connection failed: Max attempts reached'));
                    }
                }
            });
            
            req.on('error', (err) => {
                if (attempts < maxAttempts) {
                    console.log(`[${new Date().toISOString()}] Backend connection failed: ${err.message}`);
                    console.log(`[${new Date().toISOString()}] Retrying in ${delay}ms...`);
                    setTimeout(checkBackend, delay);
                } else {
                    reject(new Error(`Backend connection failed: ${err.message}`));
                }
            });
            
            req.on('timeout', () => {
                req.destroy();
                if (attempts < maxAttempts) {
                    console.log(`[${new Date().toISOString()}] Backend connection timeout, retrying in ${delay}ms...`);
                    setTimeout(checkBackend, delay);
                } else {
                    reject(new Error('Backend connection failed: Timeout'));
                }
            });
            
            req.end();
        };
        
        checkBackend();
    });
}

module.exports = { waitForBackend };
