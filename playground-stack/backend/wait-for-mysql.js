const mysql = require('mysql2');
const { exec } = require('child_process');

const dbConfig = {
    host: process.env.DB_HOST || 'mysql',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || 'vulnerable_password',
    database: process.env.DB_NAME || 'andesfinance_db',
    port: process.env.DB_PORT || 3306
};

function waitForMySQL(maxRetries = 30, delay = 2000) {
    return new Promise((resolve, reject) => {
        let retries = 0;
        
        function attemptConnection() {
            console.log(`[${new Date().toISOString()}] Attempting MySQL connection (attempt ${retries + 1}/${maxRetries})...`);
            
            const connection = mysql.createConnection(dbConfig);
            
            connection.connect((err) => {
                if (err) {
                    retries++;
                    console.log(`[${new Date().toISOString()}] MySQL connection failed: ${err.message}`);
                    
                    if (retries >= maxRetries) {
                        console.error(`[${new Date().toISOString()}] Max retries (${maxRetries}) reached. Giving up.`);
                        reject(new Error(`Failed to connect to MySQL after ${maxRetries} attempts`));
                        return;
                    }
                    
                    console.log(`[${new Date().toISOString()}] Retrying in ${delay}ms...`);
                    setTimeout(attemptConnection, delay);
                    return;
                }
                
                console.log(`[${new Date().toISOString()}] MySQL connection successful!`);
                connection.end();
                resolve();
            });
        }
        
        attemptConnection();
    });
}

// If this script is run directly, wait for MySQL and then start the server
if (require.main === module) {
    waitForMySQL()
        .then(() => {
            console.log(`[${new Date().toISOString()}] Starting Andesfinance Backend Server...`);
            exec('node server.js', (error, stdout, stderr) => {
                if (error) {
                    console.error(`Error starting server: ${error}`);
                    process.exit(1);
                }
                if (stderr) {
                    console.error(`Server stderr: ${stderr}`);
                }
                console.log(stdout);
            });
        })
        .catch((error) => {
            console.error(`[${new Date().toISOString()}] Failed to start server: ${error.message}`);
            process.exit(1);
        });
}

module.exports = { waitForMySQL };
