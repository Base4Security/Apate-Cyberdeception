#!/usr/bin/env python3
"""
Generador de actividad falsa para simular comportamiento legítimo
en un entorno de honeypots y detección de intrusiones.
"""

import time
import random
import logging
from datetime import datetime
from faker import Faker
import requests
import os
from flask import Flask, jsonify
import socket
import threading
import paramiko

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/app/fake_activity.log')
    ]
)

logger = logging.getLogger(__name__)
fake = Faker()

# Configuración
ELASTICSEARCH_URL = os.getenv('ELASTICSEARCH_URL', 'http://elasticsearch:9200')
INDEX_NAME = 'fake-activity'
SSH_HONEYPOT_HOST = os.getenv('SSH_HONEYPOT_HOST', 'prod-ssh')
SSH_HONEYPOT_PORT = int(os.getenv('SSH_HONEYPOT_PORT', '22'))

# SSH users from the honeypot userdb.txt
SSH_USERS = {
    'root': 'toor',
    'admin': 'admin123',
    'maria': 'maria123',
    'juan': 'juan123',
    'pedro': 'pedro123',
    'backup': 'backup123'
}

# Flask app
app = Flask(__name__)


def send_to_elasticsearch(event):
    """Envía el evento a Elasticsearch"""
    try:
        url = f"{ELASTICSEARCH_URL}/{INDEX_NAME}/_doc"
        response = requests.post(url, json=event, timeout=5)
        if response.status_code in [200, 201]:
            logger.info(f"Evento enviado a Elasticsearch: {event['type']} por {event['user']}")
        else:
            logger.warning(f"Error enviando a Elasticsearch: {response.status_code}")
    except Exception as e:
        logger.error(f"Error conectando con Elasticsearch: {e}")


def create_elasticsearch_index():
    """Crea el índice en Elasticsearch si no existe"""
    try:
        url = f"{ELASTICSEARCH_URL}/{INDEX_NAME}"
        response = requests.head(url, timeout=5)
        if response.status_code == 404:
            # Crear el índice
            mapping = {
                "mappings": {
                    "properties": {
                        "timestamp": {"type": "date"},
                        "type": {"type": "keyword"},
                        "user": {"type": "keyword"},
                        "command": {"type": "text"},
                        "file_path": {"type": "text"},
                        "action": {"type": "keyword"},
                        "source_ip": {"type": "ip"},
                        "destination_ip": {"type": "ip"},
                        "session_id": {"type": "keyword"},
                        "fake_activity": {"type": "boolean"}
                    }
                }
            }
            requests.put(url, json=mapping, timeout=5)
            logger.info(f"Índice {INDEX_NAME} creado en Elasticsearch")
    except Exception as e:
        logger.error(f"Error creando índice: {e}")


# Flask API endpoints
@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'fake-activity',
        'active_ssh_sessions': len([t for t in ssh_simulator.active_sessions if t.is_alive()]) if ssh_simulator else 0
    })


class SSHClientSimulator:
    """Simulates SSH client connections to the honeypot using real SSH authentication"""

    def __init__(self):
        self.active_sessions = []
        self.running = False

    def simulate_ssh_session(self, username, password):
        """Simulate a complete SSH session with real authentication"""
        ssh_client = None
        try:
            # Create SSH client
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            logger.info(f"Attempting SSH connection for user: {username}")

            # Connect to SSH honeypot with authentication
            ssh_client.connect(
                hostname=SSH_HONEYPOT_HOST,
                port=SSH_HONEYPOT_PORT,
                username=username,
                password=password,
                timeout=10,
                allow_agent=False,
                look_for_keys=False
            )

            logger.info(f"SSH session authenticated successfully for user: {username}")

            # Generate realistic command sequence
            commands = self.generate_realistic_command_sequence(username)

            # Execute commands
            for command in commands:
                try:
                    logger.info(f"Executing command: {command} (user: {username})")

                    # Execute command
                    stdin, stdout, stderr = ssh_client.exec_command(command, timeout=10)

                    # Read output
                    output = stdout.read().decode('utf-8', errors='ignore')
                    error = stderr.read().decode('utf-8', errors='ignore')

                    response = output if output else error

                    logger.debug(f"Command output: {response[:100]}...")

                    # Log the activity
                    self.log_ssh_activity(username, command, response)

                    # Random delay between commands (more realistic)
                    time.sleep(random.uniform(2, 8))

                except Exception as e:
                    logger.error(f"Error executing command {command}: {e}")
                    # Continue with next command instead of breaking
            time.sleep(1)

            logger.info(f"SSH session completed for user: {username}")

        except paramiko.AuthenticationException:
            logger.error(f"Authentication failed for user {username}")
        except paramiko.SSHException as e:
            logger.error(f"SSH error for user {username}: {e}")
        except Exception as e:
            logger.error(f"Error in SSH session for user {username}: {e}")
        finally:
            if ssh_client:
                try:
                    ssh_client.close()
                    logger.debug(f"SSH connection closed for user: {username}")
                except Exception:
                    pass

    def generate_realistic_command_sequence(self, username):
        """Generate a realistic sequence of commands for a user"""
        sequences = {
            'root': ['whoami', 'pwd', 'ls -la', 'ps aux', 'cat /etc/passwd', 'netstat -tulpn'],
            'admin': ['whoami', 'pwd', 'ls -la', 'df -h', 'free -m', 'uptime'],
            'maria': ['pwd', 'ls', 'whoami', 'ls -la', 'cat /home/maria/documents.txt'],
            'juan': ['whoami', 'pwd', 'ls -la', 'ps aux', 'df -h'],
            'pedro': ['pwd', 'ls', 'whoami', 'free -m', 'uptime'],
            'backup': ['whoami', 'pwd', 'ls -la /backup', 'df -h', 'du -sh /backup/*', 'tar -czf backup.tar.gz /data']
        }

        # Get base sequence for user
        base_commands = sequences.get(username, ['whoami', 'pwd', 'ls -la'])

        # Add some randomness with common safe commands
        safe_commands = [
            'whoami', 'pwd', 'ls', 'ls -la', 'ps aux', 'df -h',
            'free -m', 'uptime', 'date', 'hostname', 'uname -a'
        ]
        extra_commands = random.sample(safe_commands, random.randint(1, 3))

        # Combine and maintain some order (more realistic)
        final_commands = base_commands + extra_commands

        return final_commands[:random.randint(3, 7)]

    def log_ssh_activity(self, username, command, response):
        """Log SSH activity to Elasticsearch only"""
        try:
            event = {
                'timestamp': datetime.now().isoformat(),
                'type': 'ssh_session_command',
                'user': username,
                'command': command,
                'response': response[:500] if response else '',  # Limit response length
                'source_ip': fake.ipv4(),
                'session_id': fake.uuid4(),
                'fake_activity': True,
                'activity_type': 'legitimate_ssh',
                'connection_type': 'real_ssh_connection'
            }

            # Send to Elasticsearch only
            send_to_elasticsearch(event)

            logger.debug(f"SSH activity logged: {username} - {command}")

        except Exception as e:
            logger.error(f"Error logging SSH activity: {e}")

    def start_automated_sessions(self):
        """Start automated SSH sessions with real authentication"""
        self.running = True
        logger.info("Starting automated SSH sessions with real authentication...")

        # Wait for SSH honeypot to be ready
        logger.info(f"Waiting for SSH honeypot at {SSH_HONEYPOT_HOST}:{SSH_HONEYPOT_PORT}...")
        max_retries = 30
        for i in range(max_retries):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((SSH_HONEYPOT_HOST, SSH_HONEYPOT_PORT))
                sock.close()
                logger.info("SSH honeypot is available")
                break
            except Exception:
                logger.info(f"Waiting for SSH honeypot... ({i+1}/{max_retries})")
                time.sleep(10)
        else:
            logger.error("SSH honeypot not available after waiting")
            return

        # Start generating sessions
        while self.running:
            try:
                # Random delay between sessions (10 to 30 seconds for testing)
                delay = random.randint(10, 30)
                logger.info(f"Next SSH session in {delay} seconds...")
                time.sleep(delay)

                if not self.running:
                    break

                # Select random user from SSH_USERS
                username = random.choice(list(SSH_USERS.keys()))
                password = SSH_USERS[username]

                logger.info(f"Starting SSH session for user: {username}")

                # Start session in separate thread
                session_thread = threading.Thread(
                    target=self.simulate_ssh_session,
                    args=(username, password),
                    daemon=True
                )
                session_thread.start()
                self.active_sessions.append(session_thread)

                # Clean up finished sessions
                self.active_sessions = [t for t in self.active_sessions if t.is_alive()]

                # Limit concurrent sessions
                if len(self.active_sessions) > 3:
                    logger.info("Too many concurrent sessions, waiting...")
                    time.sleep(random.randint(30, 60))

            except Exception as e:
                logger.error(f"Error in automated SSH sessions: {e}")
                time.sleep(60)

    def stop(self):
        """Stop automated sessions"""
        self.running = False
        logger.info("Stopping automated SSH sessions...")


# Global SSH simulator instance
ssh_simulator = SSHClientSimulator()


def wait_for_elasticsearch():
    """Wait for Elasticsearch to be available and create index"""
    logger.info("Waiting for Elasticsearch to be available...")

    # Esperar a que Elasticsearch esté disponible
    max_retries = 30
    for i in range(max_retries):
        try:
            response = requests.get(ELASTICSEARCH_URL, timeout=5)
            if response.status_code == 200:
                logger.info("Elasticsearch is available")
                break
        except Exception:
            logger.info(f"Waiting for Elasticsearch... ({i+1}/{max_retries})")
            time.sleep(10)
    else:
        logger.error("Could not connect to Elasticsearch after 5 minutes")
        return False

    # Crear índice
    create_elasticsearch_index()
    return True


def main():
    """Función principal - inicia Flask API y sesiones SSH automáticas"""
    import threading

    logger.info("Starting fake activity service (SSH sessions only)...")

    # Wait for Elasticsearch and create index
    elasticsearch_thread = threading.Thread(target=wait_for_elasticsearch, daemon=True)
    elasticsearch_thread.start()

    # Iniciar sesiones SSH automáticas en segundo plano
    ssh_thread = threading.Thread(target=ssh_simulator.start_automated_sessions, daemon=True)
    ssh_thread.start()

    # Iniciar Flask API
    logger.info("Starting Flask API on port 5000...")
    app.run(host='0.0.0.0', port=5000, debug=False)


if __name__ == "__main__":
    main()
