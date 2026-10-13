#!/usr/bin/env python3
"""
Real SSH Honeypot Monitor
Monitors real SSH server logs and triggers fake activity based on connection attempts.
"""

import time
import json
import logging
from datetime import datetime
import os
import re
import subprocess
import random

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/app/logs/ssh_honeypot.log')
    ]
)

logger = logging.getLogger(__name__)


class RealSSHMonitor:
    def __init__(self):
        self.log_file = '/var/log/auth.log'

    def start(self):
        """Start monitoring SSH server logs"""
        logger.info("Starting Real SSH Honeypot Monitor...")
        logger.info(f"Monitoring log file: {self.log_file}")

        try:
            # Monitor SSH logs in real-time
            self.monitor_ssh_logs()
        except KeyboardInterrupt:
            logger.info("Monitor stopped by user")
        except Exception as e:
            logger.error(f"Error in SSH monitor: {e}")

    def monitor_ssh_logs(self):
        """Monitor SSH server logs for connection attempts"""
        try:
            # Try different log sources
            log_sources = [
                '/var/log/auth.log',
                '/var/log/syslog',
                '/var/log/messages',
                '/var/log/secure'
            ]

            log_file = None
            for source in log_sources:
                if os.path.exists(source):
                    log_file = source
                    break

            if not log_file:
                logger.warning("No SSH log files found, creating a simple monitor")
                self.simple_monitor()
                return

            logger.info(f"Monitoring log file: {log_file}")

            # Use tail to follow the log file
            process = subprocess.Popen(
                ['tail', '-f', log_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )

            logger.info("SSH log monitoring started")

            for line in iter(process.stdout.readline, ''):
                if line:
                    self.process_log_line(line.strip())

        except Exception as e:
            logger.error(f"Error monitoring logs: {e}")

    def simple_monitor(self):
        """Simple monitoring when no log files are available"""
        logger.info("Running simple SSH monitor (no log files available)")

        # Enable SSH logging to a custom log file
        self.setup_ssh_logging()

        # Monitor SSH connections using netstat and ps
        while True:
            try:
                # Check if SSH is running
                result = subprocess.run(['pgrep', 'sshd'], capture_output=True, text=True)
                if result.returncode == 0:
                    logger.info("SSH server is running")

                    # Monitor active SSH connections
                    self.monitor_ssh_connections()

                    # Monitor SSH processes for command execution
                    self.monitor_ssh_processes()

                    # Monitor custom SSH log file
                    self.monitor_custom_ssh_log()
                else:
                    logger.warning("SSH server not detected")

                time.sleep(5)  # Check every 5 seconds
            except Exception as e:
                logger.error(f"Error in simple monitor: {e}")
                time.sleep(5)

    def monitor_custom_ssh_log(self):
        """Monitor custom SSH log file for connections and commands"""
        try:
            custom_log_file = '/var/log/ssh_custom.log'
            if os.path.exists(custom_log_file):
                # Read the file and process new entries
                with open(custom_log_file, 'r') as f:
                    lines = f.readlines()

                # Process each line for SSH activity
                for line in lines:
                    if line.strip():
                        self.process_ssh_log_line(line.strip())

        except Exception as e:
            logger.error(f"Error monitoring custom SSH log: {e}")

    def process_ssh_log_line(self, line):
        """Process SSH log line and extract connection/command info"""
        try:
            # Look for SSH connection patterns
            if 'Accepted password' in line or 'Accepted publickey' in line:
                # Extract user and IP from log line
                parts = line.split()
                if len(parts) >= 10:
                    user = parts[8] if 'user' in parts[8] else 'unknown'
                    ip = parts[10] if len(parts) > 10 else 'unknown'

                    # Log the connection
                    self.log_ssh_connection_event(ip, user)

            # Look for command execution patterns
            elif 'command=' in line:
                # Extract command from log line
                if 'command=' in line:
                    command_start = line.find('command=') + 8
                    command_end = line.find(' ', command_start)
                    if command_end == -1:
                        command_end = len(line)
                    command = line[command_start:command_end]

                    # Log the command execution
                    self.log_command_execution('unknown', command)

        except Exception as e:
            logger.error(f"Error processing SSH log line: {e}")

    def log_ssh_connection_event(self, ip, user):
        """Log SSH connection event"""
        try:
            # Determine if this is fake activity based on known fake IPs
            is_fake = self.is_fake_activity(ip, user)

            event_data = {
                'timestamp': datetime.now().isoformat(),
                'source_ip': ip,
                'username': user,
                'event_type': 'ssh_connection',
                'fake': is_fake,
                'connection_info': {
                    'source_ip': ip,
                    'username': user,
                    'status': 'authenticated'
                },
                'fake_activity': {
                    'triggered': True,
                    'source_ip': ip,
                    'event_type': 'ssh_connection',
                    'timestamp': datetime.now().isoformat()
                }
            }

            # Write to SSH connections log
            with open('/app/logs/ssh_connections.json', 'a') as f:
                f.write(json.dumps(event_data) + '\n')

            logger.info(f"SSH connection logged: {user} from {ip}")

        except Exception as e:
            logger.error(f"Error logging SSH connection: {e}")

    def log_command_execution(self, user, command):
        """Log command execution"""
        try:
            # Determine if this is fake activity based on known fake users
            is_fake = self.is_fake_activity('unknown', user)

            event_data = {
                'timestamp': datetime.now().isoformat(),
                'source_ip': 'unknown',
                'username': user,
                'event_type': 'command_execution',
                'command': command,
                'fake': is_fake,
                'session_info': {
                    'username': user,
                    'command': command,
                    'status': 'executed'
                },
                'fake_activity': {
                    'triggered': True,
                    'source_ip': 'unknown',
                    'event_type': 'command_execution',
                    'timestamp': datetime.now().isoformat()
                }
            }

            # Write to SSH connections log
            with open('/app/logs/ssh_connections.json', 'a') as f:
                f.write(json.dumps(event_data) + '\n')

            logger.info(f"Command execution logged: {command} by {user}")

        except Exception as e:
            logger.error(f"Error logging command execution: {e}")

    def is_fake_activity(self, ip, user):
        """Determine if activity is from fake users or real attackers"""
        try:
            # Known fake users from the SSH honeypot
            fake_users = ['root', 'admin', 'user', 'maria', 'juan', 'pedro', 'backup']

            # Known fake IPs (fake-activity service container)
            fake_ips = ['172.20.0.3', '172.18.0.4', 'localhost']

            # Check if user is a known fake user
            if user in fake_users:
                return True

            # Check if IP is a known fake IP
            if ip in fake_ips:
                return True

            # Check if it's from localhost (internal connections)
            if ip in ['127.0.0.1', 'localhost', '::1']:
                return True

            # Default to false for unknown external connections
            return False

        except Exception as e:
            logger.error(f"Error determining fake activity: {e}")
            return False

    def create_synthetic_command_logs(self):
        """Create synthetic command logs for active SSH connections"""
        try:
            # Read from /proc/net/tcp to find SSH connections
            with open('/proc/net/tcp', 'r') as f:
                lines = f.readlines()

            ssh_connections = []
            for line in lines[1:]:  # Skip header
                parts = line.strip().split()
                if len(parts) >= 4:
                    local_addr = parts[1]
                    remote_addr = parts[2]
                    state = parts[3]

                    # Check if it's SSH (port 22) and established
                    if ':0016' in local_addr and state == '01':  # 0016 = 22 in hex, 01 = ESTABLISHED
                        remote_ip = self.hex_to_ip(remote_addr.split(':')[0])

                        if remote_ip and remote_ip != '0.0.0.0':
                            ssh_connections.append(remote_ip)

            # Create synthetic command logs for active connections
            if ssh_connections:
                for remote_ip in ssh_connections:
                    # Generate realistic commands that might be executed
                    commands = ['whoami', 'pwd', 'ls -la', 'ps aux', 'df -h', 'uptime', 'date']
                    command = random.choice(commands)

                    # Log the command execution
                    self.log_synthetic_command(remote_ip, command)

        except Exception as e:
            logger.error(f"Error creating synthetic command logs: {e}")

    def log_synthetic_command(self, remote_ip, command):
        """Log synthetic command execution"""
        try:
            # Determine if this is fake activity
            is_fake = self.is_fake_activity(remote_ip, 'ssh_user')

            event_data = {
                'timestamp': datetime.now().isoformat(),
                'source_ip': remote_ip,
                'username': 'ssh_user',
                'event_type': 'command_execution',
                'command': command,
                'fake': is_fake,
                'session_info': {
                    'source_ip': remote_ip,
                    'command': command,
                    'status': 'executed'
                },
                'fake_activity': {
                    'triggered': True,
                    'source_ip': remote_ip,
                    'event_type': 'command_execution',
                    'timestamp': datetime.now().isoformat()
                }
            }

            # Write to JSON log file
            with open('/app/logs/ssh_connections.json', 'a') as f:
                f.write(json.dumps(event_data) + '\n')

            logger.info(f"Synthetic command logged: {remote_ip} - {command}")

        except Exception as e:
            logger.error(f"Error logging synthetic command: {e}")

    def setup_ssh_logging(self):
        """Setup SSH logging to a custom log file"""
        try:
            # Create a custom log file for SSH
            log_file = '/var/log/ssh_custom.log'

            # Configure SSH to log to this file
            with open('/etc/ssh/sshd_config', 'a') as f:
                f.write('\n# Custom logging\n')
                f.write('LogLevel VERBOSE\n')
                f.write('SyslogFacility LOCAL0\n')

            # Create logrotate entry
            with open('/etc/logrotate.d/ssh_custom', 'w') as f:
                f.write(f'{log_file} {{\n')
                f.write('    daily\n')
                f.write('    missingok\n')
                f.write('    rotate 7\n')
                f.write('    compress\n')
                f.write('    notifempty\n')
                f.write('    create 644 root root\n')
                f.write('}\n')

            # Restart SSH to apply new config
            subprocess.run(['service', 'ssh', 'restart'], check=True)
            logger.info("SSH logging configured")

        except Exception as e:
            logger.error(f"Error setting up SSH logging: {e}")

    def monitor_ssh_connections(self):
        """Monitor active SSH connections"""
        try:
            # Read from /proc/net/tcp to find SSH connections
            with open('/proc/net/tcp', 'r') as f:
                lines = f.readlines()

            ssh_connections = []
            for line in lines[1:]:  # Skip header
                parts = line.strip().split()
                if len(parts) >= 4:
                    local_addr = parts[1]
                    remote_addr = parts[2]
                    state = parts[3]

                    # Check if it's SSH (port 22) and established
                    if ':0016' in local_addr and state == '01':  # 0016 = 22 in hex, 01 = ESTABLISHED
                        # Convert hex addresses to IP
                        local_ip = self.hex_to_ip(local_addr.split(':')[0])
                        remote_ip = self.hex_to_ip(remote_addr.split(':')[0])

                        if remote_ip and remote_ip != '0.0.0.0':
                            ssh_connections.append((remote_ip, local_ip + ':22'))

            if ssh_connections:
                for remote_ip, local_addr in ssh_connections:
                    self.log_ssh_connection(remote_ip, local_addr)

        except Exception as e:
            logger.error(f"Error monitoring SSH connections: {e}")

    def hex_to_ip(self, hex_addr):
        """Convert hex address to IP"""
        try:
            # Convert hex to int and then to IP
            addr = int(hex_addr, 16)
            ip = f"{addr & 0xff}.{(addr >> 8) & 0xff}.{(addr >> 16) & 0xff}.{(addr >> 24) & 0xff}"
            return ip
        except (ValueError, TypeError):
            return None

    def log_ssh_connection(self, remote_ip, local_addr):
        """Log SSH connection event"""
        try:
            # Extract port from local address
            local_ip, local_port = local_addr.rsplit(':', 1)

            # Determine if this is fake activity
            is_fake = self.is_fake_activity(remote_ip, 'unknown')

            event_data = {
                'timestamp': datetime.now().isoformat(),
                'source_ip': remote_ip,
                'username': 'unknown',
                'event_type': 'connection_established',
                'local_port': local_port,
                'fake': is_fake,
                'connection_info': {
                    'remote_ip': remote_ip,
                    'local_addr': local_addr,
                    'status': 'established'
                },
                'fake_activity': {
                    'triggered': True,
                    'source_ip': remote_ip,
                    'event_type': 'connection_established',
                    'timestamp': datetime.now().isoformat()
                }
            }

            # Write to JSON log file
            with open('/app/logs/ssh_connections.json', 'a') as f:
                f.write(json.dumps(event_data) + '\n')

            logger.info(f"SSH connection logged: {remote_ip} -> {local_addr}")

        except Exception as e:
            logger.error(f"Error logging SSH connection: {e}")

    def monitor_ssh_processes(self):
        """Monitor SSH processes for command execution"""
        try:
            # Get SSH processes using ps
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                ssh_processes = [line for line in lines if 'sshd:' in line and ('pts/' in line or 'notty' in line)]

                for process in ssh_processes:
                    # Extract process info
                    parts = process.split()
                    if len(parts) >= 11:
                        pid = parts[1]
                        user = parts[0]
                        command = ' '.join(parts[10:])

                        # Log the SSH session
                        self.log_ssh_session(pid, user, command)

            # Also check for active SSH sessions by looking at /proc/net/tcp
            # and correlating with process information
            self.monitor_active_ssh_sessions()

        except Exception as e:
            logger.error(f"Error monitoring SSH processes: {e}")

    def monitor_active_ssh_sessions(self):
        """Monitor active SSH sessions and log them"""
        try:
            # Read from /proc/net/tcp to find SSH connections
            with open('/proc/net/tcp', 'r') as f:
                lines = f.readlines()

            active_connections = []
            for line in lines[1:]:  # Skip header
                parts = line.strip().split()
                if len(parts) >= 4:
                    local_addr = parts[1]
                    remote_addr = parts[2]
                    state = parts[3]

                    # Check if it's SSH (port 22) and established
                    if ':0016' in local_addr and state == '01':  # 0016 = 22 in hex, 01 = ESTABLISHED
                        remote_ip = self.hex_to_ip(remote_addr.split(':')[0])

                        if remote_ip and remote_ip != '0.0.0.0':
                            active_connections.append(remote_ip)

            # Log active connections as SSH sessions
            for remote_ip in active_connections:
                self.log_ssh_session('unknown', 'ssh_user', f'SSH session from {remote_ip}')

        except Exception as e:
            logger.error(f"Error monitoring active SSH sessions: {e}")

    def log_ssh_session(self, pid, user, command):
        """Log SSH session with command execution"""
        try:
            # Determine if this is fake activity
            is_fake = self.is_fake_activity('localhost', user)

            event_data = {
                'timestamp': datetime.now().isoformat(),
                'source_ip': 'localhost',
                'username': user,
                'event_type': 'command_execution',
                'pid': pid,
                'command': command,
                'fake': is_fake,
                'session_info': {
                    'pid': pid,
                    'user': user,
                    'command': command,
                    'status': 'active'
                },
                'fake_activity': {
                    'triggered': True,
                    'source_ip': 'localhost',
                    'username': user,
                    'event_type': 'command_execution',
                    'timestamp': datetime.now().isoformat()
                }
            }

            # Write to JSON log file
            with open('/app/logs/ssh_connections.json', 'a') as f:
                f.write(json.dumps(event_data) + '\n')

            logger.info(f"SSH session logged: {user} - {command}")

        except Exception as e:
            logger.error(f"Error logging SSH session: {e}")

    def process_log_line(self, line):
        """Process each log line for SSH events"""
        try:
            # Parse SSH connection events
            if 'sshd' in line and ('Accepted' in line or 'Failed' in line or 'Invalid' in line):
                self.handle_ssh_event(line)
            elif 'sshd' in line and ('Connection' in line or 'Disconnected' in line):
                self.handle_ssh_event(line)
            elif 'sshd' in line and ('password' in line.lower() or 'auth' in line.lower()):
                self.handle_ssh_event(line)
            elif 'sshd' in line and ('user' in line.lower() or 'login' in line.lower()):
                self.handle_ssh_event(line)

        except Exception as e:
            logger.error(f"Error processing log line: {e}")

    def handle_ssh_event(self, line):
        """Handle SSH connection events"""
        try:
            # Extract IP address
            ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            source_ip = ip_match.group(1) if ip_match else 'unknown'

            # Extract username with multiple patterns
            username = 'unknown'
            user_patterns = [
                r'for (\w+)',
                r'user (\w+)',
                r'(\w+)@',
                r'user=(\w+)',
                r'username (\w+)'
            ]

            for pattern in user_patterns:
                user_match = re.search(pattern, line)
                if user_match:
                    username = user_match.group(1)
                    break

            # Extract password attempt information
            password_info = self.extract_password_info(line)

            # Determine event type and log level
            if 'Accepted' in line:
                event_type = 'successful_login'
                logger.info(f"SSH Login Success: {username} from {source_ip} {password_info}")
            elif 'Failed' in line or 'Invalid' in line:
                event_type = 'failed_login'
                logger.warning(f"SSH Login Failed: {username} from {source_ip} {password_info}")
            elif 'Connection' in line:
                event_type = 'connection_attempt'
                logger.info(f"SSH Connection: {source_ip}")
            elif 'Disconnected' in line:
                event_type = 'disconnection'
                logger.info(f"SSH Disconnection: {source_ip}")
            elif 'password' in line.lower():
                event_type = 'password_attempt'
                logger.warning(f"SSH Password Attempt: {username} from {source_ip} {password_info}")
            elif 'auth' in line.lower():
                event_type = 'authentication_attempt'
                logger.warning(f"SSH Auth Attempt: {username} from {source_ip} {password_info}")
            else:
                event_type = 'other'
                logger.info(f"SSH Event: {username} from {source_ip} - {line}")

            # Log the event with enhanced information
            self.log_ssh_event(source_ip, username, event_type, line, password_info)

        except Exception as e:
            logger.error(f"Error handling SSH event: {e}")

    def extract_password_info(self, line):
        """Extract password-related information from log line"""
        try:
            password_info = {}

            # Check for password authentication
            if 'password' in line.lower():
                password_info['auth_method'] = 'password'

            # Check for key authentication
            if 'key' in line.lower():
                password_info['auth_method'] = 'key'

            # Check for failed password attempts
            if 'failed' in line.lower() and 'password' in line.lower():
                password_info['result'] = 'failed'

            # Check for successful authentication
            if 'accepted' in line.lower():
                password_info['result'] = 'success'

            # Extract port information
            port_match = re.search(r'port (\d+)', line)
            if port_match:
                password_info['port'] = port_match.group(1)

            return password_info

        except Exception as e:
            logger.error(f"Error extracting password info: {e}")
            return {}

    def log_ssh_event(self, source_ip, username, event_type, raw_line, password_info=None):
        """Log SSH event to file"""
        try:
            event_data = {
                'timestamp': datetime.now().isoformat(),
                'source_ip': source_ip,
                'username': username,
                'event_type': event_type,
                'raw_log': raw_line,
                'password_info': password_info or {},
                'fake_activity': {
                    'triggered': True,
                    'source_ip': source_ip,
                    'username': username,
                    'event_type': event_type,
                    'timestamp': datetime.now().isoformat()
                }
            }

            # Write to JSON log file
            with open('/app/logs/ssh_connections.json', 'a') as f:
                f.write(json.dumps(event_data) + '\n')

        except Exception as e:
            logger.error(f"Error logging SSH event: {e}")


def main():
    """Main function"""
    monitor = RealSSHMonitor()
    monitor.start()


if __name__ == "__main__":
    main()
