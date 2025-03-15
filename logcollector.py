import platform
import pyshark
import time
import threading
import requests
import argparse
import os
import socket
import uuid
import json
from queue import Queue, Empty
from datetime import datetime

# Default configuration
SESSION_PACKET_THRESHOLD = 10
BATCH_SEND_INTERVAL = 10
BATCH_SIZE = 10
DEFAULT_BACKEND_URL = "http://localhost:4000/api/sessions"
HEALTH_CHECK_URL = "http://localhost:4000/api/health"
MAX_RETRIES = 3
RETRY_DELAY = 2  # seconds

active_sessions = {}
session_queue = Queue()

# Generate a unique device ID or load from file if exists
def get_device_id():
    device_id_file = os.path.join(os.path.expanduser("~"), ".snaptrace_device_id")
    
    if os.path.exists(device_id_file):
        try:
            with open(device_id_file, 'r') as f:
                return f.read().strip()
        except:
            pass
    
    # Generate new ID if file doesn't exist or couldn't be read
    device_id = str(uuid.uuid4())
    
    try:
        with open(device_id_file, 'w') as f:
            f.write(device_id)
    except:
        print(f"Warning: Could not save device ID to {device_id_file}")
    
    return device_id

def get_device_info():
    """Collect information about the device running the agent."""
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        os_info = f"{platform.system()} {platform.release()}"
        device_id = get_device_id()
        
        return {
            "device_id": device_id,
            "hostname": hostname,
            "ip_address": ip_address,
            "os": os_info,
            "agent_version": "1.0.0"  # Hardcoded for now, could be dynamic in the future
        }
    except Exception as e:
        print(f"Error collecting device info: {e}")
        return {
            "device_id": get_device_id(),
            "agent_version": "1.0.0"
        }

def check_backend_health(url, api_key=None):
    """Check if the backend server is available."""
    headers = {}
    if api_key:
        headers['Authorization'] = f'Bearer {api_key}'
    
    try:
        health_url = url.replace('/api/sessions', '/api/health')
        response = requests.get(health_url, headers=headers, timeout=5)
        if response.status_code == 200:
            print("Backend server is available")
            return True
        else:
            print(f"Backend server health check failed. Status code: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"Backend server is not available: {e}")
        return False

def get_default_interface():
    """
    Attempts to choose a default interface based on the OS.
    This is a simple guess:
      - macOS => "en0"
      - Linux => "eth0"
    """
    system_name = platform.system().lower()
    if "darwin" in system_name:  # macOS
        return "en0"
    elif "linux" in system_name:
        return "eth0"
    else:
        # If unknown OS, just default to en0 (or raise an error).
        return "en0"

class SessionData:
    def __init__(self, key):
        self.key = key  # ((src_ip, src_port), (dst_ip, dst_port), protocol)
        self.packets = 0
        self.bytes = 0
        self.start_time = None
        self.end_time = None
        self.flags = set()

    def add_packet(self, timestamp, size_bytes, flags):
        self.packets += 1
        self.bytes += size_bytes
        if not self.start_time:
            self.start_time = timestamp
        self.end_time = timestamp
        if flags:
            self.flags.update(flags)

    @property
    def duration(self):
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0

    def to_dict(self):
        (src_ip, src_port), (dst_ip, dst_port), protocol = self.key
        return {
            "Source IP": src_ip,
            "Destination IP": dst_ip,
            "Protocol": protocol,
            "Source Port": src_port,
            "Destination Port": dst_port,
            "Packets": self.packets,
            "Bytes Transferred": f"{self.bytes / (1024 * 1024):.1f}M",
            "Flags": ",".join(self.flags),
            "Duration": self.duration,
            "Class": "Unknown"
        }

    def is_complete(self):
        return self.packets >= SESSION_PACKET_THRESHOLD

def process_packet(packet):
    """Parse relevant fields from PyShark's live capture."""
    try:
        if 'ip' not in packet:
            return

        protocol_layer = packet.transport_layer
        if not protocol_layer:
            return

        protocol = protocol_layer.upper()  # e.g. 'TCP' or 'UDP'
        layer = getattr(packet, protocol.lower(), None)
        if not layer or not hasattr(layer, 'srcport') or not hasattr(layer, 'dstport'):
            return

        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        src_port = layer.srcport
        dst_port = layer.dstport

        size_bytes = len(packet)

        flags = []
        if protocol == "TCP" and hasattr(packet.tcp, 'flags_show'):
            flag_str = packet.tcp.flags_show
            flags = [f.strip() for f in flag_str.split(',')]

        timestamp = packet.sniff_time

        endpoints = sorted([(src_ip, src_port), (dst_ip, dst_port)])
        session_key = (endpoints[0], endpoints[1], protocol)

        if session_key not in active_sessions:
            active_sessions[session_key] = SessionData(session_key)

        session = active_sessions[session_key]
        session.add_packet(timestamp, size_bytes, flags)

        # If we've hit the packet threshold, queue this session for "sending" (printing).
        if session.is_complete():
            session_queue.put(session.to_dict())
            del active_sessions[session_key]

    except Exception as e:
        print(f"Error processing packet: {e}")

def send_batches(backend_url, backend_enabled, api_key=None):
    """Batch sessions and send them to the backend server."""
    device_info = get_device_info()
    print(f"Device info: {json.dumps(device_info, indent=2)}")
    
    while True:
        time.sleep(BATCH_SEND_INTERVAL)
        batch = []
        for _ in range(BATCH_SIZE):
            try:
                session_data = session_queue.get_nowait()
                batch.append(session_data)
            except Empty:
                break

        if not batch:
            continue

        for session_dict in batch:
            print(f"Completed session: {session_dict}")
            
        # Send batch to backend if enabled
        if backend_enabled and batch:
            retries = 0
            success = False
            
            # Prepare headers
            headers = {
                'Content-Type': 'application/json'
            }
            if api_key:
                headers['Authorization'] = f'Bearer {api_key}'
            
            # Prepare payload with metadata
            payload = {
                "device_info": device_info,
                "timestamp": datetime.now().isoformat(),
                "sessions": batch
            }
            
            while retries < MAX_RETRIES and not success:
                try:
                    response = requests.post(backend_url, json=payload, headers=headers)
                    if response.status_code == 200:
                        print(f"Successfully sent {len(batch)} sessions to backend")
                        success = True
                    else:
                        print(f"Failed to send sessions to backend. Status code: {response.status_code}")
                        print(f"Response: {response.text}")
                        retries += 1
                        if retries < MAX_RETRIES:
                            print(f"Retrying in {RETRY_DELAY} seconds... (Attempt {retries+1}/{MAX_RETRIES})")
                            time.sleep(RETRY_DELAY)
                except requests.exceptions.RequestException as e:
                    print(f"Error sending data to backend: {e}")
                    retries += 1
                    if retries < MAX_RETRIES:
                        print(f"Retrying in {RETRY_DELAY} seconds... (Attempt {retries+1}/{MAX_RETRIES})")
                        time.sleep(RETRY_DELAY)
            
            if not success:
                print("Failed to send data after maximum retries")

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Network traffic collector')
    parser.add_argument('--backend-url', default=DEFAULT_BACKEND_URL,
                        help=f'Backend server URL (default: {DEFAULT_BACKEND_URL})')
    parser.add_argument('--disable-backend', action='store_true',
                        help='Disable sending data to backend')
    parser.add_argument('--api-key', default=os.environ.get('SNAPTRACE_API_KEY'),
                        help='API key for backend authentication (can also be set via SNAPTRACE_API_KEY env variable)')
    parser.add_argument('--skip-health-check', action='store_true',
                        help='Skip backend health check on startup')
    args = parser.parse_args()
    
    backend_enabled = not args.disable_backend
    backend_url = args.backend_url
    api_key = args.api_key
    
    if backend_enabled:
        print(f"Backend enabled. Sending data to: {backend_url}")
        if api_key:
            print("API authentication enabled")
        else:
            print("Warning: No API key provided. Authentication disabled.")
        
        # Check backend health if not skipped
        if not args.skip_health_check:
            if not check_backend_health(backend_url, api_key):
                print("Warning: Backend server health check failed. Data will still be collected but may not be sent successfully.")
    else:
        print("Backend disabled. Running in local mode only.")
    
    interface = get_default_interface()
    print(f"Detected OS: {platform.system()}")
    print(f"Using default interface: {interface}")

    # Start background thread to batch completed sessions
    t = threading.Thread(target=send_batches, args=(backend_url, backend_enabled, api_key), daemon=True)
    t.start()

    # Start live capture
    print(f"Starting LiveCapture on interface: {interface}")
    capture = pyshark.LiveCapture(interface=interface)

    try:
        for packet in capture.sniff_continuously():
            process_packet(packet)
    except (KeyboardInterrupt, EOFError):
        print("Exiting gracefully...")
    finally:
        capture.close()

if __name__ == "__main__":
    main()