import subprocess
import signal
import sys
import os
import time
import pyshark
import requests
from datetime import datetime
from queue import Queue, Empty
import threading

# Path to the pcap file
PCAP_PATH = "/var/log/agent/traffic.pcap"
# The interface to monitor
INTERFACE = "eth0"
# Backend URL
BACKEND_URL = "http://localhost:4000/api/logs"

# Session threshold for example
SESSION_PACKET_THRESHOLD = 10
# Batching interval
BATCH_SEND_INTERVAL = 10
# Batching size
BATCH_SIZE = 5

# In-memory sessions (key: ( (src_ip, src_port), (dst_ip, dst_port), protocol ))
active_sessions = {}
session_queue = Queue()

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
            "Class": "Unknown"  # or do further classification
        }

    def is_complete(self):
        return self.packets >= SESSION_PACKET_THRESHOLD

def process_packet(packet):
    """
    Parse relevant fields from the PyShark packet and build session data.
    """
    try:
        if 'ip' not in packet:
            return

        # protocol_layer might be 'tcp', 'udp', etc.
        protocol_layer = packet.transport_layer
        if not protocol_layer:
            return  # might be something else like ARP, skip

        protocol = protocol_layer.upper()  # 'TCP', 'UDP'
        layer = getattr(packet, protocol.lower(), None)
        if not layer or not hasattr(layer, 'srcport') or not hasattr(layer, 'dstport'):
            return

        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        src_port = layer.srcport
        dst_port = layer.dstport

        # Approx packet size
        size_bytes = len(packet)

        # Attempt to parse flags if available (for TCP)
        flags = []
        if protocol == "TCP" and hasattr(packet.tcp, 'flags_show'):
            # e.g. "SYN, ACK"
            flag_str = packet.tcp.flags_show
            flags = [f.strip() for f in flag_str.split(',')]

        timestamp = packet.sniff_time  # a datetime object

        # Build session key
        endpoints = sorted([(src_ip, src_port), (dst_ip, dst_port)])
        session_key = (endpoints[0], endpoints[1], protocol)

        if session_key not in active_sessions:
            active_sessions[session_key] = SessionData(session_key)

        session = active_sessions[session_key]
        session.add_packet(timestamp, size_bytes, flags)

        if session.is_complete():
            session_queue.put(session.to_dict())
            del active_sessions[session_key]

    except Exception as e:
        print(f"Error processing packet: {e}")

def send_batches():
    """
    Send session data to the backend in batches.
    """
    while True:
        time.sleep(BATCH_SEND_INTERVAL)
        batch = []
        for _ in range(BATCH_SIZE):
            try:
                session_data = session_queue.get_nowait()
                batch.append(session_data)
            except Empty:
                break

        for session_dict in batch:
            try:
                r = requests.post(BACKEND_URL, json=session_dict)
                if r.status_code == 200:
                    print(f"Sent session to backend: {session_dict}")
                else:
                    print(f"Failed to send session: {r.status_code}")
            except Exception as e:
                print(f"Exception sending session: {e}")

def start_tcpdump():
    """
    Launch tcpdump as a subprocess that writes to PCAP_PATH.
    We'll kill it when script ends.
    """
    print(f"Starting tcpdump on interface {INTERFACE}, writing to {PCAP_PATH}")
    # Make sure directory exists
    os.makedirs(os.path.dirname(PCAP_PATH), exist_ok=True)

    # Start tcpdump
    p = subprocess.Popen(
        ["sudo", "tcpdump", "-i", INTERFACE, "-w", PCAP_PATH],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    return p

def tail_pcap():
    """
    Tails the PCAP file using PyShark and processes packets in real-time.
    """
    print(f"Tailing pcap file: {PCAP_PATH}")
    capture = pyshark.FileCapture(
        PCAP_PATH,
        keep_packets=False,
        tail=True
    )

    try:
        for packet in capture:
            process_packet(packet)
    except Exception as e:
        print(f"Error in capture loop: {e}")
    finally:
        capture.close()

def cleanup(p):
    """
    Cleanup function to kill tcpdump on exit.
    """
    print("Cleaning up, stopping tcpdump...")
    p.terminate()
    try:
        p.wait(timeout=2)
    except subprocess.TimeoutExpired:
        p.kill()
    print("tcpdump stopped.")

def main():
    # 1. Start tcpdump
    tcpdump_proc = start_tcpdump()

    # 2. Give tcpdump a second to initialize
    time.sleep(2)

    # 3. Start background thread for sending session batches
    t = threading.Thread(target=send_batches, daemon=True)
    t.start()

    # 4. Start tailing the PCAP with PyShark
    try:
        tail_pcap()
    except KeyboardInterrupt:
        print("KeyboardInterrupt detected. Exiting...")
    finally:
        cleanup(tcpdump_proc)

if __name__ == "__main__":
    main()
