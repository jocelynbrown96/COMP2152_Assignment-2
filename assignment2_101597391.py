"""
Author: <Jocelyn Brown, 101597391>
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports.
"""

import socket
import threading
import sqlite3
import os
import platform
import datetime

print(f"Python Version: {platform.python_version()}")
print(f"Operating System: {os.name}")

# common_ports stores well-known port numbers and their associated services:
common_ports = { 
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}

class NetworkTool:
    def __init__(self, target):
        self.__target = target

# Q3 - Properties: What is the benefit of using @property and @target.setter instead of acessing self.__target directly?
# ---------------------------------------------------------------------------------------------------
# When @property is used, it allows for controlled access to a private attribute.
# This enables internal validation as well as encapsulation, and allows it to behave
# like a normal attribute. Meanwhile, @target.setter permits custom behavior to be executed
# when setting the value, such as validating that the target is not an empty string.
# This helps maintain the integrity of the data and prevents invalid states from being set during assignment.
    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value == "":
            print("Error: Target cannot be empty")
            return
        self.__target = value

    def __del__(self):
        print("NetworkTool instance destroyed")

# Q1 - Inheritance: How does your PortScanner class reuse code from the NetworkTool parent class? Give one specific example.
# ---------------------------------------------------------------------------------------------------
# PortScanner reuses the target property and its validation logic from the NetworkTool class.
# This allows PortScanner to utilize the target property and its validation logic without needing to reimplement it, thus
# improving code reuse and maintainability by harnessing object-oriented programming principles such as inheritance.
class PortScanner(NetworkTool):

    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    def scan_port(self, port):
        sock = None

# Q4 - Exception Handling: What would happen if you removed all try-except blocks 
# from your scan_port method and tried to scan a port on a machine that is not reachable?
# ---------------------------------------------------------------------------------------------------
# Without try-except, any network error would cause the entire program to crash.
# This would prematurely terminate the scanning process and prevent remaining ports from being checked.
# Exception handling ensures that the scanner continues to run even if individual 
# port scans fail, providing a more robust and user-friendly experience overall.
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)

            result = sock.connect_ex((self.target, port))
            status = "Open" if result == 0 else "Closed"
            service_name = common_ports.get(port, "Unknown")

            with self.lock:
                self.scan_results.append((port, status, service_name))

        except socket.error as e:
            print(f"Error scanning port {port}: {e}")

        finally:
            if sock:
                sock.close()

    def get_open_ports(self):
        return [r for r in self.scan_results if r[1] == "Open"]

# Q2 - Threading: Why do we use threading to scan ports instead of scanning them one at a time?
# What would happen if you scanned 1024 ports without threads?
# ---------------------------------------------------------------------------------------------------
# Threading allows for multiple ports to be scanned simultaneously rather than sequentially, 
# which significantly reduces the total scan time, especially when scanning a large range of ports.
# Without threading, scanning each port one at a time would be inefficient and time-consuming.
# Using threads improves performance by running multiple scans in parallel, making the port scanning process much faster overall.
    def scan_range(self, start_port, end_port):
        threads = []

        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(thread)

        for t in threads:
            t.start()

        for t in threads:
            t.join()

def save_results(target, results):
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                port INTEGER,
                status TEXT,
                service TEXT,
                scan_date TEXT
            )
        """)

        for port, status, service in results:
            cursor.execute("""
                INSERT INTO scans (target, port, status, service, scan_date)
                VALUES (?, ?, ?, ?, ?)
            """, (target, port, status, service, str(datetime.datetime.now())))

        conn.commit()
        conn.close()

    except sqlite3.Error as e:
        print(f"Database error: {e}")

def load_past_scans():
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM scans")
        rows = cursor.fetchall()

        for row in rows:
            _, target, port, status, service, scan_date = row
            print(f"[{scan_date}] {target} : Port {port} ({service}) - {status}")

        conn.close()

    except sqlite3.Error:
        print("No past scans found.")

# ============================================================
# MAIN PROGRAM
# ============================================================
if __name__ == "__main__":
    
    target = input("Target IP (default 127.0.0.1): ") or "127.0.0.1"

    try:
        start_port = int(input("Start port (1-1024): "))
        end_port = int(input("End port (1-1024): "))

        if not (1 <= start_port <= 1024 and 1 <= end_port <= 1024):
            print("Port must be between 1 and 1024.")
            exit()

        if end_port < start_port:
            print("End port must be greater than or equal to start port.")
            exit()
    
    except ValueError:
        print("Invalid input. Please enter a valid integer.")
        exit()

    scanner = PortScanner(target)

    print(f"Scanning {target} from port {start_port} to {end_port}...")
    scanner.scan_range(start_port, end_port)
    open_ports = scanner.get_open_ports()
    print(f"--- Scan Results for {target} ---")

    for port, status, service in open_ports:
        print(f"Port {port}: {status} ({service})")

    print("------")
    print(f"Total open ports found: {len(open_ports)}")

    save_results(target, scanner.scan_results)
    choice = input("Would you like to see past scan history? (yes/no): ")

    if choice.lower() == "yes":
        load_past_scans()

# Q5: New Feature Proposal
# ---------------------------------------------------------------------------------------------------
# A useful feature to add to this port scanner would be the ability to detect and highlight high-interest ports such
# as those commonly associated with vulnerabilities (e.g., 22 for SSH, 80 for HTTP, 443 for HTTPS).
# During scanning, a nested if-statement inside the scan_port method would be used to check if a port is open and if it matches 
# one of the known critical ports, then flagging it as high-priority in the scan results.
# This improves readability by assisting users in identifying important ports and makes security-relevant ports easier to recognize in large scan outputs.
# Diagram: See diagram_101597391.png in the repository root.

