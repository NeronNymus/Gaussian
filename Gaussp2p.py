#!/usr/bin/env python3

import sys
import time
import socket
import ipaddress
import netifaces
import threading
from concurrent.futures import ThreadPoolExecutor
from utils.colors import Colors

# Global variables
active_nodes = set()
active_nodes_lock = threading.Lock()  # Thread-safe access to active_nodes
private_ip = None

def get_private_ip():
    """Get the private IP address of the current machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        private_ip = s.getsockname()[0]
        s.close()
    except Exception as e:
        print(f"Error occurred: {e}")
        private_ip = None
    return private_ip

private_ip = get_private_ip()

def get_subnet_mask(ip):
    """Get the subnet mask for the given IP address."""
    interfaces = netifaces.interfaces()
    for interface in interfaces:
        addrs = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addrs:
            for link in addrs[netifaces.AF_INET]:
                if link['addr'] == ip:
                    return link.get('netmask', None)
    return None

def get_ip_range_cidr(private_ip):
    """Get the IP network range in CIDR notation."""
    subnet_mask = get_subnet_mask(private_ip)
    if subnet_mask is None:
        print("Could not determine subnet mask.")
        return None
    
    network = ipaddress.ip_network(f"{private_ip}/{subnet_mask}", strict=False)
    return network

def scan_host(ip, port):
    """Scan a single host on the specified port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((str(ip), port))
            if result == 0:
                print(f"{Colors.GREEN}[+] {ip}:{port} is open{Colors.R}")
                with active_nodes_lock:
                    active_nodes.add(ip)
    except Exception as e:
        print(f"Error scanning {ip}:{port} - {e}")

def scan_network(network, port=65300):
    """Scan the entire network for active hosts on the specified port."""
    print(Colors.ORANGE + "[!] Scanning hosts on " + Colors.BOLD_WHITE + str(network) + Colors.ORANGE + " on port " + Colors.BOLD_WHITE + str(port) + Colors.R + "...\n")
    ip_network = ipaddress.ip_network(network, strict=False)
    
    with ThreadPoolExecutor(max_workers=100) as executor:
        for ip in ip_network.hosts():
            executor.submit(scan_host, ip, port)

def scan_private_network(port=65300):
    """Scan the private network for active nodes."""
    global private_ip
    if private_ip:
        network = get_ip_range_cidr(private_ip)
        if network:
            scan_network(network, port)

def listen_for_connections(port=65300):
    """Listen for incoming TCP connections on the specified port."""
    global private_ip

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind(('', port))
        server_socket.listen()
        print(Colors.PURPLE + f"[+] Listening for connections on port {port}..." + Colors.R)

        while True:
            conn, addr = server_socket.accept()
            ip = addr[0]
            if ip == private_ip:
                with active_nodes_lock:
                    active_nodes.add(private_ip)
                conn.close()
                continue
            
            print(Colors.PURPLE + f"[+] Connection from {addr}" + Colors.R)
            threading.Thread(target=handle_client, args=(conn,)).start()

def handle_client(conn):
    """Handle an incoming client connection."""
    global private_ip
    with conn:
        conn.settimeout(5)
        try:
            while True:
                data = conn.recv(1024)
                if not data:
                    print("No data received; closing connection.")
                    break

                print(f"Received: {data.decode()}")
                response = f"Message sent from {private_ip}".encode()
                conn.sendall(response)
        except (ConnectionResetError, socket.timeout, BrokenPipeError) as e:
            print(f"Client connection error: {e}")
        finally:
            print("Client connection closed.")

def try_connection_to_node(ip, port):
    """Attempt to connect to a node and send data."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ip, port))
            print(f"Connected to {ip}")
            # Send a message
            message = f"Hello from {private_ip}".encode()
            s.sendall(message)
            print("Message sent!")
    except Exception as e:
        print(f"Could not connect to {ip}:{port} - {e}")

def decide_roles_and_connect():
    """Decide roles and connect to another node."""
    global active_nodes
    with active_nodes_lock:
        if len(active_nodes) > 1:  # At least two active nodes
            nodes_list = list(active_nodes)
            node_to_connect = nodes_list[1]  # Get the next node

            # Randomly choose role: client or server
            if hash(private_ip) % 2 == 0:  # Simple even/odd decision
                # Act as a client
                try_connection_to_node(node_to_connect, 65300)
            else:
                # Act as a server
                listen_for_connections(65300)

if __name__ == "__main__":
    # Start network scanning and listening in separate threads
    threading.Thread(target=scan_private_network, args=(65300,), daemon=True).start()
    threading.Thread(target=listen_for_connections, args=(65300,), daemon=True).start()

    cont = 1
    try:
        while True:
            time.sleep(10)  # Scan every 10 seconds
            scan_private_network(65300)

            print(Colors.BOLD_WHITE + f"\n[{cont}] " + Colors.BOLD_WHITE + f"Active nodes:" + Colors.R)
            cont += 1

            with active_nodes_lock:
                node_cont = 1
                for node in active_nodes:
                    print(Colors.ORANGE + f"[{node_cont}] " + Colors.GREEN + str(node) + Colors.R)
                    node_cont += 1
            
            # Decide roles and connect
            decide_roles_and_connect()
    except KeyboardInterrupt:
        print("\nShutting down...")
