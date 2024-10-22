#!/usr/bin/env python3

# This is a P2P script that works on the LAN

import sys
import time
import socket
import ipaddress
import netifaces
import threading
from concurrent.futures import ThreadPoolExecutor

# Add parent directory to sys.path for personal packages
from utils.colors import Colors

# Current list of active nodes
active_nodes = set()

def get_private_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        private_ip = s.getsockname()[0]
        s.close()
    except Exception as e:
        print(f"Error occurred: {e}")
        private_ip = None
    return private_ip

# Global variable
private_ip = get_private_ip()

def get_subnet_mask(ip):
    interfaces = netifaces.interfaces()
    for interface in interfaces:
        addrs = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addrs:
            for link in addrs[netifaces.AF_INET]:
                if link['addr'] == ip:
                    return link.get('netmask', None)
    return None


def get_ip_range_cidr(private_ip):
    subnet_mask = get_subnet_mask(private_ip)
    if subnet_mask is None:
        print("Could not determine subnet mask.")
        return None
    
    network = ipaddress.ip_network(f"{private_ip}/{subnet_mask}", strict=False)
    return network


def scan_host(ip, port):
    """Attempt to connect to the specified IP on the given port."""
    global active_nodes
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((str(ip), port))
            if result == 0:
                active_nodes.add(ip)

    except Exception as e:
        print(f"Error scanning {ip}:{port} - {e}")


def scan_network(network, port=65300):
    """Scan the specified network for hosts with the given port open."""

    print(Colors.ORANGE + "[!] Scanning hosts on " + Colors.BOLD_WHITE + str(network) + Colors.ORANGE + " on port " + Colors.BOLD_WHITE + str(port) + Colors.R + "...\n")
    active_nodes.clear()    # Refresh the content
    
    ip_network = ipaddress.ip_network(network, strict=False)
    
    with ThreadPoolExecutor(max_workers=100) as executor:
        for ip in ip_network.hosts():
            executor.submit(scan_host, ip, port)


def scan_private_network(port=65300):
    global private_ip
    
    if private_ip:
        network = get_ip_range_cidr(private_ip)
        if network:
            scan_network(network, port)


def listen_for_connections(port=65300):
    """Listen for incoming connections on the specified port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind(('', port))
        server_socket.listen()
        print(Colors.GREEN + f"[+] Listening for connections on port {port}..." + Colors.R)

        while True:
            conn, addr = server_socket.accept()
            print(Colors.PURPLE + f"[+] Connection from {addr}" + Colors.R)
            threading.Thread(target=handle_client, args=(conn,)).start()  # Handle client in a new thread


def handle_client(conn):
    """Handle communication with a connected client."""
    global private_ip

    with conn:
        while True:
            data = conn.recv(1024)
            if not data:
                break  # Break the loop if no data is received

            print(f"Received: {data.decode()}")  # Print the received message

            # Optionally send a response
            response = f"Message sended from {private_ip}".encode()
            conn.sendall(response)


if __name__ == "__main__":
    # Start listening for connections in a separate thread
    threading.Thread(target=listen_for_connections, args=(65300,), daemon=True).start()

    # Scan for active nodes every 20 seconds
    cont = 1
    while True:
        time.sleep(20)
        scan_private_network(65300)

        print(Colors.ORANGE + f"\n[{cont}] " + Colors.BOLD_WHITE + f"Active nodes:" + Colors.R)

        node_cont = 1
        for node in active_nodes:
            print(Colors.ORANGE + f"[{node_cont}] " + Colors.GREEN + str(node) + Colors.R)
            node_cont += 1

