import time
import json
import requests
import sys

RPC_USER = "martin"      # <-- Set this
RPC_PASSWORD = "test"  # <-- Set this
RPC_PORT = 8332                # Default RPC port
RPC_HOST = "127.0.0.1"

NODES_PER_MINUTE = 30


def rpc_call(method, params=None):
    url = f"http://{RPC_HOST}:{RPC_PORT}"
    headers = {'content-type': 'application/json'}
    payload = {
        "method": method,
        "params": params or [],
        "jsonrpc": "2.0",
        "id": 0,
    }
    response = requests.post(url, data=json.dumps(payload), headers=headers, auth=(RPC_USER, RPC_PASSWORD))
    response.raise_for_status()
    return response.json()

def connect_nodes(ip_list):
    for i, ip in enumerate(ip_list):
        try:
            print(f"[{i+1}/{len(ip_list)}] Connecting to {ip}...")
            rpc_call("addnode", [ip, "onetry"])
        except Exception as e:
            print(f"Error connecting to {ip}: {e}")
        time.sleep(60 / NODES_PER_MINUTE)

def main():
    # Check if input file argument is provided
    if len(sys.argv) != 2:
        print("Usage: python connect.py <ip_file>")
        sys.exit(1)

    ip_file = sys.argv[1]

    try:
        with open(ip_file, 'r') as f:
            ips = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: File '{ip_file}' not found.")
        sys.exit(1)

    print(f"Connecting to {len(ips)} nodes...")
    connect_nodes(ips)

if __name__ == "__main__":
    main()
