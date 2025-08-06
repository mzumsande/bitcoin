import time
import json
import requests

RPC_USER = "martin"      # <-- Set this
RPC_PASSWORD = "test"  # <-- Set this
RPC_PORT = 8332                # Default RPC port
RPC_HOST = "127.0.0.1"

IP_FILE = "ipv4_list_0730.txt"
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
    with open(IP_FILE, 'r') as f:
        ips = [line.strip() for line in f if line.strip()]

    print(f"Connecting to {len(ips)} nodes...")
    connect_nodes(ips)

if __name__ == "__main__":
    main()
