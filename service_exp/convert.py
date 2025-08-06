import json
import random
import re

# Load JSON from a file (change path if needed)
with open('nodes_raw_0730.json', 'r') as f:
    data = json.load(f)

# Regex to match IPv4 addresses with ports (e.g. 123.123.123.123:8333)
ipv4_with_port_regex = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}:\d+\b')

# Extract IPv4:port entries from node keys
ipv4_with_port_list = [
    match.group(0)
    for key in data["nodes"].keys()
    if (match := ipv4_with_port_regex.match(key))
]

# Shuffle the list
random.shuffle(ipv4_with_port_list)

# Write to file
with open('ipv4_list_0730.txt', 'w') as out_file:
    for entry in ipv4_with_port_list:
        out_file.write(entry + '\n')

print(f"Extracted and saved {len(ipv4_with_port_list)} IPv4:port entries to ipv4_list.txt")
