import json
import random
import re
import sys

# Check if JSON file argument is provided
if len(sys.argv) != 2:
    print("Usage: python convert.py <json_file>")
    sys.exit(1)

json_file = sys.argv[1]

# Load JSON from the specified file
try:
    with open(json_file, 'r') as f:
        data = json.load(f)
except FileNotFoundError:
    print(f"Error: File '{json_file}' not found.")
    sys.exit(1)
except json.JSONDecodeError:
    print(f"Error: '{json_file}' is not a valid JSON file.")
    sys.exit(1)

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
output_file = 'ipv4_list.txt'
with open(output_file, 'w') as out_file:
    for entry in ipv4_with_port_list:
        out_file.write(entry + '\n')

print(f"Extracted and saved {len(ipv4_with_port_list)} IPv4:port entries to {output_file}")
