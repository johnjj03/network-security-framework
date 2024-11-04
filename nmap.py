import os
import subprocess
import json
from scapy.all import rdpcap, IP
import xmltodict

def perform_nmap_scan(target_file_path):
    # Build the nmap command to read targets from the file and find up hosts
    cmd = f'nmap -iL "{target_file_path}" -oG"'

    # Run the command
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if result.returncode != 0 and result.returncode != 1:
        return {'error': result.stderr}

    # Process the output to get up hosts
    up_hosts = []
    for line in result.stdout.splitlines():
        if 'Up' in line:
            parts = line.strip().split()
            if len(parts) >= 2 and parts[0] == 'Host:':
                ip_address = parts[1]
                up_hosts.append(ip_address)

    return {'up_hosts': up_hosts}

def xml_to_json():
    with open('./static/vuln_scan_results.xml', 'r') as xml_file:
        xml_content = xml_file.read()
    dict_data = xmltodict.parse(xml_content)
    return dict_data

def extract_useful_info(nmap_data):
    useful_info = {}

    # Extract host information
    if 'host' in nmap_data['nmaprun']:
        host_info = nmap_data['nmaprun']['host']
        useful_info['host'] = {
            'address': host_info['address']['@addr'],
            'hostnames': host_info.get('hostnames', {}),
            'status': host_info['status'],
        }

    # Extract run statistics
    if 'runstats' in nmap_data['nmaprun']:
        useful_info['runstats'] = nmap_data['nmaprun']['runstats']

    return useful_info

def extract_addresses_and_ports(file_path):
    # Read the pcap file and extract addresses and ports
    packets = rdpcap(file_path)
    addresses = set()

    for packet in packets:
        if IP in packet:
            ip_layer = packet[IP]
            addresses.add(ip_layer.src)
            addresses.add(ip_layer.dst)

    # Write the addresses to a text file in the static folder
    target_file_path = os.path.join('static', 'ip_list.txt')
    with open(target_file_path, 'w') as f:
        for address in addresses:
            f.write(address + '\n')

    # nmap_results = perform_nmap_scan(target_file_path)

    # return json.dumps(nmap_results, indent=4)

    data = extract_useful_info(xml_to_json())
    print(data)
    return json.dumps(data, indent=4)

