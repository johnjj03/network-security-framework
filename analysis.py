from scapy.all import rdpcap
from scapy.layers.inet import IP
from collections import defaultdict
import sys

def print_pcap_info(packets):
    """
    Print out information about each packet in a pcap
    """
    for packet in packets:
        try:
            src = packet[IP].src
            dst = packet[IP].dst
            protocol = packet[IP].proto
            print(f"Source: {src} --> Destination: {dst}, Protocol: {protocol}")
        except:
            pass

def detect_dos(packets):
    """
    Detect potential DoS attack based on packet time differences and common DDoS rules
    """
    ip_packet_times = defaultdict(list)
    window_size = 10 
    threshold_time_diff = 0.01
    packet_rate_threshold = 5  

    for packet in packets:
        try:
            if IP in packet:
                src = packet[IP].src
                protocol = packet[IP].proto
                timestamp = packet.time

                ip_packet_times[src].append(timestamp)

                # Check for high packet rate
                if len(ip_packet_times[src]) > packet_rate_threshold:
                    start_time = ip_packet_times[src][0]
                    end_time = ip_packet_times[src][-1]
                    time_diff = end_time - start_time

                    if time_diff <= threshold_time_diff:
                        return f"High Packet Rate from IP: {src} (protocol: {protocol}, time diff: {time_diff} sec)"

                if len(ip_packet_times[src]) > window_size:
                    ip_packet_times[src] = ip_packet_times[src][1:]

        except Exception as e:
            return f"Error: {e}"
    return "No DoS detected"

def detect_ddos(packets):
    unique_src_ips = set()
    random_ips_threshold = 5  

    for packet in packets:
        try:
            if IP in packet:
                src = packet[IP].src
                unique_src_ips.add(src)
                if len(unique_src_ips) >= random_ips_threshold:
                    return f"Suspicious Traffic from Multiple IPs: {list(unique_src_ips)}"
        except Exception as e:
            return f"Error: {e}"
    return "No DDoS detected"

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python analysis.py <pcap_file>")
        sys.exit(1)
    else:
        file_path = sys.argv[1]
        packets = rdpcap(file_path)
        print(f"Analyzing pcap file: {file_path}")
        detect_dos(packets)
        detect_ddos(packets)