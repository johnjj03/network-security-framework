import dpkt
import socket
from collections import defaultdict
import sys

def print_pcap_info(pcap):
    """
    Print out information about each packet in a pcap
    """
    for timestamp, buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            protocol = ip.p
            print(f"Source: {src} --> Destination: {dst}, Protocol: {protocol}")
        except:
            pass

def detect_dos(pcap):
    """
    Detect potential DoS attack based on packet time differences and common DDoS rules
    """
    ip_packet_times = defaultdict(list)
    window_size = 10 
    threshold_time_diff = 0.01
    packet_rate_threshold = 5  

    unique_src_ips = set()
    

    for timestamp, buf in pcap:
        try:

            eth = dpkt.ethernet.Ethernet(buf)

            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                src = socket.inet_ntoa(ip.src)
                protocol = ip.p

                ip_packet_times[src].append(timestamp)
                unique_src_ips.add(src)

            # Check for high packet rate
                if len(ip_packet_times[src]) > packet_rate_threshold:
                    start_time = ip_packet_times[src][0]
                    end_time = ip_packet_times[src][-1]
                    time_diff = end_time - start_time

                    if time_diff <= threshold_time_diff:
                        # print(f"High Packet Rate from IP: {src} (protocol: {protocol}, time diff: {time_diff} sec)")
                        return f"High Packet Rate from IP: {src} (protocol: {protocol}, time diff: {time_diff} sec)"

                if len(ip_packet_times[src]) > window_size:
                    ip_packet_times[src] = ip_packet_times[src][1:]

        except Exception as e:
            return f"Error: {e}"
    return "No DoS detected"

def detect_ddos(pcap):

    unique_src_ips = set()
    random_ips_threshold = 5  

    for timestamp , buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            unique_src_ips.add(src)
            if len(unique_src_ips) >= random_ips_threshold:
                # print(f"Suspicious Traffic from Multiple IPs: {list(unique_src_ips)}")
                return f"Suspicious Traffic from Multiple IPs: {list(unique_src_ips)}"
        except Exception as e:
            return f"Error: {e}"
    return "No DDoS detected"

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python analysis.py <pcap_file>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    with open(file_path, "rb") as f:
        pcap = dpkt.pcap.Reader(f)
        print(f"Analyzing pcap file: {file_path}")
        print(detect_dos(pcap))
        print(detect_ddos(pcap))

    # pcap_file = "pkt.UDP.null.pcapng"
    # with open(pcap_file, "rb") as f:
    #     pcap = dpkt.pcap.Reader(f)
