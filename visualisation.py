import pyshark
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')
import asyncio
import os
from collections import deque
import time
import sys


GRAPH_FOLDER = r'.\static\graphs'

# Load pcap file
def plot_packet_rate(file_name):
    asyncio.set_event_loop(asyncio.new_event_loop())
    cap = pyshark.FileCapture(file_name, use_json=True, include_raw=True)

    # Initialize a deque for packet timestamps
    timestamps = deque(maxlen=1000)

    # Initialize a deque for packet counts
    counts = deque(maxlen=1000)

    # Iterate over packets and count them by timestamp
    for packet in cap:
        timestamp = packet.sniff_time.timestamp()
        if timestamps and timestamp == timestamps[-1]:
            counts[-1] += 1
        else:
            timestamps.append(timestamp)
            counts.append(1)

    # Convert deques to lists for slicing
    timestamps = list(timestamps)
    counts = list(counts)

    # Calculate packet rates
    rates = []
    for i, count in enumerate(counts[:-1]):
        time_diff = timestamps[i+1] - timestamps[i]
        if time_diff > 0:
            rate = count / time_diff
        else:
            rate = 0  # Avoid negative or zero time difference
        rates.append(rate)

    # Plot packet rates over time
    plt.plot(timestamps[:-1], rates)
    plt.xlabel('Time (s)')
    plt.ylabel('Rate of packets (packets/s)')
    
    # Save the plot as an image file
    graph_filename = os.path.basename(file_name) + '.png'
    graph_path = os.path.join(GRAPH_FOLDER, graph_filename)
    plt.savefig(graph_path)
    while not os.path.exists(graph_path):
        time.sleep(0.1)
    plt.close()

    return graph_path


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python visualisation.py <pcap_file>")
        sys.exit(1)
    else:
        file_name = sys.argv[1]
        plot_packet_rate(file_name)