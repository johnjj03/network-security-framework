import pyshark
import matplotlib.pyplot as plt
from collections import Counter

# Load pcap file
cap = pyshark.FileCapture(r'C:\Users\johng\Documents\College\Capstone\Framework\uploads\pkt.TCP.synflood.spoofed.pcap')

# Initialize a Counter for packet timestamps
timestamps = Counter()

# Iterate over packets and count them by timestamp
for packet in cap:
    timestamps[packet.sniff_time.timestamp()] += 1

# Sort timestamps and packet counts
times, counts = zip(*sorted(timestamps.items()))

# Calculate packet rates
rates = [count / ((times[i+1] - times[i]) or 1) for i, count in enumerate(counts[:-1])]

# Plot packet rates over time
plt.plot(times[:-1], rates)
plt.xlabel('Time (s)')
plt.ylabel('Rate of packets (packets/s)')
plt.show()