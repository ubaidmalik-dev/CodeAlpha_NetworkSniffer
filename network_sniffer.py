"""
Basic Network Sniffer - Task 1
Requirements:
  - Python 3.8+
  - scapy (install with: pip install scapy)
Notes:
  - Running this script requires elevated privileges (root / administrator).
  - On Windows, run from an elevated PowerShell. On Linux/macOS, run with sudo.
  - Use responsibly and only on networks you own or have permission to test.

Features:
  - Captures packets in real-time.
  - Prints timestamp, source IP, destination IP, protocol, and payload snippet.
  - Optional filter: BPF style (e.g., "tcp", "udp", "ip", "icmp6", "port 80")
"""

from scapy.all import sniff, Raw
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6Unknown
import argparse
import datetime
import sys

def packet_summary(pkt):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    src = dst = proto = payload = "-"
    # IPv4
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        if TCP in pkt:
            proto = "TCP/%d" % pkt[TCP].sport
        elif UDP in pkt:
            proto = "UDP/%d" % pkt[UDP].sport
        elif ICMP in pkt:
            proto = "ICMP"
    # IPv6
    elif IPv6 in pkt:
        src = pkt[IPv6].src
        dst = pkt[IPv6].dst
        if TCP in pkt:
            proto = "TCP/%d" % pkt[TCP].sport
        elif UDP in pkt:
            proto = "UDP/%d" % pkt[UDP].sport
        elif ICMPv6Unknown in pkt:
            proto = "ICMPv6"
        else:
            proto = "IPv6"
    else:
        # fallback to layer summary
        proto = pkt.summary()
    if Raw in pkt:
        raw = bytes(pkt[Raw].load)
        # show printable part of payload (first 80 bytes)
        try:
            payload = raw[:80].decode('utf-8', errors='replace')
        except Exception:
            payload = str(raw[:80])
    print(f"[{ts}] {src:40} -> {dst:40} | {proto:12} | {payload}")

def main():
    parser = argparse.ArgumentParser(description="Basic Network Sniffer (Task 1)")
    parser.add_argument("-i", "--iface", help="Network interface to sniff (optional)", default=None)
    parser.add_argument("-f", "--filter", help="BPF filter (e.g. 'tcp', 'udp', 'port 80')", default=None)
    parser.add_argument("-c", "--count", help="Number of packets to capture (default: infinite)", type=int, default=0)
    args = parser.parse_args()

    print("Starting sniffer. Press Ctrl+C to stop.")
    try:
        sniff(iface=args.iface, filter=args.filter, prn=packet_summary, store=False, count=args.count or 0)
    except PermissionError:
        print("Permission denied: run with elevated privileges (sudo / Administrator).")
        sys.exit(1)
    except Exception as e:
        print("Error while sniffing:", e)
        sys.exit(1)

if __name__ == "__main__":
    main()

