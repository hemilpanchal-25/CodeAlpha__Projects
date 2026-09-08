#!/usr/bin/env python3
"""
Basic Network Sniffer using Scapy
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import logging

# Hide Scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def packet_callback(packet):
    """Process each captured packet safely."""

    try:
        if not packet.haslayer(IP):
            return

        ip = packet[IP]

        src_ip = ip.src
        dst_ip = ip.dst

        protocol_map = {
            1: "ICMP",
            6: "TCP",
            17: "UDP"
        }

        protocol = protocol_map.get(ip.proto, f"OTHER ({ip.proto})")

        transport = "N/A"
        payload = ""

        # ---------------- TCP ----------------
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            transport = (
                f"TCP | Src Port: {tcp.sport} | "
                f"Dst Port: {tcp.dport} | "
                f"Flags: {tcp.flags}"
            )

        # ---------------- UDP ----------------
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            transport = (
                f"UDP | Src Port: {udp.sport} | "
                f"Dst Port: {udp.dport}"
            )

        # ---------------- ICMP ----------------
        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            transport = (
                f"ICMP | Type: {icmp.type} | Code: {icmp.code}"
            )

        # ---------------- Payload ----------------
        if packet.haslayer(Raw):
            raw_data = packet[Raw].load

            try:
                payload = raw_data.decode(
                    "utf-8",
                    errors="replace"
                )[:100]
            except Exception:
                payload = raw_data.hex()[:100]

        # ---------------- Output ----------------
        print("=" * 60)
        print(f"Source IP      : {src_ip}")
        print(f"Destination IP : {dst_ip}")
        print(f"Protocol       : {protocol}")
        print(f"Transport      : {transport}")

        if payload:
            print(f"Payload        : {payload}")

    except Exception as e:
        print(f"[ERROR] {e}")


def main():
    print("[*] Starting Network Sniffer...")
    print("[*] Press Ctrl+C to stop.\n")

    try:
        sniff(
            prn=packet_callback,
            store=False,
            filter="ip"
        )

    except KeyboardInterrupt:
        print("\n[*] Sniffer stopped.")

    except Exception as e:
        print(f"[ERROR] {e}")


if __name__ == "__main__":
    main()