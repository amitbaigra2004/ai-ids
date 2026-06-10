from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import queue
import threading

# ─────────────────────────────────────────────
# SHARED QUEUE
# Flow engine (Day 3) will read from this queue
# Sniffer puts every captured packet here
# ─────────────────────────────────────────────
packet_queue = queue.Queue()

# change to wlan0 if you are on wifi
INTERFACE = "wlp0s20f3"

# running counter
packet_count = 0


def get_tcp_flags(flags):
    """
    Convert Scapy TCP flags object to readable string.

    Scapy stores flags as a special FlagValue object.
    We convert it to something human-readable like:
    "SYN" or "SYN+ACK" or "FIN+ACK"

    Why we need this:
    Raw flags object prints as a number or cryptic string
    We need readable names for logs and dashboard
    """
    flag_map = {
        "F": "FIN",   # finish    — closing connection
        "S": "SYN",   # sync      — opening connection
        "R": "RST",   # reset     — forceful kill
        "P": "PSH",   # push      — send data immediately
        "A": "ACK",   # ack       — confirming receipt
        "U": "URG",   # urgent    — priority data
    }
    result = []
    for symbol, name in flag_map.items():
        if symbol in str(flags):
            result.append(name)
    return "+".join(result) if result else "NONE"


def packet_callback(packet):
    """
    Scapy calls this function ONCE for every single packet.

    Two jobs:
    1. Print readable info to terminal
    2. Put packet in queue for flow engine

    Why check haslayer(IP) first:
    Not all ethernet frames have IP headers
    ARP packets, for example, don't
    Accessing packet[IP] on a non-IP packet crashes
    So always check before accessing a layer
    """
    global packet_count
    packet_count += 1

    # skip non-IP packets (ARP etc)
    if not packet.haslayer(IP):
        return

    # ── extract IP layer ──────────────────────
    src_ip   = packet[IP].src    # who sent this packet
    dst_ip   = packet[IP].dst    # who receives this packet
    ttl      = packet[IP].ttl    # hops remaining before discard
    pkt_size = len(packet)       # total size in bytes
    ts       = datetime.now().strftime("%H:%M:%S")

    # ── TCP packet ────────────────────────────
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport   # source port
        dst_port = packet[TCP].dport   # destination port
        flags    = get_tcp_flags(packet[TCP].flags)

        print(
            f"[{ts}] [TCP] "
            f"{src_ip}:{src_port} → {dst_ip}:{dst_port} | "
            f"Flags: {flags:<12} | "
            f"TTL: {ttl:<4} | "
            f"Size: {pkt_size}B"
        )

    # ── UDP packet ────────────────────────────
    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

        print(
            f"[{ts}] [UDP] "
            f"{src_ip}:{src_port} → {dst_ip}:{dst_port} | "
            f"TTL: {ttl:<4} | "
            f"Size: {pkt_size}B"
        )

    # ── other IP protocols (ICMP, IGMP etc) ──
    else:
        proto = packet[IP].proto
        # protocol numbers: 1=ICMP, 2=IGMP, 6=TCP, 17=UDP
        print(
            f"[{ts}] [PROTO:{proto}] "
            f"{src_ip} → {dst_ip} | "
            f"TTL: {ttl:<4} | "
            f"Size: {pkt_size}B"
        )

    # ── put in queue for Day 3 flow engine ───
    # non-blocking put — if queue is full, drop packet
    # better to drop than to block capture
    try:
        packet_queue.put_nowait(packet)
    except queue.Full:
        pass  # drop if queue is full — capture must never block


def start_sniffer(interface=INTERFACE, packet_limit=0):
    """
    Start capturing packets on the given interface.

    Parameters
    interface     — network interface name (wlp0s20f3, wlan0 etc)
    packet_limit  — how many packets to capture (0 = forever)

    sniff() parameters:
    iface  — which network card to listen on
    prn    — callback function called per packet
    store  — False = don't keep packets in memory
    count  — 0 = capture forever
    """
    print("=" * 65)
    print("   AI-IDS Packet Sniffer")
    print(f"   Interface : {interface}")
    print(f"   Started   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("   Press Ctrl+C to stop")
    print("=" * 65)

    try:
        sniff(
            iface=interface,
            prn=packet_callback,
            store=False,
            count=packet_limit
        )
    except KeyboardInterrupt:
        print(f"\n[*] Sniffer stopped.")
        print(f"[*] Total packets captured: {packet_count}")
    except PermissionError:
        print("\n[!] Permission denied.")
        print("[!] Scapy needs root to capture packets.")
        print("[!] Run with: sudo python packet_capture/sniffer.py")
    except OSError as e:
        print(f"\n[!] Interface error: {e}")
        print(f"[!] Check your interface name with: ip a")


if __name__ == "__main__":
    start_sniffer()
