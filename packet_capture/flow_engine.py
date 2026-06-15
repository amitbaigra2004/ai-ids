
import time
import queue
import threading
from scapy.all import IP, TCP, UDP


from packet_capture.sniffer import packet_queue

flow_output_queue = queue.Queue()

# how long with no packets before a flow is considered complete
FLOW_TIMEOUT = 30  # seconds


class Flow:
   

    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
       
        self.src_ip   = src_ip
        self.dst_ip   = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol

       
        self.start_time = time.time()
        self.last_seen  = time.time()
       
        self.packet_count = 0
        self.byte_count   = 0

       
        self.syn_count = 0
        self.ack_count = 0
        self.fin_count = 0
        self.rst_count = 0
        self.psh_count = 0
        self.urg_count = 0

    def update(self, packet):
        
        self.packet_count += 1
        self.byte_count   += len(packet)
        self.last_seen     = time.time()

        # update TCP flag counts if this is a TCP packet
        if packet.haslayer(TCP):
            flags = str(packet[TCP].flags)
            if "S" in flags: self.syn_count += 1
            if "A" in flags: self.ack_count += 1
            if "F" in flags: self.fin_count += 1
            if "R" in flags: self.rst_count += 1
            if "P" in flags: self.psh_count += 1
            if "U" in flags: self.urg_count += 1

    def is_timed_out(self):
       
        return (time.time() - self.last_seen) > FLOW_TIMEOUT

    def to_dict(self):
        
        duration  = max(self.last_seen - self.start_time, 0.001)
        pkt_count = max(self.packet_count, 1)

        return {
            
            "src_ip":            self.src_ip,
            "dst_ip":            self.dst_ip,
            "src_port":          self.src_port,
            "dst_port":          self.dst_port,
            "protocol":          self.protocol,

            
            "duration":          round(duration, 4),

            "packet_count":      self.packet_count,
            "byte_count":        self.byte_count,

         
            "syn_count":         self.syn_count,
            "ack_count":         self.ack_count,
            "fin_count":         self.fin_count,
            "rst_count":         self.rst_count,

         
            "avg_packet_size":   round(self.byte_count / pkt_count, 2),
            "packets_per_second":round(self.packet_count / duration, 2),
            "bytes_per_second":  round(self.byte_count / duration, 2),
            "syn_ratio":         round(self.syn_count / pkt_count, 4),
            "rst_ratio":         round(self.rst_count / pkt_count, 4),
        }


class FlowEngine:
   

    def __init__(self):
        self.flows   = {}              # flow table: key → Flow
        self.lock    = threading.Lock()
        self.running = False

        # statistics
        self.total_flows_seen      = 0
        self.total_flows_completed = 0

    def _get_flow_key(self, packet):
        
        if not packet.haslayer(IP):
            return None

        src_ip   = packet[IP].src
        dst_ip   = packet[IP].dst
        protocol = packet[IP].proto

        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            src_port = 0
            dst_port = 0

        return (src_ip, dst_ip, src_port, dst_port, protocol)

    def _process_packet(self, packet):
        
        key = self._get_flow_key(packet)
        if key is None:
            return

        src_ip, dst_ip, src_port, dst_port, proto = key

        with self.lock:
            if key not in self.flows:
                # first packet of a new flow
                self.flows[key] = Flow(
                    src_ip, dst_ip,
                    src_port, dst_port,
                    proto
                )
                self.total_flows_seen += 1

            # update flow with this packet
            self.flows[key].update(packet)

    def _consume_packets(self):
       
        print("[*] Packet consumer thread started.")
        while self.running:
            try:
                packet = packet_queue.get(timeout=1)
                self._process_packet(packet)
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[!] Consumer error: {e}")

    def _check_timeouts(self):
       
        print("[*] Timeout checker thread started.")
        while self.running:
            time.sleep(1)  # check every second
            completed = []

            with self.lock:
                for key, flow in list(self.flows.items()):
                    if flow.is_timed_out():
                        completed.append(flow.to_dict())
                        del self.flows[key]
                        self.total_flows_completed += 1

            
            for flow_dict in completed:
                flow_output_queue.put(flow_dict)
                self._print_flow(flow_dict)

    def _print_flow(self, flow):
        """Print a completed flow summary to terminal."""
        print(
            f"\n[FLOW COMPLETE] "
            f"{flow['src_ip']}:{flow['src_port']} → "
            f"{flow['dst_ip']}:{flow['dst_port']} | "
            f"Pkts: {flow['packet_count']:<6} | "
            f"Bytes: {flow['byte_count']:<8} | "
            f"Duration: {flow['duration']}s | "
            f"PPS: {flow['packets_per_second']:<8} | "
            f"SYN ratio: {flow['syn_ratio']}"
        )

    def get_stats(self):
        """Return current engine statistics."""
        with self.lock:
            active = len(self.flows)
        return {
            "active_flows":     active,
            "total_seen":       self.total_flows_seen,
            "total_completed":  self.total_flows_completed,
        }

    def start(self):
        """Start both background threads."""
        self.running = True

        t1 = threading.Thread(
            target=self._consume_packets,
            name="packet-consumer",
            daemon=True   # dies when main program exits
        )
        t2 = threading.Thread(
            target=self._check_timeouts,
            name="timeout-checker",
            daemon=True
        )

        t1.start()
        t2.start()
        print("[*] Flow engine started.")
        print(f"[*] Flow timeout: {FLOW_TIMEOUT} seconds")
        return t1, t2

    def stop(self):
        self.running = False
        print("[*] Flow engine stopped.")
