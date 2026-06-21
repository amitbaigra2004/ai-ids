
from collections import defaultdict, deque
import time


class RuleEngine:
   

    def __init__(self, window_seconds=10):
        self.window = window_seconds

     
        self.port_history = defaultdict(deque)

       
        self.conn_history = defaultdict(deque)

        self.flow_history = defaultdict(deque)


        self.brute_force_ports = {22, 23, 3389, 21, 5900}

    def _clean_window(self, dq):
       
        cutoff = time.time() - self.window
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    def _check_syn_flood(self, flow):
       
        if flow["packet_count"] < 5:
            return None

        if flow["syn_ratio"] > 0.9 and flow["packets_per_second"] > 1000:
            return "SYN_FLOOD"

        return None

    def _check_port_scan(self, flow, now):
       
        src_ip = flow["src_ip"]
        dst_port = flow["dst_port"]

        self._clean_window(self.port_history[src_ip])
        self.port_history[src_ip].append((now, dst_port))

        unique_ports = len(set(p for _, p in self.port_history[src_ip]))

        if unique_ports > 50:
            return "PORT_SCAN"

        return None

  
    def _check_brute_force(self, flow, now):
     
        src_ip = flow["src_ip"]
        dst_port = flow["dst_port"]

        if dst_port not in self.brute_force_ports:
            return None

        key = (src_ip, dst_port)
        self._clean_window(self.conn_history[key])
        self.conn_history[key].append((now, 1))

        if len(self.conn_history[key]) > 20:
            return "BRUTE_FORCE"

        return None

   
    def _check_connection_burst(self, flow, now):
       
        src_ip = flow["src_ip"]

        self._clean_window(self.flow_history[src_ip])
        self.flow_history[src_ip].append((now, 1))

        if len(self.flow_history[src_ip]) > 100:
            return "CONNECTION_BURST"

        return None

    
    def _check_rst_scan(self, flow):
       
        if flow["packet_count"] < 20:
            return None

        if flow["rst_ratio"] > 0.8:
            return "RST_SCAN"

        return None

    def check(self, flow):
       
        now = time.time()

        result = self._check_syn_flood(flow)
        if result:
            return result

        result = self._check_port_scan(flow, now)
        if result:
            return result

        result = self._check_brute_force(flow, now)
        if result:
            return result

        result = self._check_connection_burst(flow, now)
        if result:
            return result

        result = self._check_rst_scan(flow)
        if result:
            return result

        return "BENIGN"
