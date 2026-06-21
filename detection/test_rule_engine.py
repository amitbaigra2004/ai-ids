"""
Manual test script for the rule engine.
Constructs synthetic flows representing each
attack pattern and confirms detection works.
"""
import time
from rule_engine import RuleEngine


def make_flow(src_ip="10.0.0.99", dst_port=443,
              packet_count=10, syn_ratio=0.1,
              pps=5.0, rst_ratio=0.0):
    return {
        "src_ip": src_ip,
        "dst_port": dst_port,
        "packet_count": packet_count,
        "syn_ratio": syn_ratio,
        "packets_per_second": pps,
        "rst_ratio": rst_ratio,
    }


def test_benign():
    engine = RuleEngine()
    flow = make_flow()  # normal-looking flow
    result = engine.check(flow)
    print(f"Normal traffic        -> {result}  (expect BENIGN)")


def test_syn_flood():
    engine = RuleEngine()
    flow = make_flow(packet_count=500, syn_ratio=0.98, pps=5000.0)
    result = engine.check(flow)
    print(f"SYN flood pattern      -> {result}  (expect SYN_FLOOD)")


def test_syn_flood_false_positive_guard():
    engine = RuleEngine()
    # the exact artifact pattern you saw in real traffic
    flow = make_flow(packet_count=1, syn_ratio=1.0, pps=1000.0)
    result = engine.check(flow)
    print(f"Single packet artifact -> {result}  (expect BENIGN)")


def test_port_scan():
    engine = RuleEngine()
    attacker_ip = "10.0.0.66"
    result = "BENIGN"
    # simulate scanning 60 different ports rapidly
    for port in range(1, 61):
        flow = make_flow(src_ip=attacker_ip, dst_port=port,
                          packet_count=2, syn_ratio=0.5, pps=10.0)
        result = engine.check(flow)
    print(f"Port scan (60 ports)   -> {result}  (expect PORT_SCAN)")


def test_brute_force():
    engine = RuleEngine()
    attacker_ip = "10.0.0.77"
    result = "BENIGN"
    # simulate 25 connection attempts to SSH (port 22)
    for i in range(25):
        flow = make_flow(src_ip=attacker_ip, dst_port=22,
                          packet_count=3, syn_ratio=0.5, pps=10.0)
        result = engine.check(flow)
    print(f"SSH brute force (25x)  -> {result}  (expect BRUTE_FORCE)")


def test_connection_burst():
    engine = RuleEngine()
    attacker_ip = "10.0.0.88"
    result = "BENIGN"
    # simulate 110 flows to different normal-looking ports
    for i in range(110):
        flow = make_flow(src_ip=attacker_ip, dst_port=443,
                          packet_count=3, syn_ratio=0.1, pps=5.0)
        result = engine.check(flow)
    print(f"Connection burst (110x)-> {result}  (expect CONNECTION_BURST)")


def test_rst_scan():
    engine = RuleEngine()
    flow = make_flow(packet_count=30, syn_ratio=0.1,
                      pps=20.0, rst_ratio=0.9)
    result = engine.check(flow)
    print(f"RST scan pattern        -> {result}  (expect RST_SCAN)")


if __name__ == "__main__":
    print("=" * 55)
    print("Rule Engine Test Suite")
    print("=" * 55)
    test_benign()
    test_syn_flood()
    test_syn_flood_false_positive_guard()
    test_port_scan()
    test_brute_force()
    test_connection_burst()
    test_rst_scan()
    print("=" * 55)
