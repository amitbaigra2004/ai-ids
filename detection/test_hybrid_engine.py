
import sys
sys.path.insert(0, ".")

from detection.hybrid_engine import HybridEngine


def make_flow(src_ip="10.0.0.1", dst_ip="192.168.1.1",
              src_port=12345, dst_port=443, protocol=6,
              duration=2.0, packet_count=20, byte_count=5000,
              packets_per_second=10.0, bytes_per_second=2500.0,
              avg_packet_size=250.0, syn_count=1, ack_count=18,
              fin_count=1, rst_count=0, syn_ratio=0.05,
              rst_ratio=0.0):
    return {k: v for k, v in locals().items()}


def print_result(label, result):
    print(f"\n{'─'*55}")
    print(f"  Test:         {label}")
    print(f"  Verdict:      {result['verdict']}")
    print(f"  Threat Score: {result['threat_score']}/100")
    print(f"  Rule Alert:   {result['rule_alert']}")
    print(f"  ML Prob:      {result['ml_probability']:.4f}")
    print(f"  Needs CTI:    {result['needs_cti']}")


if __name__ == "__main__":
    print("=" * 55)
    print("Hybrid Engine Test Suite")
    print("=" * 55)

    engine = HybridEngine()

    flow = make_flow()
    print_result("Normal HTTPS browsing", engine.analyze(flow))

    flow = make_flow(
        packet_count=500, syn_count=490,
        syn_ratio=0.98, packets_per_second=5000.0,
        byte_count=27000, avg_packet_size=54.0,
        bytes_per_second=135000.0, ack_count=5,
        fin_count=0, rst_count=5, rst_ratio=0.01
    )
    print_result("SYN Flood", engine.analyze(flow))

    flow = make_flow(
        packet_count=2, syn_count=1, syn_ratio=0.5,
        duration=0.001, packets_per_second=2000.0,
        byte_count=128, avg_packet_size=64.0,
        bytes_per_second=128000.0, ack_count=0,
        fin_count=0, rst_count=1, rst_ratio=0.5,
        dst_port=22
    )
    print_result("Single port probe (SSH)", engine.analyze(flow))

    flow = make_flow(
        packet_count=10000, byte_count=540000,
        avg_packet_size=54.0, packets_per_second=8000.0,
        bytes_per_second=432000.0, syn_count=9800,
        syn_ratio=0.98, ack_count=100,
        fin_count=0, rst_count=100, rst_ratio=0.01,
        duration=1.25
    )
    print_result("High volume flood", engine.analyze(flow))

    print(f"\n{'='*55}")
    print("Test complete.")
