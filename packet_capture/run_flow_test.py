
import time
import threading
import sys
import os

# add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from packet_capture.sniffer import start_sniffer, INTERFACE
from packet_capture.flow_engine import FlowEngine, flow_output_queue

def main():
    print("=" * 65)
    print("   AI-IDS — Flow Engine Test")
    print(f"   Interface: {INTERFACE}")
    print("   Flows complete after 30s of inactivity")
    print("   Browse websites to generate traffic")
    print("   Press Ctrl+C to stop")
    print("=" * 65)

    # start flow engine in background
    engine = FlowEngine()
    engine.start()

    # start sniffer in background thread
    sniffer_thread = threading.Thread(
        target=start_sniffer,
        daemon=True
    )
    sniffer_thread.start()

    # print stats every 10 seconds
    try:
        while True:
            time.sleep(10)
            stats = engine.get_stats()
            print(
                f"\n[STATS] Active flows: {stats['active_flows']} | "
                f"Total seen: {stats['total_seen']} | "
                f"Completed: {stats['total_completed']}"
            )
    except KeyboardInterrupt:
        print("\n[*] Stopping...")
        engine.stop()
        stats = engine.get_stats()
        print(f"[*] Final — Total flows seen: {stats['total_seen']}")
        print(f"[*] Final — Flows completed:  {stats['total_completed']}")


if __name__ == "__main__":
    main()
