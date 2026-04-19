from scapy.all import sniff, IP, TCP, UDP, Raw, get_if_addr, conf
from logger import AlertLogger
from rules import RuleEngine
import threading
import time

class IDS:
    def __init__(self, interface=None):
        self.interface = interface or conf.iface

        self.logger = AlertLogger()
        self.rules = RuleEngine(self.logger)

        self.running = False
        self.packet_count = 0
        self.start_time = None

        self.logger.info(f"IDS initialized on interface: {self.interface}")
        self.logger.info(f"Monitoring IP: {get_if_addr(self.interface)}")

    def analyze_packet(self, packet):
        self.packet_count += 1

        if not packet.haslayer(IP):
            return

        src_ip = packet[IP].src

        # Ignore already blocked attackers
        if src_ip in self.rules.blocked_ips:
            return

        # DDoS check (global)
        self.rules.check_ddos(src_ip)

        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport

            self.rules.check_port_scan(src_ip, dst_port)
            self.rules.check_brute_force(src_ip, dst_port)
            self.rules.check_sensitive_port_access(src_ip, dst_port)

            # Payload inspection
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                self.rules.check_suspicious_payload(src_ip, payload)

        elif packet.haslayer(UDP):
            dst_port = packet[UDP].dport
            self.rules.check_port_scan(src_ip, dst_port)

    def print_stats(self):
        while self.running:
            time.sleep(10)  # faster updates for demo

            if self.start_time:
                elapsed = int(time.time() - self.start_time)
                rate = self.packet_count / max(elapsed, 1)

                self.logger.info(
                    f"Stats — Packets: {self.packet_count} | "
                    f"Time: {elapsed}s | Rate: {rate:.1f} pkt/s | "
                    f"Alerts: {self.logger.alert_count}"
                )

    def start(self):
        self.running = True
        self.start_time = time.time()

        print("\n" + "="*60)
        print("🛡️ IDS STARTED — Monitoring traffic")
        print("Press Ctrl+C to stop")
        print("="*60 + "\n")

        threading.Thread(target=self.print_stats, daemon=True).start()

        try:
            sniff(
                iface=self.interface,
                prn=self.analyze_packet,
                store=False
            )
        except KeyboardInterrupt:
            self.running = False
            print(f"\n\n✅ IDS stopped. Total packets: {self.packet_count}")


if __name__ == "__main__":
    IDS().start()