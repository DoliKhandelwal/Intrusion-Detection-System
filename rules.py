import time
from collections import defaultdict

class RuleEngine:
    def __init__(self, logger):
        self.logger = logger

        # Track scanned ports per IP
        self.port_scan_tracker = defaultdict(set)

        # Track connection attempts per IP
        self.brute_force_tracker = defaultdict(list)

        # Track packets per IP (for DDoS)
        self.packet_count_from_ip = defaultdict(list)

        # Blocked IPs
        self.blocked_ips = set()

        # Sensitive ports
        self.sensitive_ports = {22, 23, 3389, 5900, 21, 3306, 1433}

        # Thresholds
        self.PORT_SCAN_THRESHOLD = 5
        self.BRUTE_FORCE_THRESHOLD = 10
        self.BRUTE_FORCE_WINDOW = 60

        self.DDOS_THRESHOLD = 100
        self.DDOS_WINDOW = 10

    def check_port_scan(self, src_ip, dst_port):
        """Detect multiple ports access"""

        self.port_scan_tracker[src_ip].add(dst_port)

        if len(self.port_scan_tracker[src_ip]) > self.PORT_SCAN_THRESHOLD:
            self.logger.alert(
                "HIGH",
                "PORT SCAN DETECTED",
                src_ip,
                f"{len(self.port_scan_tracker[src_ip])} ports scanned",
                reason="Many ports in short time"
            )
            self.port_scan_tracker[src_ip].clear()
            return True
        return False

    def check_brute_force(self, src_ip, dst_port):
        """Detect repeated attempts on same port"""

        if dst_port not in self.sensitive_ports:
            return False

        now = time.time()
        self.brute_force_tracker[src_ip].append(now)

        # Remove old entries
        self.brute_force_tracker[src_ip] = [
            t for t in self.brute_force_tracker[src_ip]
            if now - t < self.BRUTE_FORCE_WINDOW
        ]

        attempts = len(self.brute_force_tracker[src_ip])

        if attempts > self.BRUTE_FORCE_THRESHOLD:
            self.logger.alert(
                "HIGH",
                "BRUTE FORCE DETECTED",
                src_ip,
                f"{attempts} attempts on port {dst_port}",
                reason="Too many attempts in short time"
            )

            # Block IP
            self.blocked_ips.add(src_ip)
            print(f"⛔ BLOCKED IP: {src_ip}")

            self.brute_force_tracker[src_ip].clear()
            return True
        return False

    def check_ddos(self, src_ip):
        """Detect high traffic from single IP"""

        now = time.time()
        self.packet_count_from_ip[src_ip].append(now)

        # Remove old entries
        self.packet_count_from_ip[src_ip] = [
            t for t in self.packet_count_from_ip[src_ip]
            if now - t < self.DDOS_WINDOW
        ]

        if len(self.packet_count_from_ip[src_ip]) > self.DDOS_THRESHOLD:
            self.logger.alert(
                "HIGH",
                "DDoS ATTACK DETECTED",
                src_ip,
                f"{len(self.packet_count_from_ip[src_ip])} packets",
                reason="Too many packets in short time"
            )

            # Block IP
            self.blocked_ips.add(src_ip)
            print(f"⛔ BLOCKED IP: {src_ip}")

            self.packet_count_from_ip[src_ip].clear()
            return True
        return False

    def check_sensitive_port_access(self, src_ip, dst_port):
        """Log access to sensitive ports"""

        if dst_port in self.sensitive_ports:
            self.logger.alert(
                "LOW",
                "SENSITIVE PORT ACCESS",
                src_ip,
                f"Port {dst_port} accessed",
                reason="Sensitive service access"
            )
            return True
        return False

    def check_suspicious_payload(self, src_ip, payload):
        """Detect known malicious patterns"""

        attack_signatures = [
            b"SELECT * FROM",
            b"DROP TABLE",
            b"<script>",
            b"/etc/passwd",
            b"cmd.exe",
            b"wget http",
            b"chmod 777",
        ]

        payload_lower = payload.lower() if payload else b""

        for sig in attack_signatures:
            if sig.lower() in payload_lower:
                self.logger.alert(
                    "MEDIUM",
                    "SUSPICIOUS PAYLOAD",
                    src_ip,
                    f"Signature: {sig.decode(errors='ignore')}",
                    reason="Matched known attack pattern"
                )
                return True
        return False