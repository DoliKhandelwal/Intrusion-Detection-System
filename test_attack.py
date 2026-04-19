import socket
import time
from scapy.all import *

TARGET = "127.0.0.1"

def simulate_sensitive_port_access():
    print("[TEST] Sensitive port access (LOW)...")
    ports = [22, 21, 3306, 3389]
    for port in ports:
        s = socket.socket()
        s.connect_ex((TARGET, port))
        s.close()
        time.sleep(0.2)


def simulate_payload_attack():
    print("[TEST] Payload attack (MEDIUM)...")
    pkt = IP(dst=TARGET)/TCP(dport=80)/Raw(load="DROP TABLE users")
    send(pkt)


def simulate_port_scan():
    print("[TEST] Port scan (HIGH)...")
    for port in range(1, 50):
        s = socket.socket()
        s.settimeout(0.1)
        s.connect_ex((TARGET, port))
        s.close()
        time.sleep(0.02)


def simulate_brute_force():
    print("[TEST] Brute force (HIGH)...")
    for i in range(10):
        s = socket.socket()
        s.connect_ex((TARGET, 22))
        s.close()
        time.sleep(0.05)


def simulate_ddos():
    print("[TEST] DDoS (HIGH)...")
    for i in range(100):
        s = socket.socket()
        s.connect_ex((TARGET, 80))
        s.close()


if __name__ == "__main__":
    print("🔴 Attack Simulation Started...\n")
    time.sleep(2)

    simulate_sensitive_port_access()   # LOW first
    time.sleep(2)

    simulate_payload_attack()          # MEDIUM second
    time.sleep(2)

    simulate_port_scan()               # HIGH
    time.sleep(1)

    simulate_brute_force()             # HIGH
    time.sleep(1)

    simulate_ddos()                    # HIGH

   # print("\n✅ All attack simulations completed.")