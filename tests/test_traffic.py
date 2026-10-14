import os
import time
import threading
import subprocess


def run_cmd(cmd):
    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def icmp_dominant():
    # Ping 8.8.8.8 continuously for high ICMP
    print("📡 Generating ICMP Dominant traffic (8.8.8.8)...")
    run_cmd("ping -i 0.2 -c 100 8.8.8.8")

def udp_dominant():
    # DNS queries to 8.8.4.4
    print("📡 Generating UDP Dominant traffic (8.8.4.4)...")
    for _ in range(50):
        run_cmd("dig @8.8.4.4 google.com")
        time.sleep(0.1)

def tcp_normal():
    # Download a large file to get many TCP packets, 1 SYN-ACK (Low SYN Rate -> NORMAL)
    print("📡 Generating TCP Normal SYN traffic (speedtest.tele2.net)...")
    run_cmd("curl -s -o /dev/null http://speedtest.tele2.net/1MB.zip")

def tcp_aggressive():
    # Repeatedly connect and disconnect (nc -z) to 1.1.1.1
    # Each connection is 1 SYN-ACK and ~2 ACKs -> SYN Rate ~0.33 -> AGGRESSIVE
    print("📡 Generating TCP Aggressive SYN traffic (1.1.1.1)...")
    for _ in range(30):
        run_cmd("nc -z -w 1 1.1.1.1 443")

def mixed_traffic():
    # Generate a mix to 9.9.9.9
    print("📡 Generating Mixed traffic (9.9.9.9)...")
    for _ in range(10):
        run_cmd("ping -c 1 9.9.9.9")
        run_cmd("dig @9.9.9.9 example.com")
        run_cmd("nc -z -w 1 9.9.9.9 53")

if __name__ == '__main__':
    print("🚀 Starting Brutal Hardcore Traffic Generator...")
    threads = [
        threading.Thread(target=icmp_dominant),
        threading.Thread(target=udp_dominant),
        threading.Thread(target=tcp_normal),
        threading.Thread(target=tcp_aggressive),
        threading.Thread(target=mixed_traffic),
    ]

    for t in threads:
        t.start()

    for t in threads:
        t.join()

    print("✅ Traffic generation complete. Wait a few seconds to observe IDLE state.")

