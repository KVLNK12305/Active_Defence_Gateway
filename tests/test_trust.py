import os
import time
import threading
import subprocess


def run_cmd(cmd):
    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def scenario_normal_web():
    # 100 Trust Expected
    print("🌐 Scenario 1: Normal Web Browsing (Target: speedtest.tele2.net) -> Expected Trust: 100")
    run_cmd("curl -s -o /dev/null http://speedtest.tele2.net/1MB.zip")

def scenario_syn_scan():
    # 40-50 Trust Expected
    print("🕵️ Scenario 2: Aggressive Port Scan (Target: 1.1.1.1) -> Expected Trust: 40-50 (Suspicious/Untrusted)")
    for _ in range(30):
        run_cmd("nc -z -w 1 1.1.1.1 443")

def scenario_udp_flood():
    # ~85 Trust Expected
    print("🌊 Scenario 3: UDP Heavy Traffic (Target: 8.8.4.4) -> Expected Trust: ~85-90")
    for _ in range(30):
        run_cmd("dig @8.8.4.4 google.com")
        time.sleep(0.05)

def scenario_idle_decay():
    # Score drops over time
    print("⏳ Scenario 4: Creating a short burst to 9.9.9.9 to watch it decay to IDLE (Trust drop -15)")
    run_cmd("ping -c 3 9.9.9.9")


if __name__ == '__main__':
    print("🛡️ Starting Real-World Trust Engine Testing...")
    threads = [
        threading.Thread(target=scenario_normal_web),
        threading.Thread(target=scenario_syn_scan),
        threading.Thread(target=scenario_udp_flood),
        threading.Thread(target=scenario_idle_decay),
    ]

    for t in threads:
        t.start()

    for t in threads:
        t.join()

    print("✅ Real-world traffic generated. Watch your ADG Monitor to see the Trust Scores calculate live!")

