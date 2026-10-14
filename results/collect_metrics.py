import time
import csv
import subprocess
import sys
import os
from datetime import datetime

# Add controller to path to reuse existing logic
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../controller')))
from trust import TrustStore  # type: ignore[import-not-found]
from policy import PolicyEngine  # type: ignore[import-not-found]

def get_flows(switch="s1"):
    try:
        result = subprocess.run(
            ["sudo", "ovs-ofctl", "-O", "OpenFlow13", "dump-flows", switch],
            capture_output=True, text=True, check=True
        )
        # Count high priority policy flows
        policy_flows = [line for line in result.stdout.split('\n') if "priority=200" in line or "priority=150" in line or "priority=120" in line]
        return len(policy_flows), result.stdout
    except Exception as e:
        return 0, str(e)

def main():
    target_ip = "10.0.0.1" # Adjust to the host you are attacking from
    if len(sys.argv) > 1:
        target_ip = sys.argv[1]

    trust_store = TrustStore()
    policy_engine = PolicyEngine()
    
    csv_file = "experiment_data.csv"
    print(f"Starting metrics collection for IP: {target_ip}")
    print(f"Writing to {csv_file}... Press Ctrl+C to stop.")

    with open(csv_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp", "Time_Seconds", "IP", "Trust_Score", "Policy_Action", "Policy_Flows_Installed"])

        start_time = time.time()
        
        try:
            while True:
                current_time = time.time()
                elapsed = int(current_time - start_time)
                timestamp = datetime.now().strftime('%H:%M:%S')
                
                # Get Trust
                trust = trust_store.get(target_ip)
                
                # Get Policy Action
                action = policy_engine.evaluate(trust).name
                
                # Get Flows
                policy_flow_count, _ = get_flows()
                
                writer.writerow([timestamp, elapsed, target_ip, trust, action, policy_flow_count])
                f.flush()
                
                print(f"[{timestamp}] IP: {target_ip} | Trust: {trust} | Action: {action} | Flows: {policy_flow_count}")
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("\nCollection stopped. Data saved to experiment_data.csv")

if __name__ == "__main__":
    main()
