#!/usr/bin/env python3
import os
import sys
import time
import subprocess
import psutil
import csv
import statistics
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.log import setLogLevel

def log_header(title):
    print("\n" + "="*80)
    print(f"  {title}")
    print("="*80 + "\n")

def exec_cmd(cmd):
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return res.stdout.strip(), res.stderr.strip(), res.returncode

def start_controllers(num_controllers=3, disable_dedup=False):
    log_header(f"STARTING {num_controllers} CONTROLLERS (Dedup Disabled={disable_dedup})")
    exec_cmd("pkill -9 -f osken-manager")
    time.sleep(2)
    
    ports = [6653 + i for i in range(num_controllers)]
    pids = {}
    
    for i, port in enumerate(ports):
        cid = f"C{i+1}"
        log_file = f"/tmp/c{i+1}.log"
        pid_file = f"/tmp/c{i+1}.pid"
        exec_cmd(f"rm -f {log_file} {pid_file}")
        
        env_vars = f"export ADG_CONTROLLER_ID={cid}; "
        if disable_dedup:
            env_vars += "export ADG_DISABLE_DEDUP=1; "
            
        cmd = f"{env_vars} nohup osken-manager controller/adg_controller.py --ofp-tcp-listen-port {port} > {log_file} 2>&1 & echo $! > {pid_file}"
        subprocess.run(cmd, shell=True, executable='/bin/bash')
    
    time.sleep(3)
    
    for i in range(num_controllers):
        cid = f"C{i+1}"
        pid_file = f"/tmp/c{i+1}.pid"
        try:
            pid = int(open(pid_file).read().strip())
            pids[cid] = pid
        except:
            pids[cid] = None
    
    print(f"Controller PIDs: {pids}")
    return pids

def build_mininet_topology(num_switches=8, num_controllers=3):
    setLogLevel('info')
    net = Mininet(switch=OVSSwitch, controller=RemoteController)
    
    controller_objs = []
    for i in range(num_controllers):
        c_obj = net.addController(f"c{i+1}", controller=RemoteController, ip='127.0.0.1', port=6653+i)
        controller_objs.append(c_obj)
        
    switches = []
    for i in range(1, num_switches + 1):
        s_obj = net.addSwitch(f"s{i}", protocols='OpenFlow13')
        switches.append(s_obj)
        
    for i in range(len(switches) - 1):
        net.addLink(switches[i], switches[i+1])
            
    hosts = []
    host_idx = 1
    for s_idx, s in enumerate(switches):
        for h_in_s in range(2):
            ip_addr = f"10.0.0.{host_idx}"
            mac_addr = f"00:00:00:00:00:{host_idx:02x}"
            h_obj = net.addHost(f"h{host_idx}", ip=ip_addr, mac=mac_addr)
            net.addLink(h_obj, s)
            hosts.append(h_obj)
            host_idx += 1
            
    return net, hosts

def get_packetin_count(num_controllers):
    counts = {}
    for i in range(num_controllers):
        cid = f"C{i+1}"
        out, _, _ = exec_cmd(f"grep -c 'PACKET_IN' /tmp/c{i+1}.log")
        try:
            counts[cid] = int(out)
        except:
            counts[cid] = 0
    return counts

def measure_cpu(pids_dict, duration, interval=0.1):
    procs = {}
    for cid, pid in pids_dict.items():
        if pid:
            try:
                procs[cid] = psutil.Process(pid)
                procs[cid].cpu_percent(interval=None) # Initialize
            except:
                pass

    samples = {cid: [] for cid in procs.keys()}
    start = time.time()
    
    while time.time() - start < duration:
        time.sleep(interval)
        for cid, p in procs.items():
            try:
                cpu = p.cpu_percent(interval=None)
                samples[cid].append(cpu)
            except:
                pass
    return samples

def run_trial(config_name, disable_dedup, trial_idx):
    log_header(f"TRIAL {trial_idx}: {config_name} (Dedup Disabled={disable_dedup})")
    
    exec_cmd("mn -c")
    time.sleep(2)
    
    num_ctl = 3
    num_sw = 8
    pids = start_controllers(num_controllers=num_ctl, disable_dedup=disable_dedup)
    
    net, hosts = build_mininet_topology(num_switches=num_sw, num_controllers=num_ctl)
    net.start()
    time.sleep(5)
    
    h1 = hosts[0]
    # Set static ARP to force packets to an unknown MAC address.
    # Because it is unknown, out_port = FLOOD, and NO flow rule will be installed.
    # This guarantees EVERY packet will trigger a PacketIn.
    h1.cmd("arp -s 10.0.0.99 00:11:22:33:44:55")
    
    print("Starting 1,000 pkt/s workload (hping3)...")
    hping_cmd = "hping3 -c 40000 -i u1000 --udp 10.0.0.99 > /tmp/hping3.log 2>&1 &"
    h1.cmd(hping_cmd)
    
    print("Warmup 5 seconds...")
    time.sleep(5)
    
    pkts_before = get_packetin_count(num_ctl)
    
    print("Measuring CPU for 30 seconds...")
    cpu_samples = measure_cpu(pids, duration=30, interval=0.1)
    
    pkts_after = get_packetin_count(num_ctl)
    
    print("Cooldown 5 seconds...")
    time.sleep(5)
    
    h1.cmd("pkill -9 -f hping3")
    net.stop()
    exec_cmd("mn -c")
    exec_cmd("pkill -9 -f osken-manager")
    
    total_packetins = 0
    for cid in pkts_before:
        diff = pkts_after[cid] - pkts_before[cid]
        total_packetins += diff
        print(f"{cid} processed {diff} PacketIns")
        
    rate = total_packetins / 30.0
    print(f"Total PacketIn rate across all controllers: {rate:.2f} pkt/s")
    
    # Calculate stats
    stats = {}
    aggregate_cpu_mean = 0.0
    for cid, samples in cpu_samples.items():
        if samples:
            s_mean = statistics.mean(samples)
            s_median = statistics.median(samples)
            s_min = min(samples)
            s_max = max(samples)
            s_std = statistics.stdev(samples) if len(samples) > 1 else 0.0
            aggregate_cpu_mean += s_mean
        else:
            s_mean = s_median = s_min = s_max = s_std = 0.0
            
        stats[cid] = {
            "mean": round(s_mean, 2),
            "median": round(s_median, 2),
            "min": round(s_min, 2),
            "max": round(s_max, 2),
            "std": round(s_std, 2)
        }
        print(f"{cid} CPU - Mean: {s_mean:.2f}%, Median: {s_median:.2f}%")
        
    return {
        "config": config_name,
        "trial": trial_idx,
        "packetins": total_packetins,
        "rate": round(rate, 2),
        "stats": stats,
        "agg_mean": round(aggregate_cpu_mean, 2),
        "per_ctl_mean": round(aggregate_cpu_mean / num_ctl, 2)
    }

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Must run as root for Mininet")
        sys.exit(1)
        
    results = []
    
    # Validation step: 1 run of each
    print("=== VALIDATION RUN ===")
    res_a = run_trial("DEDUP_DISABLED", True, 0)
    res_b = run_trial("DEDUP_ENABLED", False, 0)
    results.extend([res_a, res_b])
    
    print("\n=== FULL BENCHMARK (5 REPETITIONS) ===")
    for i in range(1, 6):
        res = run_trial("DEDUP_DISABLED", True, i)
        results.append(res)
        
    for i in range(1, 6):
        res = run_trial("DEDUP_ENABLED", False, i)
        results.append(res)
        
    import json
    with open('/tmp/cpu_benchmark_results.json', 'w') as f:
        json.dump(results, f, indent=2)
        
    csv_file = '/home/kushal/FYP/results/cpu_benchmark_raw.csv'
    with open(csv_file, 'w') as f:
        f.write("config,trial,packetins,rate_pkt_s,agg_mean_cpu,per_ctl_mean_cpu,c1_mean,c2_mean,c3_mean\n")
        for r in results:
            c1m = r['stats'].get('C1', {}).get('mean', 0.0)
            c2m = r['stats'].get('C2', {}).get('mean', 0.0)
            c3m = r['stats'].get('C3', {}).get('mean', 0.0)
            f.write(f"{r['config']},{r['trial']},{r['packetins']},{r['rate']},{r['agg_mean']},{r['per_ctl_mean']},{c1m},{c2m},{c3m}\n")
            
    md_file = '/home/kushal/FYP/results/cpu_benchmark_summary.md'
    with open(md_file, 'w') as f:
        f.write("# CPU Benchmark Summary\n\n")
        f.write("This rigorous CPU benchmark replaces the historically unsupported 82.4% -> 6.2% claim.\n\n")
        f.write("## Methodology\n")
        f.write("- **Topology:** 3 Controllers, 8 Switches, 16 Hosts.\n")
        f.write("- **Hardware CPU Allocation:** As per underlying VM/metal running the test.\n")
        f.write("- **Workload:** 1,000 UDP pkts/s destined to an unknown MAC to guarantee 100% `PacketIn` translation without `FlowMod` caching.\n")
        f.write("- **Measurement:** `psutil` sampling of `osken-manager` at 100ms intervals over a 30s steady-state window.\n\n")
        
        f.write("## Results\n\n")
        f.write("| Config | Trial | PacketIns (30s) | Rate (pkt/s) | Per-Ctl Mean CPU (%) | Agg Mean CPU (%) |\n")
        f.write("|---|---|---|---|---|---|\n")
        for r in results:
            f.write(f"| {r['config']} | {r['trial']} | {r['packetins']} | {r['rate']} | {r['per_ctl_mean']} | {r['agg_mean']} |\n")
            
    print("Benchmark complete. Raw data saved to results/cpu_benchmark_raw.csv")
