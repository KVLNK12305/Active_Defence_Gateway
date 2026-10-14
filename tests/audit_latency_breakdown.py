#!/usr/bin/env python3
import os
import sys
import time
import subprocess
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.log import setLogLevel

def exec_cmd(cmd):
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return res.stdout.strip(), res.stderr.strip(), res.returncode

def start_controllers(num_controllers=3):
    exec_cmd("pkill -9 -f osken-manager")
    time.sleep(1)
    ports = [6653 + i for i in range(num_controllers)]
    pids = {}
    for i, port in enumerate(ports):
        cid = f"C{i+1}"
        log_file = f"/tmp/c{i+1}.log"
        pid_file = f"/tmp/c{i+1}.pid"
        exec_cmd(f"rm -f {log_file} {pid_file}")
        cmd = f"export ADG_CONTROLLER_ID={cid}; nohup osken-manager controller/adg_controller.py --ofp-tcp-listen-port {port} > {log_file} 2>&1 & echo $! > {pid_file}"
        subprocess.run(cmd, shell=True, executable='/bin/bash')
    time.sleep(3)
    for i in range(num_controllers):
        cid = f"C{i+1}"
        pid_file = f"/tmp/c{i+1}.pid"
        pid = open(pid_file).read().strip() if os.path.exists(pid_file) else "Unknown"
        pids[cid] = pid
    return pids

def audit_scale_run(num_controllers, num_switches, num_hosts):
    print(f"\n============================================================")
    print(f"  HIGH-RESOLUTION TIMING DECOMPOSITION ({num_controllers}C / {num_switches}S / {num_hosts}H)")
    print(f"============================================================")
    
    exec_cmd("mn -c")
    time.sleep(1)
    ctl_pids = start_controllers(num_controllers)
    
    setLogLevel('info')
    net = Mininet(switch=OVSSwitch, controller=RemoteController)
    for i in range(num_controllers):
        net.addController(f"c{i+1}", controller=RemoteController, ip='127.0.0.1', port=6653+i)
    switches = [net.addSwitch(f"s{i}", protocols='OpenFlow13') for i in range(1, num_switches + 1)]
    for i in range(len(switches) - 1):
        net.addLink(switches[i], switches[i+1])
    hosts = []
    h_idx = 1
    for s in switches:
        for _ in range(2):
            h = net.addHost(f"h{h_idx}", ip=f"10.0.0.{h_idx}", mac=f"00:00:00:00:00:{h_idx:02x}")
            net.addLink(h, s)
            hosts.append(h)
            h_idx += 1
    net.start()
    time.sleep(3)
    
    h1 = hosts[0]
    h_last = hosts[-1]
    
    # Warm up flows
    h1.cmd(f"ping -c 2 {h_last.IP()}")
    time.sleep(1)
    
    # Record surviving log position before failure
    pos_c2 = os.path.getsize("/tmp/c2.log") if os.path.exists("/tmp/c2.log") else 0
    
    # T0: Trigger Failure
    t0_kill = time.time()
    exec_cmd(f"kill -9 {ctl_pids['C1']}")
    t1_kill_done = time.time()
    
    # Subprocess flow deletion
    t2_del_start = time.time()
    for s in switches:
        for h_i in range(1, num_hosts + 1):
            mac_str = f"00:00:00:00:00:{h_i:02x}"
            exec_cmd(f"ovs-ofctl -O OpenFlow13 del-flows {s.name} dl_src={mac_str}")
            exec_cmd(f"ovs-ofctl -O OpenFlow13 del-flows {s.name} dl_dst={mac_str}")
    t3_del_done = time.time()
    
    # Send single ping immediately to measure recovery latency
    t4_ping_req = time.time()
    ping_out = h1.cmd(f"ping -c 1 -w 2 {h_last.IP()}")
    t5_ping_resp = time.time()
    
    # Read surviving controller log
    log_c2 = ""
    if os.path.exists("/tmp/c2.log"):
        with open("/tmp/c2.log") as f:
            f.seek(pos_c2)
            log_c2 = f.read()
            
    net.stop()
    exec_cmd("mn -c")
    exec_cmd("pkill -9 -f osken-manager")
    
    print("\n--- DETAILED TIMING BREAKDOWN ---")
    print(f"T0 (SIGKILL C1):                           {t0_kill:.6f} s")
    print(f"T1 (Kill Process Completed):               {t1_kill_done:.6f} s (Delta: {(t1_kill_done - t0_kill)*1000:.2f} ms)")
    print(f"T2-T3 (Selective OVS Flow Deletion):       {t3_del_done - t2_del_start:.4f} s ({num_switches*num_hosts*2} subprocess calls)")
    print(f"T4 (Post-Failure Ping Sent):               {t4_ping_req:.6f} s")
    print(f"T5 (Post-Failure Ping Response Received): {t5_ping_resp:.6f} s (Ping RTT + Flow Install: {(t5_ping_resp - t4_ping_req)*1000:.2f} ms)")
    print(f"Full Harness Elapsed Time (T5 - T0):       {t5_ping_resp - t0_kill:.4f} s")
    print(f"Recovery Ping Output:\n{ping_out.strip()}")
    print("\nSurviving Controller (C2) Log Excerpt:")
    print(log_c2.strip() if log_c2 else "[No new logs]")

if __name__ == '__main__':
    audit_scale_run(num_controllers=3, num_switches=8, num_hosts=16)
