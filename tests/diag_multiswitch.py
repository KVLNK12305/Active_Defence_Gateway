#!/usr/bin/env python3
"""
DIAGNOSTIC: Multi-switch connectivity under single vs multi-controller.
Purpose: Determine whether the 8-switch linear topology works at all,
         and whether multi-controller EQUAL mode causes packet amplification.
"""
import os, sys, time, subprocess
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.log import setLogLevel

setLogLevel('warning')

def run(cmd):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return r.stdout.strip()

def cleanup():
    run("pkill -9 -f osken-manager")
    time.sleep(0.5)
    run("mn -c")
    time.sleep(0.5)

def start_controllers(n):
    cleanup()
    pids = {}
    for i in range(n):
        port = 6653 + i
        cid = f"C{i+1}"
        cmd = (f"export ADG_CONTROLLER_ID={cid}; "
               f"nohup osken-manager controller/adg_controller.py "
               f"--ofp-tcp-listen-port {port} > /tmp/{cid}.log 2>&1 & "
               f"echo $! > /tmp/{cid}.pid")
        subprocess.run(cmd, shell=True, executable='/bin/bash')
        pids[cid] = open(f"/tmp/{cid}.pid").read().strip() if os.path.exists(f"/tmp/{cid}.pid") else "?"
    time.sleep(3)
    listening = run("ss -ltnp | grep -cE '6653|6654|6655'")
    print(f"  Controllers listening: {listening}/{n}")
    return pids

def build_topo(num_sw, num_ctl):
    net = Mininet(switch=OVSSwitch, controller=RemoteController)
    for i in range(num_ctl):
        net.addController(f"c{i+1}", controller=RemoteController,
                          ip='127.0.0.1', port=6653+i)
    switches = [net.addSwitch(f"s{i}", protocols='OpenFlow13')
                for i in range(1, num_sw+1)]
    for i in range(len(switches)-1):
        net.addLink(switches[i], switches[i+1])

    hosts = []
    for i in range(1, num_sw*2 + 1):
        s = switches[(i-1)//2]
        h = net.addHost(f"h{i}", ip=f"10.0.0.{i}",
                        mac=f"00:00:00:00:00:{i:02x}")
        net.addLink(h, s)
        hosts.append(h)
    return net, switches, hosts

def test_connectivity(net, hosts, switches, label):
    print(f"\n{'='*60}")
    print(f"  TEST: {label}")
    print(f"{'='*60}")

    net.start()
    time.sleep(3)

    # Same-switch ping (h1 -> h2, both on s1)
    r1 = hosts[0].cmd("ping -c 3 -W 2 10.0.0.2")
    same_ok = "0% packet loss" in r1
    print(f"  Same-switch  (h1->h2):  {'PASS' if same_ok else 'FAIL'}")

    # Adjacent-switch ping (h2 -> h3, s1 -> s2)
    r2 = hosts[1].cmd("ping -c 3 -W 2 10.0.0.3")
    adj_ok = "0% packet loss" in r2
    print(f"  Adjacent-sw  (h2->h3):  {'PASS' if adj_ok else 'FAIL'}")

    # Cross-switch ping (h1 -> h16, s1 -> s8)
    r3 = hosts[0].cmd("ping -c 5 -W 2 10.0.0.16")
    cross_ok = "0% packet loss" in r3
    # Extract loss
    loss_line = [l for l in r3.splitlines() if "packet loss" in l]
    print(f"  Cross-switch (h1->h16): {'PASS' if cross_ok else 'FAIL'}  {loss_line[0] if loss_line else ''}")

    # Flow count
    total_flows = 0
    for s in switches:
        out = run(f"ovs-ofctl -O OpenFlow13 dump-flows {s.name}")
        total_flows += len([l for l in out.splitlines() if "cookie=" in l])
    print(f"  Total flows across {len(switches)} switches: {total_flows}")

    # Controller CPU
    cpu_out = run("ps aux | grep osken-manager | grep -v grep")
    for line in cpu_out.splitlines():
        parts = line.split()
        if len(parts) > 2:
            print(f"  Controller CPU: {parts[2]}%  MEM: {parts[3]}%  CMD: ...{parts[-1][-20:]}")

    net.stop()
    return same_ok, adj_ok, cross_ok


# ============================================================
# TEST 1: Single controller, 8 switches, 16 hosts
# ============================================================
pids = start_controllers(1)
net, switches, hosts = build_topo(8, 1)
s1, a1, c1 = test_connectivity(net, hosts, switches, "1 Controller / 8 Switches / 16 Hosts")
cleanup()

# ============================================================
# TEST 2: 2 controllers (EQUAL), 8 switches, 16 hosts
# ============================================================
pids = start_controllers(2)
net, switches, hosts = build_topo(8, 2)
s2, a2, c2 = test_connectivity(net, hosts, switches, "2 Controllers (EQUAL) / 8 Switches / 16 Hosts")
cleanup()

# ============================================================
# TEST 3: 3 controllers (EQUAL), 8 switches, 16 hosts
# ============================================================
pids = start_controllers(3)
net, switches, hosts = build_topo(8, 3)
s3, a3, c3 = test_connectivity(net, hosts, switches, "3 Controllers (EQUAL) / 8 Switches / 16 Hosts")
cleanup()

# ============================================================
# SUMMARY
# ============================================================
print(f"\n{'='*60}")
print(f"  DIAGNOSTIC SUMMARY")
print(f"{'='*60}")
print(f"  {'Config':<45} {'Same-SW':<10} {'Adj-SW':<10} {'Cross-SW':<10}")
print(f"  {'-'*75}")
print(f"  {'1 Ctl / 8 SW / 16 Hosts':<45} {'PASS' if s1 else 'FAIL':<10} {'PASS' if a1 else 'FAIL':<10} {'PASS' if c1 else 'FAIL':<10}")
print(f"  {'2 Ctl (EQUAL) / 8 SW / 16 Hosts':<45} {'PASS' if s2 else 'FAIL':<10} {'PASS' if a2 else 'FAIL':<10} {'PASS' if c2 else 'FAIL':<10}")
print(f"  {'3 Ctl (EQUAL) / 8 SW / 16 Hosts':<45} {'PASS' if s3 else 'FAIL':<10} {'PASS' if a3 else 'FAIL':<10} {'PASS' if c3 else 'FAIL':<10}")
