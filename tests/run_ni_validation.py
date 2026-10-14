#!/usr/bin/env python3
import os
import sys
import time
import subprocess
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.log import setLogLevel

def log_header(title):
    print("\n" + "="*60, flush=True)
    print(f"  {title}", flush=True)
    print("="*60 + "\n", flush=True)

def exec_cmd(cmd):
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return res.stdout.strip(), res.stderr.strip(), res.returncode

def start_xdp(iface):
    print(f"Building and starting adg-xdp on {iface}...")
    exec_cmd("cd adg-xdp && cargo build --release")
    xdp_cmd = f"nohup /home/kushal/FYP/adg-xdp/target/release/adg-xdp --iface {iface} > /home/kushal/FYP/xdp.log 2>&1 & echo $! > /tmp/xdp.pid"
    subprocess.run(xdp_cmd, shell=True)
    time.sleep(3)
    if os.path.exists("/tmp/xdp.pid"):
        return open("/tmp/xdp.pid").read().strip()
    return None

def start_controller():
    print("Starting controller...")
    exec_cmd("pkill -9 -f osken-manager")
    time.sleep(1)
    exec_cmd("rm -f /tmp/c1.log /tmp/c1.pid")
    env = "export ADG_CONTROLLER_ID=C1; "
    cmd = f"{env} nohup osken-manager controller/adg_controller.py --ofp-tcp-listen-port 6653 > /tmp/c1.log 2>&1 & echo $! > /tmp/c1.pid"
    subprocess.run(cmd, shell=True)
    time.sleep(3)

def stop_daemons():
    exec_cmd("pkill -9 -f adg-xdp")
    exec_cmd("pkill -9 -f osken-manager")

def extract_policy(host_ip):
    log_data = open("/tmp/c1.log").read()
    blocks = log_data.split("[POLICY]")
    latest_risk = 0
    latest_decision = "UNKNOWN"
    for b in reversed(blocks):
        if f"Host : {host_ip}" in b:
            lines = b.strip().split('\n')
            for line in lines:
                if "Risk :" in line:
                    latest_risk = int(line.split(":")[1].strip())
                if "Decision :" in line:
                    latest_decision = line.split(":")[1].strip()
            return latest_risk, latest_decision
    return latest_risk, latest_decision

def run_experiment_6a():
    log_header("EXPERIMENT 6A - BENIGN BASELINE")
    stop_daemons()
    exec_cmd("mn -c")
    time.sleep(1)
    
    net = Mininet(switch=OVSSwitch, controller=RemoteController)
    c1 = net.addController('c1', controller=RemoteController, ip='127.0.0.1', port=6653)
    h1 = net.addHost('h1', ip='10.0.0.1')
    h2 = net.addHost('h2', ip='10.0.0.2')
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    
    net.start()
    time.sleep(2)
    
    xdp_pid = start_xdp("s1-eth1")
    start_controller()
    
    print("Generating benign traffic (Ping and TCP)")
    h1.cmd("ping -c 5 10.0.0.2")
    
    h2.cmd("python3 -m http.server 80 &")
    time.sleep(1)
    h1.cmd("curl 10.0.0.2:80")
    h1.cmd("curl 10.0.0.2:80")
    
    # Delete flows so controller gets PacketIn
    s1.cmd("ovs-ofctl -O OpenFlow13 del-flows s1")
    s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 'priority=0,actions=CONTROLLER'")
    s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 'priority=10,dl_dst=ff:ff:ff:ff:ff:ff,actions=FLOOD'")
    h1.cmd("ping -c 1 10.0.0.2")
    time.sleep(2)
    
    risk, dec = extract_policy("10.0.0.1")
    print(f"Observed Risk: {risk}, Decision: {dec}")
    
    net.stop()
    return risk, dec

def run_experiment_6b():
    log_header("EXPERIMENT 6B - TCP SYN SCAN")
    stop_daemons()
    exec_cmd("mn -c")
    time.sleep(1)
    net = Mininet(switch=OVSSwitch, controller=RemoteController)
    c1 = net.addController('c1', controller=RemoteController, ip='127.0.0.1', port=6653)
    h1 = net.addHost('h1', ip='10.0.0.1')
    h2 = net.addHost('h2', ip='10.0.0.2')
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.start()
    time.sleep(2)
    xdp_pid = start_xdp("s1-eth1")
    start_controller()
    
    print("Generating TCP SYN scan to 100 ports")
    for p in range(1, 101):
        h1.cmd(f"nc -w 1 -z 10.0.0.2 {p} &")
    time.sleep(2)
    
    s1.cmd("ovs-ofctl -O OpenFlow13 del-flows s1")
    s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 'priority=0,actions=CONTROLLER'")
    s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 'priority=10,dl_dst=ff:ff:ff:ff:ff:ff,actions=FLOOD'")
    h1.cmd("ping -c 1 10.0.0.2")
    time.sleep(2)
    
    risk, dec = extract_policy("10.0.0.1")
    print(f"Observed Risk: {risk}, Decision: {dec}")
    net.stop()
    return risk, dec

def run_experiment_6c():
    log_header("EXPERIMENT 6C - DESTINATION DIVERSITY")
    stop_daemons()
    exec_cmd("mn -c")
    time.sleep(1)
    net = Mininet(switch=OVSSwitch, controller=RemoteController)
    c1 = net.addController('c1', controller=RemoteController, ip='127.0.0.1', port=6653)
    h1 = net.addHost('h1', ip='10.0.0.1')
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    net.addLink(h1, s1)
    
    for i in range(2, 12):
        hx = net.addHost(f'h{i}', ip=f'10.0.0.{i}')
        net.addLink(hx, s1)
    
    net.start()
    time.sleep(2)
    xdp_pid = start_xdp("s1-eth1")
    start_controller()
    
    print("Sending traffic to 10 unique destinations")
    for i in range(2, 12):
        h1.cmd(f"nc -w 1 -z 10.0.0.{i} 80 &")
    
    time.sleep(2)
    s1.cmd("ovs-ofctl -O OpenFlow13 del-flows s1")
    s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 'priority=0,actions=CONTROLLER'")
    s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 'priority=10,dl_dst=ff:ff:ff:ff:ff:ff,actions=FLOOD'")
    h1.cmd("ping -c 1 10.0.0.2")
    time.sleep(2)
    
    risk, dec = extract_policy("10.0.0.1")
    print(f"Observed Risk: {risk}, Decision: {dec}")
    net.stop()
    return risk, dec

def run_experiment_6d():
    log_header("EXPERIMENT 6D - CONNECTION FAILURE / RST")
    stop_daemons()
    exec_cmd("mn -c")
    time.sleep(1)
    net = Mininet(switch=OVSSwitch, controller=RemoteController)
    c1 = net.addController('c1', controller=RemoteController, ip='127.0.0.1', port=6653)
    h1 = net.addHost('h1', ip='10.0.0.1')
    h2 = net.addHost('h2', ip='10.0.0.2')
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.start()
    time.sleep(2)
    xdp_pid = start_xdp("s1-eth1")
    start_controller()
    
    print("Generating TCP SYNs to closed ports (Expect RSTs)")
    for p in range(1000, 1020):
        h1.cmd(f"nc -w 1 -z 10.0.0.2 {p}")
    time.sleep(2)
    
    s1.cmd("ovs-ofctl -O OpenFlow13 del-flows s1")
    s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 'priority=0,actions=CONTROLLER'")
    s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 'priority=10,dl_dst=ff:ff:ff:ff:ff:ff,actions=FLOOD'")
    h1.cmd("ping -c 1 10.0.0.2")
    time.sleep(2)
    
    risk, dec = extract_policy("10.0.0.1")
    print(f"Observed Risk: {risk}, Decision: {dec}")
    net.stop()
    return risk, dec

if __name__ == '__main__':
    run_experiment_6a()
    run_experiment_6b()
    run_experiment_6c()
    run_experiment_6d()
    stop_daemons()
    exec_cmd("mn -c")
