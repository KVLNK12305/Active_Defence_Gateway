#!/usr/bin/env python3
import sys
import time
import subprocess
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.log import setLogLevel

def test_setup():
    setLogLevel('info')
    net = Mininet(switch=OVSSwitch, controller=RemoteController)
    c1 = net.addController('c1', controller=RemoteController, ip='127.0.0.1', port=6653)
    c2 = net.addController('c2', controller=RemoteController, ip='127.0.0.1', port=6654)
    h1 = net.addHost('h1', ip='10.0.0.1', mac='00:00:00:00:00:01')
    h2 = net.addHost('h2', ip='10.0.0.2', mac='00:00:00:00:00:02')
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    
    net.start()
    print("Mininet started successfully.")
    
    print("h1 IP:", h1.IP())
    print("h2 IP:", h2.IP())
    
    time.sleep(2)
    
    res = net.pingAll()
    print("PingAll result:", res)
    
    net.stop()

if __name__ == '__main__':
    test_setup()
