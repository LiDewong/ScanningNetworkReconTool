from logging import getLogger, ERROR
getLogger("scapy.runtime").setLevel(ERROR)
from scapy.all import *
import sys
from datetime import datetime
from time import strftime

try:
    target = input('[*] Enter Target IP Address: ')
    min_port = input("[*] Enter Minimum Port Number: ")
    max_port = input("[*] Enter Maximum Port Number: ")
    try:
        if int(min_port) >= 0 and int(max_port) >= 0 and int(max_port) >= int(min_port):
            pass
        else:
            print ("\n[!] Invalid Range of Ports")
            print ("[!] Exiting...")
            sys.exit(1)
    except Exception:
        print ("\n[!] Invalid Range of Ports")
        print ("[!] Exiting...")
        sys.exit(1)
except KeyboardInterrupt:
    print("\n[*] User Requested Shutdown...")
    print ("[*] Exiting")
    sys.exit(1)

ports = range(int(min_port),int(max_port)+1)
start_clock = datetime.now()
SYNACK = 0x12
RSTACK = 0x14

def checkhost(ip):
    conf.verb = 0
    try:
        ping = sr1(IP(dst = ip)/ICMP(), timeout=2)
        print ("\n[*] Target is Up, Beginning Scan...")
    except Exception:
        print("\n[!] Couldn't Resolve Target")
        print("[!] Exiting...")
        sys.exit(1)

def scanport(port):
    srcport = RandShort()
    conf.verb = 0
    SYNACKpkt = sr1(IP(dst = target)/TCP(sport =srcport, dport = port, flags = "S"), timeout=2)
    if SYNACKpkt is None:
        return False
    pktflags = SYNACKpkt.getlayer(TCP).flags
    if pktflags == SYNACK:
        RSTpkt = IP(dst = target)/TCP(sport = srcport, dport = port, flags = "R")
        send(RSTpkt)
        return True
    else:
        return False

checkhost(target)
print("[*] Scanning Started at " + strftime("%H:%M:%S") + "!\n")

for port in ports:
    status = scanport(port)
    if status:
        print("Port " + str(port) + ": Open")

stop_clock = datetime.now()
total_time = stop_clock - start_clock
print("\n[*] Scanning Finished!")
print("[*] Total Scan Duration: " + str(total_time))
