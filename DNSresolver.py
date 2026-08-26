from scapy.all import IP, UDP, DNS, sr1, DNSQR
import psutil
import sys
import argparse
import os
import subprocess

clsc = "cls" if os.name == "nt" else "clear"
subprocess.run(clsc, shell=True, check=True)

#Display up and available network interfaces
print("-------", " Available Network Interface/s", "-------", "\n")

addresses = psutil.net_if_addrs()
stats = psutil.net_if_stats()

# Filtering out inactive net interfaces
available_networks = []
for intface, addr_list in addresses.items():
    if any(getattr(addr, 'address').startswith("169.254") for addr in addr_list):
        continue
    elif intface in stats and getattr(stats[intface], "isup"):
        available_networks.append(intface)

print(available_networks, "\n", flush=True)

# While loop for interface input validation
ifaceinput = input("Select interface to use: ")
while ifaceinput not in available_networks:
    print("\n","Please select an available interface!", "\n")

    ifaceinput = input("Select interface to use: ")
    print("\n", ifaceinput, "selected", "\n")

p = sr1(IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="google.com")), timeout=5)

iface=ifaceinput,

print(p, "\n")

# Clearing up raw packet dump
if p is None:
    print("No response (timed out).")
elif not p.haslayer(DNS) or p[DNS].ancount == 0:
    print("Response received but no DNS answers.")
else:
    print(f"Answers from {p.src}:")
    for rr in p[DNS].an:
        print(" ", rr.rdata)
