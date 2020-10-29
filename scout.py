import threading
import sys
import json
import argparse
import requests as r
import os
import socket
from scapy.all import *

def ping(network,starting_host,ending_host,timeout_):
    for i in range(starting_host,ending_host+1):
        host = network + str(i)
        icmp = IP(dst=host)/ICMP()
        status = sr1(icmp,timeout=timeout_,verbose=0)
        if status != None:
            mac = getmacbyip(host)
            print("\n[!] {} is alive.  \n ╰––> [!] MAC address: {} | Vendor: {}".format(host,mac,getVendor(mac)))
            #print("[!] {} is alive.".format(host))


def create_ping_thread(network,starting_host,ending_host,timeout):
    thread = threading.Thread(target=ping,args=(network,starting_host,ending_host,timeout))
    threads.append(thread)
    thread.start()

def getVendor(mac):
    if mac == None:
        return None
    else:
        url = "https://macvendors.co/api/"
        try:
            vendor = json.loads(r.get(url+mac).content)['result']['company']
        except:
            vendor = "Unknown"
        return vendor    

logo = '''
   _____                 _   
  / ____|               | |  
 | (___   ___ ___  _   _| |_ 
  \___ \ / __/ _ \| | | | __|
  ____) | (_| (_) | |_| | |_ 
 |_____/ \___\___/ \__,_|\__|
        Network Scanner

 - By Thanos Apostolidis
'''          

print(logo)                             

if os.geteuid() != 0:
    print("[!] You need to be root to execute this script, please try again using 'sudo'.")
    sys.exit(1)

parser = argparse.ArgumentParser(prog='Scout', description='Scout Network Scanner', 
                epilog='Example usage: sudo python3 scout.py 192.168.1.1 192.168.1.254', 
                formatter_class=argparse.RawDescriptionHelpFormatter)

parser.add_argument('starting_host', type=str, help='starting host')
parser.add_argument('ending_host', type=str, help='ending host')
parser.add_argument('--threads', type=int, help='total threads')
parser.add_argument('--timeout', type=int, help='icmp timeout')

args = parser.parse_args()

start = args.starting_host
end = args.ending_host

try:
    socket.inet_aton(start) 
    socket.inet_aton(end)
except:
    print("[!] Illegal IP passed as host.")
    sys.exit(1)

net_a = start.split('.')
net_a.pop()
net_b = end.split('.')
net_b.pop()
if '.'.join(net_a) != '.'.join(net_b):
    print("[!] Please provide ranges between the same network.")
    sys.exit(1)

tmp = start.split('.')[-1]
start = start.split('.')
start[-1] = ''
network = '.'.join(start)
start = int(tmp)
end = int(end.split('.')[-1])

number_of_hosts = end - start + 1
if(number_of_hosts<0):
    sys.exit(1)

threads = []
number_of_threads = 150

pings_per_thread = number_of_hosts//number_of_threads
remaining_pings = number_of_hosts%number_of_threads

timeout = 7

if args.timeout != None:
    timeout = args.timeout

if args.threads != None:
    number_of_threads = args.threads

print("[*] Scanning from {} to {}".format(network+str(start),network+str(end)))
print("[*] Total hosts: {}".format(number_of_hosts))
print("[*] Number of threads: {}".format(number_of_threads))
print("[*] Ping timeout: {} sec(s)".format(timeout))

if number_of_hosts<number_of_threads:
    for i in range(start,end+1):
        create_ping_thread(network,i,i,timeout)
else:
    # balance hosts and threads    
    starting_host = start
    for i in range(number_of_threads):
        ending_host = starting_host + pings_per_thread -1 
        if remaining_pings >0:
            ending_host += 1
            remaining_pings -= 1
        create_ping_thread(network,starting_host,ending_host,timeout)
        starting_host = ending_host + 1

for thread in threads:
    thread.join()

print("\n[*] Scan finished.")