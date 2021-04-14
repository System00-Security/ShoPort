#!/usr/bin/env python3
__author__      = "Joy Ghosh"
__TYP__         = "Passive_Portscanner"
__copyright__   = "Copyright 2021, SYSTEM00 SECURITY"
__PROJECT__     = "Project Khoj"
import requests
from colorama import Fore, Back, Style
import sys
import re
import json
import argparse
import socket
import ipaddress
import time
start = time.time()
#####YOUR_SHODAN_API_KEY###################
api_key="Your_Api_Key"
####YOUR_SHODAN_API_KEY####################
try:
    parser = argparse.ArgumentParser()
    parser.add_argument("-sip", "--singleip", help="Enter ip Adress ex : -sip 192.168.1.1 ", type=str)
    parser.add_argument("-ipl", "--iplist", help="Enter ip list ex : -ipl ip.txt ", type=str)
    parser.add_argument("-ir", "--iprange", help="Enter ip range ex : -ir 192.168.1.1/24 ", type=str)
    parser.add_argument("-hn", "--hostname", help="Enter hostname : -h 'google.com' ", type=str)
    args = parser.parse_args()
except TypeError:
    print("Type -h To See all the options")
except():
    exit()
def logo():
    print(f"""
    {Fore.RED}█▀ █░█ █▀█ █▀█ █▀█ █▀█ ▀█▀{Fore.WHITE}
    {Fore.GREEN}▄█ █▀█ █▄█ █▀▀ █▄█ █▀▄ ░█░{Fore.WHITE}
    ==============================
    Passive Portscanner [{Fore.RED}Shodan{Fore.WHITE}]

    """)
def port_gather(ip):
    GET_JSON=requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={api_key}")
    DUMP_JSON=json.dumps(GET_JSON.json())
    LOAD_JSON=json.loads(DUMP_JSON)
    print(f'{Fore.RED}[$]{Fore.WHITE} Scanning Ports For {ip}')
    try:
        for port in LOAD_JSON['ports']:
            print(f'{Fore.GREEN}[*] {Fore.WHITE} {ip}:{port}')
    except KeyError:
        print(f'{Fore.RED}[-]{Fore.WHITE} No Ports Found for {ip}')
        pass
    except:
        pass
def ip_range(iprange):
    try:
        for ip in ipaddress.IPv4Network(iprange):
            port_gather(ip)
    except ValueError:
        print(Fore.RED+"ValueError Detected Bit Set Is Not Correct"+Fore.WHITE)
    except KeyboardInterrupt:
        print('Exit Command Detected Exiting')
        exit()
    except:
        pass

def list_read(list):
    with open(list) as con:
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b',con.read())
        for ip in ips:
            try:
                port_gather(ip)
                print(Fore.RED+"--"+Fore.WHITE)
            except KeyError:
                print("No Ports Found for "+ip)
            except KeyboardInterrupt:
                print(Fore.RED+'[+]'+Fore.WHITE+"Exiting On User Command")
                exit()
            except:
                pass

def host_ip(host_add):
    try:
        ip=socket.gethostbyname(host_add)
        print(Fore.GREEN+'[+] '+Fore.WHITE+'Scanning Ip For '+host_add)
        print('')
        port_gather(ip)
    except KeyError:
        print(Fore.RED+'[+] '+Fore.WHITE+'No Port Found '+host_add)
    except:
        pass
logo()
if args.singleip is not None:
    port_gather(args.singleip)
    print('Scanning finished in ',Fore.BLUE, time.time()-start,Fore.WHITE, 'seconds.')
elif args.iplist is not None:
    list_read(args.iplist)
elif args.iprange is not None:
    ip_range(args.iprange)
elif args.hostname is not None:
    host_ip(args.hostname)
else:
    print("Type -h to see all scanning methods")
    pass
