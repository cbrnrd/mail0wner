#!/bin/bash

echo "Installing scapy"
pip install scapy > /dev/null 2>&1
echo "Installing pypcap and libpcap"
apt-get install -y libpcap-dev > /dev/null 2>&1
brew install libpcap > /dev/null 2>&1
pip install pypcap > /dev/null 2>&1
pip install netifaces > /dev/null 2>&1
echo "You're ready to 0wn."
chmod +x mail0wner.py
