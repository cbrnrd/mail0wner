#!/bin/bash
echo "If there are any error messages concerning installs, install whatever they tell you to install using your package manager"


echo "Installing tcpdump"
apt-get install -y tcpdump
echo "Installing scapy"
pip install scapy
echo "Installing pypcap and libpcap"
apt-get install -y libpcap-dev
pip install pypcap
pip install netifaces
echo "You're ready to 0wn."
chmod +x mail0wner.py
exit 0
