#!/bin/bash
if [ "$(id -u)" != "0" ]; then
        echo "Run this script as root!"
        echo "Exiting..."
        exit 1
fi
echo "If there are any error messages concerning installs, install whatever they tell you to install using sudo apt-get"


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
