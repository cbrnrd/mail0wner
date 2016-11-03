#!/bin/bash
clear

echo "If there are any error messages concerning installs, install whatever they tell you to install \nusing sudo apt-get"

echo "Installing pip"
easy_install pip
echo "Installing scapy through pip"
pip install scapy
echo "Installing pypcap"
pip install pypcap
echo "You're ready to 0wn, just run `sudo python mail0wner.py`"
