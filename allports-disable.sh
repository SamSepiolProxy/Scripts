#!/bin/bash 
RED='\033[0;31m' # Sets Colour to Red 
YEL='\033[1;33m' # Sets Colour to Yellow
NC='\033[0m' # No Color

echo -e "${RED}[+]${NC} Clearing IP tables, prerouting and postrouting."
iptables -t nat -D PREROUTING 1
iptables -F
sleep .5
echo " "
ipt=$(iptables -L -t nat)
echo -e "${YEL}$ipt${NC}"
