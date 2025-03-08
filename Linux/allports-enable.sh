#!/bin/bash 
RED='\033[0;31m' # Sets Colour to Red 
YEL='\033[1;33m' # Sets Colour to Yellow
NC='\033[0m' # No Color

echo -e "${RED}[+]${NC} Enter the interface you would like to run all ports on and press [ENTER]: "
read interface 
ip=$(ip -f inet -o addr show $interface|cut -d\  -f 7 | cut -d/ -f 1)
echo -e "${RED}[+]${NC} Setting up all ports server on IP address:" ${YEL}$ip${NC}
echo " "
sleep .5
iptables -t nat -A PREROUTING -i $interface -p tcp -j DNAT --to-destination $ip:80
echo -e "${RED}[+]${NC} Checking iptables configuration\n"
sleep .5
dnat=$(iptables -L -t nat | grep DNAT)
echo "$dnat"
