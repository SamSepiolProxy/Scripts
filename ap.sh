#!/bin/bash

if [[ $EUID -ne 0 ]]; then
  echo "Script must be run as a root user" 2>&1
  exit 1
fi

echo -n "Enter the AP device name [ENTER]: "
read accesspoint
echo

echo -n "Enter the uplink device name [ENTER]: "
read uplink
echo

func_create_ap_config() {
cat > /opt/ap/hostapd.conf <<EOF
interface=$accesspoint
driver=nl80211
ssid=testwifi
hw_mode=g
channel=7
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=password123
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP
EOF
}

func_create_dnsmasq_profile() {
cat > /opt/ap/dnsmasq.conf <<EOF
interface=$accesspoint
dhcp-range=192.168.30.2,192.168.30.230,255.255.255.0,12h
dhcp-option=3,192.168.30.1
dhcp-option=6,192.168.30.1
server=8.8.8.8
server=8.8.4.4
log-queries
log-dhcp
listen-address=127.0.0.1
listen-address=192.168.30.1
conf-file=/opt/ap/dnsmasq.blacklist.txt
log-facility=/opt/ap/dnsmasq.log
EOF

cat > /opt/ap/dnsmasq.blacklist.txt <<EOF
address=/example.com/#
EOF
}

func_ip_setup() {
ip a a 192.168.30.1/24 dev wlan0
route add -net 192.168.30.0 netmask 255.255.255.0 gw 192.168.30.1
iptables --table nat --append POSTROUTING --out-interface $uplink -j MASQUERADE
iptables --append FORWARD --in-interface $accesspoint -j ACCEPT
echo 1 > /proc/sys/net/ipv4/ip_forward
}

func_kill_conflicts() {
#stops NetworkManage conflict
sudo nmcli device set ifname $accesspoint managed no
#stops airmon conflict
sudo airmon-ng stop ${accesspoint}mon
#Mainly for Ubuntu stops systemd-resolved as it conflicts with dnsmasq
systemctl stop systemd-resolved
}

mkdir /opt/ap
func_create_ap_config
func_create_dnsmasq_profile
func_ip_setup
func_kill_conflicts
hostapd /opt/ap/hostapd.conf -B -f /opt/ap/ap.log
dnsmasq -C /opt/ap/dnsmasq.conf
echo "To kill the processes use the following commands:"
echo
echo "pkill -f hostapd"
echo
echo "pkill -f dnsmasq"