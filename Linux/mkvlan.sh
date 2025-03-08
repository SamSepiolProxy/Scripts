#!/usr/bin/env bash

INT_NAME="${1}"
VLAN_ID="${2}"
IP_ADDRESS="${4}"
GATEWAY="${5}"

manual() {
	ip link add link ${INT_NAME} name ${INT_NAME}.$VLAN_ID type vlan id $VLAN_ID
	ip addr add ${IP_ADDRESS} dev ${INT_NAME}.$VLAN_ID
	ip link set ${INT_NAME}.$VLAN_ID up
}

mangateway() {
	ip link add link ${INT_NAME} name ${INT_NAME}.$VLAN_ID type vlan id $VLAN_ID
	ip addr add ${IP_ADDRESS} dev ${INT_NAME}.$VLAN_ID
	ip route add default via ${GATEWAY}
}

dhcp() {
	ip link add link ${INT_NAME} name ${INT_NAME}.$VLAN_ID type vlan id $VLAN_ID
	dhclient ${INT_NAME}.$VLAN_ID
}

delete(){
	ip link del link ${INT_NAME} name ${INT_NAME}.$VLAN_ID
}


if [ -z "$INT_NAME" ] || [ -z "$VLAN_ID" ]
then
	echo "Usage: $0 [ INTERFACE NAME ] [ VLAN ID ] { m[anual] | dh[cp] | d[el] | g[ateway]} [IP ADDRESS] [GATEWAY]
Example for create vlan 10 with dhcp: eth1 $0 10 dh manual: $0 eth1 10 manual 10.0.0.5/24 gateway: $0 eth1 10 gateway 10.0.0,1/24 10.0.0.1 del: $0 eth1 10"
else
	case "$3" in
		m|manual)		manual ;;
		g|ateway)		gateway ;;
		dh|dhcp)		dhcp ;;
		d|del)			delete ;;
		*)			echo "Usage: $0 [ INTERFACE NAME ] [ VLAN ID ] m[anual] | dh[cp] | d[el] | g[ateway] [IP ADDRESS] [GATEWAY]" >&2
					exit 1 ;;
	esac
fi
