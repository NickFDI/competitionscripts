#!/bin/bash


# MODIFY ACCORDINGLY
INTERFACE="Change Interface"
DEFAULT_IP="192.168.x.x"
DEFAULT_NETMASK="255.255.x.x"
DEFAULT_GATEWAY="192.168.x.x"
DEFAULT_DNS="some.hostname.net"

# Check the networking interface
if ! ip link show | grep -q "$INTERFACE"; then
  echo "Error: Cant find the network interface $INTERFACE"
  exit
fi

# Prompt user
read -r -p "Is this the correct interface you want to modify? ($INTERFACE) [y/N]: " CONFIRM
if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    echo "Operation canceled."
    exit 0
fi

ip addr add $DEFAULT_IP/$DEFAULT_NETMASK dev $INTERFACE

ip route add default via $DEFAULT_GATEWAY

ip link set $INTERFACE up

echo "nameserver $DEFAULT_DNS" | sudo tee /etc/resolv.conf > /dev/null

if ip addr show $INTERFACE | grep -q "state UP"; then
    echo "$INTERFACE is now up and running."
    echo "DNS server set to $DEFAULT_DNS."
    echo "Gateway set to $DEFAULT_GATEWAY."

else
    echo "Failed to bring up $INTERFACE."
fi