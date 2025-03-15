#!/bin/bash


# MODIFY ACCORDINGLY
INTERFACE="eth0"
DEFAULT_IP="192.168.16.4"
DEFAULT_NETMASK="255.255.255.0"
DEFAULT_GATEWAY="192.168.16.1"

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

if ip addr show $INTERFACE | grep -q "state UP"; then
    echo "$INTERFACE is now up and running."
else
    echo "Failed to bring up $INTERFACE."
fi