#!/bin/bash

# Check for sudo permissions
if [ "$(id -u)" -ne 0 ]; then
    echo "You need to run this script as root or with sudo privileges."
    exit 1
fi

# Prompt user for input for internal network
echo "Configuring internal network:"
read -p "Enter the internal interface name (e.g., eth0): " INTERNAL_INTERFACE
read -p "Enter the internal IP address: " INTERNAL_IP
read -p "Enter the internal subnet mask (e.g., 255.255.255.0): " INTERNAL_SUBNET
read -p "Enter the internal gateway IP address: " INTERNAL_GATEWAY
read -p "Enter the DNS server IP address: " DNS_SERVER

# Display the provided information
echo "Configuring internal network with the following details:"
echo "Internal Network (Interface: $INTERNAL_INTERFACE)"
echo "Internal IP: $INTERNAL_IP"
echo "Internal Subnet: $INTERNAL_SUBNET"
echo "Internal Gateway: $INTERNAL_GATEWAY"
echo "DNS Server: $DNS_SERVER"

# Bring down the internal interface
sudo ifconfig $INTERNAL_INTERFACE down

# Assign the static IP, subnet, and gateway for internal network
sudo ifconfig $INTERNAL_INTERFACE $INTERNAL_IP netmask $INTERNAL_SUBNET up
sudo route add default gw $INTERNAL_GATEWAY $INTERNAL_INTERFACE

# Configure DNS
echo "nameserver $DNS_SERVER" | sudo tee /etc/resolv.conf > /dev/null

# Display the updated network configurations
echo "Internal network configuration updated:"
ifconfig $INTERNAL_INTERFACE
route -n
cat /etc/resolv.conf
