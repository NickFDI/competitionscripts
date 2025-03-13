#!/bin/bash

# Ensure the script is run with sudo
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit
fi

# Prompt user for network configuration details
read -p "Enter the network interface (e.g., eth0 or wlan0): " interface
read -p "Enter the static IP address with subnet mask (e.g., 192.168.1.10/24): " ip_address_mask
read -p "Enter the default gateway: " gateway
read -p "Enter the primary DNS server: " dns1
read -p "Enter the secondary DNS server (optional): " dns2

# Backup existing network configuration file
cp /etc/network/interfaces /etc/network/interfaces.bak

# Configure the network interface with static IP settings
cat <<EOF > /etc/network/interfaces
auto lo
iface lo inet loopback

auto $interface
iface $interface inet static
    address $ip_address_mask
    gateway $gateway
    dns-nameservers $dns1 $dns2
EOF

# Restart networking service to apply changes
systemctl restart networking

# Verify the new network configuration
echo "Updated network configuration:"
ip addr show dev $interface

echo "DNS configuration:"
cat /etc/resolv.conf

echo "Network settings successfully updated!"
