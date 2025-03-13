#!/bin/bash

# Check if script is run as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be ran as a sudo user, or root!"
   exit 1
fi

# Function to disable a user
disable_user() {
    if id "$1" &>/dev/null; then
        usermod -L -e 1 "$1" && echo "User $1 has been disabled."
    else
        echo "User $1 does not exist. Try again."
    fi
}

echo "Enter the usernames to disable (one per line). Press Ctrl+D when finished:"

# Read usernames from input
users_to_disable=()
while IFS= read -r username; do
    users_to_disable+=("$username")
done

echo "Disabling specified users..."

# Disable users from the input
for user in "${users_to_disable[@]}"; do
    disable_user "$user"
done

echo "Users have been disabled!"
