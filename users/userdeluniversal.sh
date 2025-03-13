#!/bin/bash

# Check root privileges
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root, or with sudo permissions!" >&2
    exit 1
fi

# Function to verify user existence
user_exists() {
    getent passwd "$1" >/dev/null 2>&1
}

# Function to delete user
delete_user() {
    if user_exists "$1"; then
        echo "Deleting user: $1"
        if userdel -rf "$1" 2>/dev/null; then
            echo "Successfully deleted user: $1"
        else
            echo "Failed to delete user: $1 (try manual removal)" >&2
        fi
    else
        echo "User $1 does not exist. Skipping."
    fi
}

# Read user input
echo "Enter users to delete (one per line, Ctrl+D to finish):"
users_to_delete=()
while IFS= read -r username; do
    [[ -n "$username" ]] && users_to_delete+=("$username")
done

# Delete users
for user in "${users_to_delete[@]}"; do
    delete_user "$user"
done

echo "Users deleted!"
