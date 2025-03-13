#!/bin/bash

# Check root privileges
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root. Use sudo or run as root user." >&2
    exit 1
fi

# Detect OS and set sudo group
source /etc/os-release
case $ID in
    ubuntu|kali)
        sudo_group="sudo"
        ;;
    rocky)
        sudo_group="wheel"
        ;;
    *)
        if getent group sudo >/dev/null; then
            sudo_group="sudo"
        elif getent group wheel >/dev/null; then
            sudo_group="wheel"
        else
            echo "Unsupported OS or missing sudo group. Try again!" >&2
            exit 1
        fi
        ;;
esac

# List of usernames, one of these will randomly be chosen.
# If for whatever reason you need more than 4 sudo users,
# add additional users to the list.
usernames=("management" "abovetherest" "blueteam" "theyknowtoomuch")

# Function to check if a user exists
user_exists() {
    getent passwd "$1" > /dev/null 2>&1
}

# Randomly select a username that doesn't exist
selected_username=""
for i in {1..20}; do  # Try up to 20 times to find an available username
    potential_username=${usernames[$RANDOM % ${#usernames[@]}]}
    if ! user_exists "$potential_username"; then
        selected_username="$potential_username"
        break
    fi
done

if [[ -z "$selected_username" ]]; then
    echo "Error: Could not find an available username. Add additional usernames, or delete a user!" >&2
    exit 1
fi

# Generate random password (16 characters alphanumeric)
password=$(openssl rand -base64 20 | tr -dc 'a-zA-Z0-9' | head -c 16)
encrypted_pw=$(openssl passwd -1 "$password")

# Create user with generated credentials
if ! useradd -m -s /bin/bash -p "$encrypted_pw" "$selected_username"; then
    echo "Failed to create user $selected_username. Exiting." >&2
    exit 1
fi

# Add to sudo group
if ! usermod -aG "$sudo_group" "$selected_username"; then
    echo "Failed to add $selected_username to $sudo_group group. Exiting." >&2
    exit 1
fi

# Force password change on next login
passwd --expire "$selected_username" >/dev/null

# Output results
echo "User created successfully:"
echo "Username: $selected_username"
echo "Temporary password: $password"
echo "User must change password at next login"
echo "Sudo group used: $sudo_group"
