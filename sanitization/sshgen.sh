#!/bin/bash
# Run with sudo perms, or root.

# Paths
USER_LIST_FILE="./userlist.txt"  # File containing list of users
WHITELIST=("Unknown" "Unknown")  # Users whose keys should not be removed

# Static SSH Key (Embedded in memory) Modify as needed, should key be
# provided for scoring, add it here.
SSH_KEY=" "

# Check for user file. Make sure to create a file in the running directory.
if [[ ! -f "$USER_LIST_FILE" ]]; then
    echo "User list file not found: $USER_LIST_FILE"
    exit 1
fi

# Read user list from file (One user per line)
mapfile -t USER_LIST < "$USER_LIST_FILE"

# Check if the username exists.
in_array() {
    local needle="$1"
    shift
    [[ " $* " =~  (.*\s)?$needle(\s.*)? ]]
}

# Process each user in the list
for user in "${USER_LIST[@]}"; do
    USER_HOME="/home/$user"
    USER_SSH_DIR="$USER_HOME/.ssh"

    # Skip users without a valid home directory
    if [[ ! -d "$USER_HOME" ]]; then
        echo "Skipping $user (home directory not found)"
        continue
    fi

    # Securely create .ssh directory
    install -d -m 700 -o "$user" -g "$user" "$USER_SSH_DIR"

    # Write private key directly from memory
    echo "$SSH_KEY" > "$USER_SSH_DIR/id_rsa"
    chmod 600 "$USER_SSH_DIR/id_rsa"
    chown "$user:$user" "$USER_SSH_DIR/id_rsa"

    # Generate public key in-memory and write it
    ssh-keygen -y -f <(echo "$SSH_KEY") > "$USER_SSH_DIR/id_rsa.pub"
    chmod 644 "$USER_SSH_DIR/id_rsa.pub"
    chown "$user:$user" "$USER_SSH_DIR/id_rsa.pub"

    echo "Installed SSH key for $user"
done

# Find users with home directories but not in the user list or whitelist
for home in /home/*; do
    user=$(basename "$home")

    # Skip users who are in the user list or whitelist
    if in_array "$user" "${USER_LIST[@]}" || in_array "$user" "${WHITELIST[@]}"; then
        echo "Preserved keys for $user"
        continue
    fi

    USER_SSH_DIR="$home/.ssh"

    # If the SSH directory exists, clear out the SSH keys
    if [[ -d "$USER_SSH_DIR" ]]; then
        find "$USER_SSH_DIR" -type f -name "id_rsa*" -exec rm -f {} \;
        echo "Removed SSH keys for $user"
    fi
done

echo "SSH key setup complete."
