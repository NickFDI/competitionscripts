#!/bin/bash

# Define suspicious patterns (modify as needed)
SUSPICIOUS_PATTERNS=(
    "entered promiscuous mode"
    "Oversized packet received from"
    "imuxsock begins to drop messages"
    "Deactivating service"
    "Failed password"
    "reverse path filtering"
    "possible SYN flooding"
    "scan detected"
    "pty_.*session opened"
    "sudo:.*user=root"
    "session opened for user.*by.*uid=0"
    "reverse mapping checking failed"
)

# Define known legitimate processes (modify as needed)
KNOWN_PROCESSES=(
    "systemd"
    "dbus-daemon"
    "gvfsd"
    "gvfsd-dnssd"
    "xfwm4"
    "xfce4-panel"
    "xfdesktop"
    "xfsettingsd"
    "vmtoolsd"
    "sublime_text"
    "qterminal"
    "blueman-applet"
    "sshd"
    "cron"
    "rsyslogd"
    "NetworkManager"
    "polkitd"
)

# Define suspicious processes (modify as needed)
SUSPICIOUS_PROCESSES=(
    "nmap"
    "netcat"
    "socat"
    "masscan"
    "hydra"
    "metasploit"
    "msfconsole"
    "weevely"
    "c99shell"
    "wget.*/tmp/"
    "curl.*-o.*/dev/shm"
    "sh -c"
    "python3"
    "zsh"
)

# Function to check if a given entry is suspicious
is_suspicious_entry() {
    local text="$1"

    # Skip known good processes
    for known in "${KNOWN_PROCESSES[@]}"; do
        if [[ "$text" == *"$known"* ]]; then
            return 1  # Not suspicious
        fi
    done

    # Check for suspicious patterns
    for pattern in "${SUSPICIOUS_PATTERNS[@]}" "${SUSPICIOUS_PROCESSES[@]}"; do
        if [[ "$text" =~ $pattern ]]; then
            return 0  # Suspicious
        fi
    done

    return 1  # Not suspicious
}

# Get all logged-in users
# shellcheck disable=SC2207
LOGGED_IN_USERS=($(who | awk '{print $1}' | sort | uniq))

echo "Currently logged-in users:"
for user in "${LOGGED_IN_USERS[@]}"; do
    echo " - $user"
done

# Compare against known users
KNOWN_USERS=(
    "daemon" "bin" "sys" "sync" "games" "man" "lp" "mail"
    "news" "uucp" "proxy" "www-data" "backup" "list" "irc"
    "_apt" "nobody"
)
UNKNOWN_USERS=()
VALID_USERS=()

echo "Checking for unauthorized users..."
for user in "${LOGGED_IN_USERS[@]}"; do
    if [[ " ${KNOWN_USERS[*]} " == *" $user "* ]]; then
        VALID_USERS+=("$user")
    else
        UNKNOWN_USERS+=("$user")
    fi
done

if [ ${#UNKNOWN_USERS[@]} -gt 0 ]; then
    echo "ALERT! Possible Unauthorized Users:"
    for user in "${UNKNOWN_USERS[@]}"; do
        echo " - $user"
    done
fi

# define logged-in users for manual selection
AVAILABLE_USERS=("${LOGGED_IN_USERS[@]}")

if [ ${#AVAILABLE_USERS[@]} -eq 0 ]; then
    echo "No users found. Exiting."
    exit 1
fi

# Allow manual selection of a user for inspection
echo "Select a user to inspect:"
select TARGET_USER in "${AVAILABLE_USERS[@]}"; do
    if [ -n "$TARGET_USER" ]; then
        break
    else
        echo "Invalid selection. Try again."
    fi
done

echo "Inspecting user: $TARGET_USER"

# Networking check function
check_networking() {
    local filename="${TARGET_USER}networking.txt"
    echo "Suspicious network connections for $TARGET_USER:" > "$filename"

    # Get the IP address of the network adapter (replace 'eth0' with your interface name)
    local interface="eth0" # Change this if needed (e.g., enp0s3)
    # shellcheck disable=SC2155
    local my_ip=$(ip addr show "$interface" | grep "inet " | awk '{print $2}' | cut -d'/' -f1)

    # If we couldn't get the IP address, use 127.0.0.1 as a fallback (change fallback if needed)
    if [ -z "$my_ip" ]; then
        echo "WARNING: Could not determine IP address of interface '$interface'.  Falling back to 127.0.0.1" >> "$filename"
        my_ip="127.0.0.1"
    fi

    echo "Excluding connections to/from IP: $my_ip" >> "$filename"

    if command -v ss &>/dev/null; then
        ss -tuln | grep -v "$my_ip" | while read -r line; do
            if is_suspicious_entry "$line"; then
                echo "[SUSPICIOUS CONNECTION] $line" >> "$filename"
            else
                echo "[CONNECTION] $line" >> "$filename"
            fi
        done
    elif command -v netstat &>/dev/null; then
        netstat -tuln | grep -v "$my_ip" | while read -r line; do
             if is_suspicious_entry "$line"; then
                echo "[SUSPICIOUS CONNECTION] $line" >> "$filename"
            else
                echo "[CONNECTION] $line" >> "$filename"
            fi
        done
    else
        echo "Neither ss nor netstat commands are available." >> "$filename"
    fi
    echo "Networking check complete. Results saved to $filename"
}


# Process check function
check_processes() {
    local filename="${TARGET_USER}processes.txt"
    echo "Suspicious processes for $TARGET_USER:" > "$filename"
    ps -u "$TARGET_USER" -o pid=,comm=,args= | while read -r pid comm args; do
        if is_suspicious_entry "$comm $args"; then
            echo "[SUSPICIOUS PROCESS] PID: $pid, Command: $comm, Args: $args" >> "$filename"
        fi
    done
    echo "Process check complete. Results saved to $filename"
}

# File check function
check_files() {
    local filename="${TARGET_USER}files.txt"
    echo "Suspicious open files by $TARGET_USER:" > "$filename"
    if command -v lsof &>/dev/null; then
        lsof -u "$TARGET_USER" 2>/dev/null | while read -r line; do
            if is_suspicious_entry "$line" || [[ "$line" =~ /tmp/|/dev/shm|\.php$|unusual/path ]]; then
                echo "[OPEN FILE] $line" >> "$filename"
            elif [[ "$line" =~ \.so$ ]] && ! [[ "$line" =~ /usr/lib/ ]]; then
                echo "[OPEN FILE] $line" >> "$filename"
            fi
        done
    else
        echo "lsof unavailable." >> "$filename"
    fi
    echo "File check complete. Results saved to $filename"
}

# Manual selection menu
while true; do
    echo "Choose an action:"
    echo "1) Check Networking"
    echo "2) Check Processes"
    echo "3) Check Files"
    echo "4) Exit"
    read -p "Enter your choice (1-4): " choice

    case "$choice" in
        1)
            check_networking
            ;;
        2)
            check_processes
            ;;
        3)
            check_files
            ;;
        4)
            echo "Exiting."
            exit 0
            ;;
        *)
            echo "Invalid choice. Please enter a number between 1 and 4."
            ;;
    esac
done
