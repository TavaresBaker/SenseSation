#!/bin/sh

# Ensure script runs with root privileges
if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root." >&2
  exit 1
fi

# Prompt user for action
echo "What do you want to do with SSH?"
echo "1) Disable SSH service only (kill sessions, keep keys/config)"
echo "2) Completely destroy SSH (disable + remove keys/config + kill sessions)"
echo "3) Restart SSH service"
read -rp "Enter 1, 2, or 3: " CHOICE

if [ "$CHOICE" != "1" ] && [ "$CHOICE" != "2" ] && [ "$CHOICE" != "3" ]; then
  echo "Invalid choice. Exiting."
  exit 1
fi

case "$CHOICE" in
  1|2)
    # Step 1: Disable SSH Service on pfSense
    echo "Disabling SSH service on pfSense..."
    pfSsh.php playback disable_ssh

    # Step 2: Kill all running SSH processes
    echo "Killing all running SSH processes..."
    for pid in $(pgrep sshd); do
      kill -9 "$pid" 2>/dev/null
    done

    if [ "$CHOICE" = "2" ]; then
      # Remove SSH Keys (private and public)
      echo "Removing SSH keys..."
      rm -f /root/.ssh/id_rsa /root/.ssh/id_dsa /root/.ssh/id_ecdsa /root/.ssh/id_ed25519
      rm -f /root/.ssh/authorized_keys

      # Clear SSH Config Files
      echo "Clearing SSH config files..."
      rm -f /etc/ssh/sshd_config
      rm -f /etc/ssh/ssh_config
      rm -f /usr/local/etc/ssh/sshd_config

      # Remove any potential SSH key files anywhere
      echo "Searching for additional SSH key files..."
      find / -type f \( -name "id_rsa" -o -name "id_dsa" -o -name "*.pem" -o -name "*.key" \) -exec rm -f {} \;
    fi

    # Disable SSH in pfSense's Web GUI (if enabled)
    echo "Disabling SSH in pfSense's Web GUI (if enabled)..."
    pfSsh.php playback disable_ssh_gui

    # Step 3: Check status
    echo "Checking SSH status..."
    if ! ps aux | grep -q '[s]shd'; then
      echo "SSH service is disabled and all SSH sessions are terminated."
      [ "$CHOICE" = "2" ] && echo "SSH has been completely destroyed (keys/config removed)."
    else
      echo "SSH processes are still running."
    fi
    ;;
  3)
    # Restart SSH
    echo "Restarting SSH service on pfSense..."
      pfSsh.php playback enablesshd

    echo "SSH should now be running. Verifying..."
    if ps aux | grep -q '[s]shd'; then
      echo "SSH service is running."
    else
      echo "Failed to start SSH service."
    fi
    ;;
esac
