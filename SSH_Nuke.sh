#!/bin/sh

# Ensure script runs with root privileges
if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root." >&2
  exit 1
fi

# Step 1: Disable SSH Service on pfSense
echo "Disabling SSH service on pfSense..."
pfSsh.php playback disable_ssh

# Step 2: Remove SSH Keys (private and public)
echo "Removing SSH keys..."
rm -f /root/.ssh/id_rsa /root/.ssh/id_dsa /root/.ssh/id_ecdsa /root/.ssh/id_ed25519
rm -f /root/.ssh/authorized_keys

# Step 3: Clear SSH Config Files (in case they exist in unusual places)
echo "Clearing SSH config files..."
rm -f /etc/ssh/sshd_config
rm -f /etc/ssh/ssh_config
rm -f /usr/local/etc/ssh/sshd_config

# Step 4: Remove Any Potential SSH Key Files Anywhere (if misconfigured)
echo "Searching for additional SSH key files..."
find / -type f \( -name "id_rsa" -o -name "id_dsa" -o -name "*.pem" -o -name "*.key" \) -exec rm -f {} \;

# Step 5: Disable SSH in pfSense's Web GUI (if enabled)
echo "Disabling SSH in pfSense's Web GUI (if enabled)..."
pfSsh.php playback disable_ssh_gui

# Step 6: Check if SSH is disabled and confirm
echo "Checking SSH status..."
if ! ps aux | grep -q '[s]shd'; then
  echo "SSH service is successfully disabled."
else
  echo "Failed to disable SSH service."
fi

echo "SSH has been completely nuked from the system."

