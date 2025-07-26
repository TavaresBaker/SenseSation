# SenseSation

## Background

**SenseSation** is a collection of scripts designed to defend **pfSense routers** against cyber attacks.

My name is **Tavares Baker**, and I’m a sophomore in college preparing for the bi-annual **University at Buffalo Lockdown** competition. I created these scripts to **automate and accelerate the system-cleansing process**, aiming to remove red team presence from the router before they can cause serious damage.

---

## Recommendation

**SenseSation** is intended primarily for **cybersecurity competitions** that involve a **pfSense firewall in the network topology**. In these environments, **uptime is the #1 priority**, and reinstalling the OS is often not an option.

> **If you can reinstall, DO IT. DO NOT USE THIS.**

There are programs and artifacts that **SenseSation cannot catch**, which can lead to reinfection. But if you **can’t afford to reinstall**, welcome to my humble project — let's make the best of a bad situation.

---

## What SenseSation Does

- Repairs critical binaries that may have been corrupted or altered  
- Restores startup scripts and PHP files to break most web shells and persistence  
- Detects added users — even hidden ones — to manage privileges and permissions  
- Searches the filesystem for webhooks that could exfiltrate sensitive data (e.g., passwords)  
- Scavenges for entry points like web shells, reverse shells, or rogue bash sessions  
- Disables SSH by removing associated config files for maximum security  
- Automates the deployment of **pfBlockerNG** and **Snort** for rapid hardening  
- Scans the filesystem for ransomware and malicious scripts  
- Analyzes active processes for suspicious behavior  

---

## How It Works

Once the setup script is run, **SenseSation** will:

- Create the required directories  
- Generate the core cleanup and utility scripts  
- Move and back up essential files  
- Conclude with a success or failure message  

After the setup is complete, return to the **console menu** and run each cleanup step **in order starting from Option 2**. If you're just doing **initial configuration**, you can safely skip most of the cleanup-specific steps.
