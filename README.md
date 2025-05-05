# SenseSation

SenseSation is a collection of scripts designed to defend pfSense routers against cyber attacks.

My name is Tavares Baker. At the time of writing this, I was a freshman in college preparing for the bi-annual University at Buffalo Lockdown competition. I created these scripts to automate and speed up the system-cleansing process, aiming to kick the red team off the router before they could cause significant damage. Unfortunately, the first draft of SenseSation wasn’t finished in time.

Despite that, I was able to use many of the concepts and partial scripts during the competition. While they helped, they weren’t quite enough. I did manage to completely remove the red team from the router—aside from a brief moment when I was PWNed by a LAN machine. I’ve since learned from that experience.

Even with that hiccup, I maintained 97% uptime for the router. It was down for only 8 minutes over 4.5 hours, 5 of which were from a manual reboot.

## Recommendation: 
If you suspect your device has been compromised—especially in a home environment—your best option is to reinstall the operating system.
For business-critical environments, download the scripts, disconnect the WAN interface, and proceed with caution. Some downtime is better than permanent downtime.

## What SenseSation Does

- Creates necessary directories for use during cleanup
- Replaces rc.initial with a modified version that presents a menu of cleanup options
- Automatically restores the original rc.initial if the script is interrupted
- Offers staged cleanup procedures tailored to your situation
- Backs up and/or quarantines any file it modifies

## Why Use SenseSation?

SenseSation is built to detect persistence and tampering on your pfSense machine. Instead of writing or downloading multiple cleanup scripts, you only need this one tool. It streamlines the process, offering a guided approach to remediation and helping you regain control of your router with minimal hassle.
