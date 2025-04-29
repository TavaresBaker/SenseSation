# SenseSation
A compilation of scripts to fight cyber attacks against pfSense

My name is Tavares Baker, and at the time of writing this, I was a freshman in college preparing for the bi-annual University at Buffalo Lockdown competition. I decided to create scripts to automate and speed up my system cleansing process, aiming to kick the red team out before they could do any damage to the router. Unfortunately, the first complete draft of my script wasn't finished in time.

However, I was still able to use many of the concepts and partial scripts to my advantage during the competition. While they helped, they weren't quite enough. I did manage to completely remove the red team from the router—excluding a brief incident where I was PWNed by a LAN machine. I've since learned from those mistakes.

Despite that hiccup, I achieved 97% uptime for the router. It was down for only 8 minutes over 4.5 hours, 5 of which were due to me restarting the router.

In general, your best bet is to just reboot the operating system onto the device if you were genuinely hacked especially if it's for home use. If you need this for a business to keep operstions running I would honestly suggest downloading the files, then disconnecting your wan interface. The downtime might not be great, but it is a hell of a lot better than permanent donwtime. 

The main program has a few function as it creates directories for later use, replaces rc.initial with a modified version, presents you with a menu of cleanup options, and if for any reason the script stops, the origional rc.initial file is restored.
