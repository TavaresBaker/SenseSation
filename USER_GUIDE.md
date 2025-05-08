# SenseSation User Guide

## Getting the File

### Downloading It

You can use:

```sh
fetch https://raw.githubusercontent.com/TavaresBaker/SenseSation/refs/heads/main/SenseSation.sh
```

### Copy/Pasting It

1. Go to the GitHub repo or any source where the script is hosted and copy it.
2. Log in to the web GUI and go to **Diagnostics > Edit File**.
3. Paste the script into a blank file and save it.

## Running It

```sh
chmod +x SenseSation.sh
./SenseSation.sh
```

## Using It

A menu will appear resembling the original pfSense console menu. You can select various sub-scripts to assist in cleaning compromised boxes.

- Each option that removes or modifies files will back them up into a quarantined and zipped directory for **OPSEC** purposes.
- Some options require manual review. For example, the **webhook script** will highlight potential webhook entries—you must use discretion to determine what's malicious and whether to delete it.
- Others run automatically, such as the **restore file script**, which replaces the entire `/usr/local/www` directory to recover the GUI from red team modifications.

## Cleanup

At the end of the competition, **delete the script from the router**.

We do **not** want anyone from the University at Buffalo to access it, as that would undermine future blue team efforts for the NET side of competitions. While they might be able to look it up, the script is not human-readable without context.