# Mint Software Auditor

Scans a Linux Mint machine for non-work or potentially malicious software and sorts what it finds into categories (games, password cracking, network tools, and so on).

It is **report-only**. It never deletes, kills, quarantines or changes anything. It records file paths, owners and SHA-256 hashes, and does not read file contents beyond hashing.

## Requirements

- Linux Mint (or any Ubuntu/Debian-based system)
- Python 3 (already installed on Mint)
- tkinter for the window version: `sudo apt install python3-tk`

## How to run

1. Put `mint_scanner.py` in a folder (for example Downloads).
2. Right-click an empty spot in that folder and choose **Open in Terminal**.
3. Run one of:

```
sudo -E python3 mint_scanner.py                 # window with a "Scan now" button
sudo python3 mint_scanner.py --cli              # results printed in the terminal
sudo python3 mint_scanner.py --cli --csv report.csv --json report.json
sudo python3 mint_scanner.py --cli --no-files   # skip the file search (faster)
```

Use `sudo`. Without it the scanner can't read other users' home folders.

## Using the window

- **Scan now** runs a full scan. Run it as often as you like.
- Results are grouped by category. Click the arrow next to a category to expand it.
- **Export CSV / Export JSON** save the results.
- **Include file scan** can be unticked for a quicker packages-and-processes-only scan.

## What it checks

- Installed packages (apt, snap, flatpak)
- Services and running processes
- Installed commands in `/usr/bin`, `/usr/local/bin`, `/opt` and similar
- Files and folders in every user's home folder, `/root`, `/opt`, `/tmp`, `/var/tmp`, `/var/www`, `/usr/local`, `/mnt` and `/media`
- File types: audio/video, `.exe`/`.deb`/`.AppImage`/`.run` installers, `.torrent`

## Categories

Password cracking, Wireless attack tools, Network scanners & sniffers, Exploitation & web attack tools, Remote access & backdoors, Server software, Games, Torrents & file sharing, Chat & social apps, Media & entertainment apps, Anonymity/VPN/proxy tools, Malware/miners/keyloggers, Password lists & wordlists, Media files, Installers & executables, Torrent files.

## Customising

Open `mint_scanner.py` in a text editor. Near the top:

- **`CATEGORIES`**: add or remove names (lowercase) to change what gets flagged, or add a new category.
- **`ALLOWLIST`**: names to ignore, for software your scenario requires. Example: `ALLOWLIST = {"apache2", "openssh-server"}`
- **`EXTRA_ROOTS`**: more folders to search for files.

Names match as whole words, so `john` flags `john-data` but not `johnson`.

## Limits

- Renaming a file defeats name matching. The SHA-256 hash in the report helps you spot known files regardless of name.
- Some findings are legitimate (system installers, media files). Review before acting.
- It only sees the machine it runs on, and only what the account running it can read, so run it as root.
