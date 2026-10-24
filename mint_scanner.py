#!/usr/bin/env python3
"""
Mint Software Auditor
=====================
Scans a Linux Mint VM for prohibited / non-work / potentially malicious
software and sorts the findings into categories.

REPORT-ONLY: it never deletes, kills, quarantines or modifies anything.
It records file paths, owners and SHA-256 hashes, but never reads file
contents beyond hashing.

Usage
-----
  sudo -E python3 mint_scanner.py              # GUI with a "Scan now" button
  sudo python3 mint_scanner.py --cli           # scan in the terminal
  sudo python3 mint_scanner.py --cli --csv report.csv --json report.json
  sudo python3 mint_scanner.py --cli --no-files   # skip the file-system walk

Run it with sudo/root so it can read every user's home directory.

Customising
-----------
* Add or remove names in CATEGORIES below (lowercase). A name matches a
  package, binary, process, service, file or folder whose name contains it
  as a whole "word" (so "john" matches "john-data" but not "johnson").
* Add names to ALLOWLIST to ignore them (e.g. software your scenario requires).
"""

import argparse
import csv
import datetime
import hashlib
import json
import os
import pwd
import re
import socket
import subprocess
import sys
from collections import defaultdict

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

# Exact names (lowercase) to ignore, e.g. {"apache2"} if the scenario needs it.
ALLOWLIST = set()

CATEGORIES = {
    "Password cracking": [
        "ophcrack", "john", "johnny", "hashcat", "hydra", "medusa", "ncrack",
        "patator", "brutespray", "crunch", "cewl", "fcrackzip", "pdfcrack",
        "rarcrack", "chntpw", "rainbowcrack", "rcrack", "sucrack", "hashid",
        "l0phtcrack", "pwdump", "mimikatz", "lazagne", "cowpatty", "asleap",
        "pixiewps",
    ],
    "Wireless attack tools": [
        "aircrack", "airodump", "aireplay", "airmon", "wifite", "reaver",
        "bully", "fern-wifi-cracker", "kismet", "wifiphisher", "mdk3", "mdk4",
        "eaphammer", "fluxion",
    ],
    "Network scanners & sniffers": [
        "nmap", "zenmap", "masscan", "zmap", "wireshark", "tshark", "tcpdump",
        "ettercap", "dsniff", "bettercap", "netdiscover", "arp-scan", "nikto",
        "unicornscan", "hping3", "netcat", "ncat", "nc", "socat", "fping",
        "angryip", "ipscan", "driftnet", "sslstrip", "dnsenum", "dnsrecon",
        "nbtscan", "enum4linux", "snort", "tcpflow", "ngrep", "iptraf",
        "macchanger", "mitmproxy", "yersinia", "p0f",
    ],
    "Exploitation & web attack tools": [
        "metasploit", "msfconsole", "msfvenom", "msfdb", "sqlmap", "burpsuite",
        "zaproxy", "beef-xss", "exploitdb", "searchsploit", "setoolkit",
        "social-engineer-toolkit", "commix", "wpscan", "w3af", "skipfish",
        "gobuster", "dirb", "dirbuster", "ffuf", "wfuzz", "weevely", "veil",
        "shellter", "nessus", "openvas", "greenbone", "sqlninja", "bloodhound",
        "linpeas", "pspy", "pwncat", "nuclei", "joomscan", "droopescan",
        "xsser",
    ],
    "Remote access & backdoors": [
        "teamviewer", "anydesk", "rustdesk", "x11vnc", "tightvncserver",
        "vnc4server", "tigervnc", "vino", "xrdp", "ngrok", "chrome-remote-desktop",
        "realvnc", "vncserver", "telnetd", "rsh-server", "cryptcat", "noip2",
        "splashtop", "parsec", "logmein",
    ],
    "Server software (verify if required)": [
        "apache2", "nginx", "lighttpd", "httpd", "tomcat", "mysql-server",
        "mariadb-server", "postgresql", "vsftpd", "proftpd", "pure-ftpd",
        "tftpd", "atftpd", "samba", "smbd", "nmbd", "nfs-kernel-server",
        "bind9", "snmpd", "openssh-server", "sshd", "dovecot", "postfix",
        "exim4", "sendmail", "squid", "php", "telnet", "xinetd",
        "isc-dhcp-server", "slapd",
    ],
    "Games": [
        "steam", "steamcmd", "lutris", "wine", "winetricks", "playonlinux",
        "retroarch", "dolphin-emu", "pcsx2", "rpcs3", "yuzu", "ryujinx",
        "mgba", "desmume", "snes9x", "mupen64plus", "dosbox", "scummvm",
        "openra", "minecraft", "minetest", "luanti", "supertuxkart",
        "supertux", "0ad", "wesnoth", "openttd", "freeciv", "pingus",
        "frozen-bubble", "gnome-games", "aisleriot", "gnome-mahjongg",
        "gnome-mines", "gnome-sudoku", "gnome-chess", "gnome-nibbles",
        "gnome-robots", "gnome-klotski", "gnome-taquin", "gnome-tetravex",
        "gnome-2048", "five-or-more", "four-in-a-row", "hitori", "iagno",
        "lightsoff", "quadrapassel", "swell-foop", "tali", "kmahjongg",
        "kpat", "kmines", "ksudoku", "kblocks", "chromium-bsu", "xonotic",
        "openarena", "alienarena", "tuxracer", "extremetuxracer", "neverball",
        "neverputt", "bzflag", "warzone2100", "widelands", "teeworlds",
        "sauerbraten", "hedgewars", "xmoto", "flightgear", "roblox",
        "epicgames", "runescape",
    ],
    "Torrents & file sharing": [
        "transmission", "deluge", "qbittorrent", "ktorrent", "rtorrent",
        "aria2", "amule", "frostwire", "vuze", "utorrent", "bittorrent",
        "jdownloader", "gtk-gnutella", "nicotine", "soulseek", "limewire",
        "popcorntime", "stremio", "webtorrent",
    ],
    "Chat & social apps": [
        "discord", "telegram", "skype", "whatsapp", "signal-desktop",
        "element-desktop", "pidgin", "hexchat", "irssi", "weechat",
        "teamspeak", "mumble", "viber", "messenger", "caprine", "ferdium",
        "franz", "wechat", "twitch",
    ],
    "Media & entertainment apps": [
        "spotify", "kodi", "plexmediaserver", "plex", "jellyfin", "clementine",
        "audacious", "vlc", "strawberry", "youtube-dl", "yt-dlp", "freetube",
        "tartube", "minitube",
    ],
    "Anonymity, VPN & proxy tools": [
        "tor", "tor-browser", "torbrowser", "proxychains", "openvpn",
        "wireguard", "nordvpn", "protonvpn", "expressvpn", "mullvad",
        "psiphon", "ultrasurf", "i2p", "freenet", "anonsurf", "windscribe",
        "surfshark", "privoxy", "obfs4proxy",
    ],
    "Malware, miners & keyloggers": [
        "xmrig", "minerd", "cpuminer", "bfgminer", "cgminer", "ethminer",
        "nbminer", "nicehash", "minergate", "phoenixminer", "cryptominer",
        "logkeys", "pykeylogger", "keylogger", "keylog", "xspy", "diamorphine",
        "azazel", "rootkit", "backdoor", "trojan", "ransomware", "webshell",
        "reverse-shell", "revshell", "botnet", "mirai",
    ],
    "Password lists & wordlists": [
        "rockyou", "wordlist", "wordlists", "seclists", "passlist",
        "password-list", "darkc0de", "crackstation", "passwords", "pwlist",
    ],
    # The two categories below are matched by file extension (see below).
    "Media files (audio/video)": [],
    "Installers & executables": [],
    "Torrent files": [],
}

EXTENSION_RULES = {
    ".mp3": "Media files (audio/video)", ".wav": "Media files (audio/video)",
    ".flac": "Media files (audio/video)", ".ogg": "Media files (audio/video)",
    ".m4a": "Media files (audio/video)", ".aac": "Media files (audio/video)",
    ".wma": "Media files (audio/video)", ".mp4": "Media files (audio/video)",
    ".mkv": "Media files (audio/video)", ".avi": "Media files (audio/video)",
    ".mov": "Media files (audio/video)", ".wmv": "Media files (audio/video)",
    ".flv": "Media files (audio/video)", ".webm": "Media files (audio/video)",
    ".mpg": "Media files (audio/video)", ".mpeg": "Media files (audio/video)",
    ".m4v": "Media files (audio/video)",
    ".exe": "Installers & executables", ".msi": "Installers & executables",
    ".bat": "Installers & executables", ".scr": "Installers & executables",
    ".appimage": "Installers & executables", ".deb": "Installers & executables",
    ".rpm": "Installers & executables", ".run": "Installers & executables",
    ".torrent": "Torrent files",
}

# Extra places to search for files besides every user's home folder.
EXTRA_ROOTS = ["/opt", "/srv", "/tmp", "/var/tmp", "/var/www", "/usr/local",
               "/mnt", "/media"]
# Directories that hold installed commands.
BIN_DIRS = ["/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin",
            "/usr/games", "/snap/bin", "/opt"]
SKIP_DIRNAMES = {".cache", "node_modules", "site-packages", "dist-packages",
                 "__pycache__", ".git"}
# Library/documentation file types that merely *mention* a tool name
# (icons, type stubs, bytecode...) and would only add noise.
IGNORE_NAME_MATCH_EXTS = {".svg", ".pyi", ".pyc", ".xml", ".po", ".mo", ".md"}
MAX_HASH_BYTES = 200 * 1024 * 1024  # don't hash files bigger than 200 MB

# --------------------------------------------------------------------------
# Matching
# --------------------------------------------------------------------------

KEYWORD_CATEGORY = {}
for _cat, _kws in CATEGORIES.items():
    for _kw in _kws:
        KEYWORD_CATEGORY.setdefault(_kw.lower(), _cat)

# Very short names must match the whole name exactly (e.g. "nc", "tor").
SHORT = {k for k in KEYWORD_CATEGORY if len(k) <= 2 or k == "tor"}
_LONG = sorted((k for k in KEYWORD_CATEGORY if k not in SHORT),
               key=len, reverse=True)
MASTER = re.compile(
    r"(?<![a-z0-9])(" + "|".join(re.escape(k) for k in _LONG) + r")(?![a-z])")


def classify(name):
    """Return (category, keyword) if the name matches the blocklist."""
    n = name.lower()
    if n in ALLOWLIST:
        return None
    m = MASTER.search(n)
    if m:
        return KEYWORD_CATEGORY[m.group(1)], m.group(1)
    stem = n.split(".")[0]
    if stem in SHORT:
        return KEYWORD_CATEGORY[stem], stem
    return None


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------

def run(cmd, timeout=60):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception:
        return ""


def owner_of(path):
    try:
        uid = os.lstat(path).st_uid
        try:
            return pwd.getpwuid(uid).pw_name
        except KeyError:
            return str(uid)
    except OSError:
        return ""


def sha256_of(path):
    try:
        if os.path.getsize(path) > MAX_HASH_BYTES:
            return "(skipped: large file)"
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def home_dirs():
    """Home folders of every real user (plus root) found on the system."""
    homes = {}
    try:
        for p in pwd.getpwall():
            if p.pw_uid == 0 or 1000 <= p.pw_uid < 65534:
                if os.path.isdir(p.pw_dir):
                    homes[p.pw_dir] = p.pw_name
    except Exception:
        pass
    if os.path.isdir("/home"):
        for d in sorted(os.listdir("/home")):
            full = os.path.join("/home", d)
            if os.path.isdir(full) and full not in homes:
                homes[full] = d
    return homes


def make(cat, kw, item, kind, user="", path="", detail="", sha=""):
    return {"category": cat, "keyword": kw, "item": item, "kind": kind,
            "user": user, "path": path, "detail": detail, "sha256": sha}


def scan_system(progress=None, include_files=True):
    say = progress or (lambda m: None)
    findings, seen = [], set()

    def add(f):
        key = (f["path"],) if f["path"] else (f["kind"], f["item"], f["user"])
        if key in seen:
            return
        seen.add(key)
        findings.append(f)

    # --- apt packages ---
    say("Checking installed apt packages...")
    out = run(["dpkg-query", "-W",
               r"-f=${db:Status-Abbrev}\t${Package}\t${Version}\n"])
    for line in out.splitlines():
        p = line.split("\t")
        if len(p) < 3 or not p[0].startswith("ii"):
            continue
        hit = classify(p[1])
        if hit:
            add(make(hit[0], hit[1], p[1], "apt package", detail="version " + p[2]))

    # --- snap ---
    say("Checking snap packages...")
    for line in run(["snap", "list"]).splitlines()[1:]:
        parts = line.split()
        if parts:
            hit = classify(parts[0])
            if hit:
                add(make(hit[0], hit[1], parts[0], "snap package",
                         detail="version " + (parts[1] if len(parts) > 1 else "?")))

    # --- flatpak ---
    say("Checking flatpak apps...")
    for line in run(["flatpak", "list", "--columns=application,name"]).splitlines():
        parts = line.split("\t")
        hit = classify(parts[0]) or (classify(parts[1]) if len(parts) > 1 else None)
        if hit:
            add(make(hit[0], hit[1], parts[-1], "flatpak app", detail=parts[0]))

    # --- systemd services ---
    say("Checking services...")
    out = run(["systemctl", "list-unit-files", "--type=service",
               "--no-legend", "--no-pager"])
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        name = parts[0][:-8] if parts[0].endswith(".service") else parts[0]
        hit = classify(name)
        if hit:
            add(make(hit[0], hit[1], parts[0], "service",
                     detail="unit file state: " + parts[1]))

    # --- running processes ---
    say("Checking running processes...")
    agg = defaultdict(list)
    out = run(["ps", "-eww", "--no-headers", "-o", "user:32,pid,comm,args"])
    for line in out.splitlines():
        parts = line.split(None, 3)
        if len(parts) < 3:
            continue
        user, pid, comm = parts[:3]
        if pid == str(os.getpid()):
            continue
        tokens = parts[3].split() if len(parts) > 3 else []
        names = [comm]
        if tokens:
            names.append(os.path.basename(tokens[0]))
            if comm.startswith(("python", "perl", "bash", "sh", "ruby", "node")) \
                    and len(tokens) > 1:
                names.append(os.path.basename(tokens[1]))
        for n in names:
            hit = classify(n)
            if hit:
                agg[(user, n, hit)].append(pid)
                break
    for (user, n, hit), pids in agg.items():
        add(make(hit[0], hit[1], n, "running process", user=user,
                 detail="%d process(es), PID %s" % (len(pids), ", ".join(pids[:8]))))

    # --- installed commands ---
    say("Checking installed commands...")
    for d in BIN_DIRS:
        try:
            with os.scandir(d) as it:
                for e in it:
                    hit = classify(e.name)
                    if not hit:
                        continue
                    is_dir = e.is_dir(follow_symlinks=False)
                    add(make(hit[0], hit[1], e.name,
                             "directory" if is_dir else "binary",
                             user=owner_of(e.path), path=e.path,
                             sha="" if is_dir else sha256_of(e.path)))
        except OSError:
            continue

    # --- files in every user's home + other common locations ---
    if include_files:
        homes = home_dirs()
        roots = list(homes) + [r for r in EXTRA_ROOTS
                               if os.path.isdir(r) and r not in homes]
        for root in roots:
            say("Scanning files in %s ..." % root)
            for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
                keep = []
                for d in dirnames:
                    if d in SKIP_DIRNAMES or d.startswith("systemd-private-"):
                        continue
                    full = os.path.join(dirpath, d)
                    if os.path.islink(full):
                        continue
                    hit = classify(d)
                    if hit:
                        add(make(hit[0], hit[1], d, "directory",
                                 user=owner_of(full), path=full))
                        continue  # don't descend into flagged folders
                    keep.append(d)
                dirnames[:] = keep
                for fn in filenames:
                    ext = os.path.splitext(fn)[1].lower()
                    hit = None if ext in IGNORE_NAME_MATCH_EXTS else classify(fn)
                    if not hit:
                        cat = EXTENSION_RULES.get(os.path.splitext(fn)[1].lower())
                        if cat and fn.lower() not in ALLOWLIST:
                            hit = (cat, os.path.splitext(fn)[1].lower())
                    if hit:
                        full = os.path.join(dirpath, fn)
                        add(make(hit[0], hit[1], fn, "file", user=owner_of(full),
                                 path=full, sha=sha256_of(full)))

    order = {c: i for i, c in enumerate(CATEGORIES)}
    findings.sort(key=lambda f: (order.get(f["category"], 99), f["keyword"],
                                 f["kind"], f["item"]))
    return findings


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def group_by_category(findings):
    by = defaultdict(list)
    for f in findings:
        by[f["category"]].append(f)
    return by


def print_report(findings):
    by = group_by_category(findings)
    print("Scan of %s at %s" % (socket.gethostname(),
                                datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    for cat in CATEGORIES:
        if cat not in by:
            continue
        print("\n=== %s (%d) ===" % (cat, len(by[cat])))
        for f in by[cat]:
            line = "  [%s] %s" % (f["kind"], f["item"])
            if f["user"]:
                line += "  user=" + f["user"]
            if f["path"]:
                line += "  " + f["path"]
            if f["detail"]:
                line += "  (" + f["detail"] + ")"
            print(line)
    print("\nTotal: %d findings in %d categories." % (len(findings), len(by)))


def write_csv(findings, path):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["category", "keyword", "item", "kind",
                                           "user", "path", "detail", "sha256"])
        w.writeheader()
        w.writerows(findings)


def write_json(findings, path):
    data = {
        "host": socket.gethostname(),
        "scanned_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "ran_as_root": os.geteuid() == 0,
        "total": len(findings),
        "findings": findings,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


# --------------------------------------------------------------------------
# GUI
# --------------------------------------------------------------------------

def run_gui():
    import threading
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    root = tk.Tk()
    root.title("Mint Software Auditor")
    root.geometry("1150x680")
    state = {"findings": [], "running": False, "msg": "", "error": None}

    top = ttk.Frame(root, padding=8)
    top.pack(fill="x")
    scan_btn = ttk.Button(top, text="Scan now")
    scan_btn.pack(side="left")
    csv_btn = ttk.Button(top, text="Export CSV", state="disabled")
    csv_btn.pack(side="left", padx=6)
    json_btn = ttk.Button(top, text="Export JSON", state="disabled")
    json_btn.pack(side="left")
    include_files = tk.BooleanVar(value=True)
    ttk.Checkbutton(top, text="Include file scan", variable=include_files
                    ).pack(side="left", padx=12)
    if os.geteuid() != 0:
        ttk.Label(top, foreground="red",
                  text="Not running as root: other users' files may be hidden"
                  ).pack(side="right")

    status = ttk.Label(root, text="Ready. Click 'Scan now'.", anchor="w", padding=6)
    status.pack(side="bottom", fill="x")

    cols = ("kind", "user", "item", "path", "detail")
    tree = ttk.Treeview(root, columns=cols, show="tree headings")
    tree.heading("#0", text="Category / matched name")
    tree.column("#0", width=260)
    for col, title, width in (("kind", "Type", 110), ("user", "User", 90),
                              ("item", "Item", 200), ("path", "Path", 380),
                              ("detail", "Detail", 220)):
        tree.heading(col, text=title)
        tree.column(col, width=width)
    sb = ttk.Scrollbar(root, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=sb.set)
    sb.pack(side="right", fill="y")
    tree.pack(fill="both", expand=True)

    def populate():
        tree.delete(*tree.get_children())
        if state["error"]:
            status.config(text="Scan failed: %s" % state["error"])
        else:
            by = group_by_category(state["findings"])
            for cat in CATEGORIES:
                if cat not in by:
                    continue
                parent = tree.insert("", "end", open=True,
                                     text="%s (%d)" % (cat, len(by[cat])))
                for f in by[cat]:
                    tree.insert(parent, "end", text=f["keyword"],
                                values=(f["kind"], f["user"], f["item"],
                                        f["path"], f["detail"]))
            status.config(text="Scan finished %s: %d findings in %d categories."
                          % (datetime.datetime.now().strftime("%H:%M:%S"),
                             len(state["findings"]), len(by)))
        scan_btn.config(state="normal")
        ok = "normal" if state["findings"] else "disabled"
        csv_btn.config(state=ok)
        json_btn.config(state=ok)

    def poll():
        if state["running"]:
            status.config(text=state["msg"])
            root.after(200, poll)
        else:
            populate()

    def start_scan():
        state.update(running=True, error=None, msg="Starting scan...")
        scan_btn.config(state="disabled")
        csv_btn.config(state="disabled")
        json_btn.config(state="disabled")
        do_files = include_files.get()

        def worker():
            try:
                state["findings"] = scan_system(
                    lambda m: state.__setitem__("msg", m), do_files)
            except Exception as exc:
                state["error"] = str(exc)
            finally:
                state["running"] = False

        threading.Thread(target=worker, daemon=True).start()
        root.after(200, poll)

    def export(kind):
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        path = filedialog.asksaveasfilename(
            defaultextension="." + kind, initialfile="audit_%s.%s" % (stamp, kind))
        if path:
            (write_csv if kind == "csv" else write_json)(state["findings"], path)
            messagebox.showinfo("Saved", "Report saved to:\n" + path)

    scan_btn.config(command=start_scan)
    csv_btn.config(command=lambda: export("csv"))
    json_btn.config(command=lambda: export("json"))
    root.mainloop()


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def run_cli(args):
    findings = scan_system(lambda m: print(m, file=sys.stderr),
                           include_files=not args.no_files)
    print_report(findings)
    if args.csv:
        write_csv(findings, args.csv)
        print("CSV saved to", args.csv)
    if args.json:
        write_json(findings, args.json)
        print("JSON saved to", args.json)


def main():
    ap = argparse.ArgumentParser(description="Mint Software Auditor (report-only)")
    ap.add_argument("--cli", action="store_true", help="scan in the terminal")
    ap.add_argument("--csv", help="write a CSV report to this path")
    ap.add_argument("--json", help="write a JSON report to this path")
    ap.add_argument("--no-files", action="store_true",
                    help="skip the file-system walk (packages/processes only)")
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("WARNING: not running as root; other users' files may be hidden. "
              "Re-run with sudo.", file=sys.stderr)

    if args.cli or args.csv or args.json:
        run_cli(args)
        return
    try:
        run_gui()
    except Exception as exc:
        print("GUI unavailable (%s). Falling back to terminal mode.\n"
              "If tkinter is missing: sudo apt install python3-tk" % exc,
              file=sys.stderr)
        run_cli(args)


if __name__ == "__main__":
    main()
