# TarPit Watcher — Runbook / Notes

## What you have

This repo contains:

- `TarPit-Watcher/tarpit_watch.py`  
  A curses UI that watches the Linux conntrack table and reports:
  - Active inbound sessions to watched ports
  - Top sources by active sessions
  - Longest active sessions + longest historical sessions (persisted)
  - Port stats (active + lifetime)
  - Basic CPU/memory/load/disk/network stats
  - Docker container summary + per-port container labels (best effort)

- `install.sh`  
  Installs dependencies, copies the watcher into `~/tpotce`, creates `~/Tar-Start.sh`, and can optionally run it.

- `Tar-Start.sh`  
  Launcher that runs the watcher with `sudo` and sets a 256‑color terminal.

## Where stats live

- `~/.tarpit_watch_stats.json` (persistent stats + ended-session history)
- `~/.tarpit_watch_snapshot.txt` (human snapshot)
- Autosave interval defaults to **60 seconds**.

If the stats file is corrupted (power loss, partial write), the program starts fresh and notes the failure in `"notes"`.

## Keys

`q` quit (auto-save)  
`t` theme  
`p` hide/show private sources (RFC1918)  
`a` hide/show admin ports (64295/64294/64297)  
`l` include/exclude loopback listening ports  
`w` wrap watched-port list on/off  
`e` mode toggle (ALL / EST)  
`s` save now  
`r` reset lifetime port hits (history kept)  
`h`/`?` help

## Install

Recommended:

```bash
cd ~
git clone <THIS_REPO_URL> tpot-tarpit-watcher
cd tpot-tarpit-watcher
chmod +x install.sh Tar-Start.sh
./install.sh --all
```

## How the watcher decides what ports to watch

Default behavior:

1) Reads your current LISTEN ports from `ss -Hlnpt`  
2) Watches those ports (excluding admin ports unless you toggle `a`)  
3) If none found, falls back to a common list (see code)

You can override:

```bash
sudo python3 ~/tpotce/tarpit_watch.py --watch-ports "21,22,23,25,80,443,3389,5900,3306,8080"
```

## Confirm you’re actually getting traffic

On the T‑Pot host:

```bash
# listening ports
sudo ss -lntp | head -n 80

# containers
sudo docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' | head -n 80

# conntrack sample
sudo conntrack -L -p tcp 2>/dev/null | egrep 'ESTABLISHED|SYN_SENT|SYN_RECV|CLOSE' | head -n 120
```

If conntrack shows entries, the watcher will show them unless:
- the source is private and you’re hiding private sources (`p`)
- the destination port is an admin port and you’re hiding admin ports (`a`)
- you’re in `EST` mode and the state is not `ESTABLISHED` (`e`)

## Optional systemd service

`systemd/tarpit-watcher.service` is provided as a starting point.

Example install:

```bash
sudo cp systemd/tarpit-watcher.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now tarpit-watcher.service
```

Logs:

```bash
journalctl -u tarpit-watcher.service -f
```
