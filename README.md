# TPOT TarPit Watcher (TAR-PIT WATCH)

A fast, zero-dependency (no pip) terminal dashboard for **T‑Pot** hosts that summarizes inbound activity using Linux **conntrack**, and correlates ports to **Docker containers** when possible.

> Defensive monitoring only. Use this on systems you own or are authorized to monitor.

## What you get

A 4‑panel terminal UI:

- **SESSIONS (TOP) + TOP SOURCES** (combined, aligned divider)
- **PC INFO** (CPU / load / mem / disk / network rates + totals)
- **DOCKER + ESTABLISHED** (container overview + longest active + longest ended history, with `[container]` labels)
- **PORTS (ACTIVE/TOTAL) + WATCHED** (active ports + lifetime hits + watched-port list)

It also persists:
- `~/.tarpit_watch_stats.json` (stats + history)
- `~/.tarpit_watch_snapshot.txt` (human-readable snapshot)
- autosaves every 60s (configurable)

## Quick start

### 1) Copy this repo onto your T‑Pot host
Example:

```bash
cd ~
git clone <THIS_REPO_URL> tpot-tarpit-watcher
cd tpot-tarpit-watcher
```

### 2) Install + run (recommended)

```bash
chmod +x install.sh Tar-Start.sh
./install.sh --all
```

Then run any time with:

```bash
~/Tar-Start.sh
```

## Keys

- `q` quit (saves stats)
- `t` theme (25 total; includes **amber**)
- `p` private sources hide/show (RFC1918)
- `a` admin ports hide/show (64295/64294/64297)
- `l` loopback listen ports include/exclude
- `w` watched-port list wrap on/off
- `e` mode toggle (ALL / ESTABLISHED-only)
- `s` save now (stats + snapshot)
- `r` reset lifetime port-hit counters (history kept)
- `h` or `?` help overlay

## Notes

- **Session age** is “first time this watcher observed the session”, not necessarily the TCP open time.
- Container tags come from parsing `docker ps` host-port mappings (best effort).

## Systemd (optional)

A service file is included in `systemd/`. See the runbook for details.

## License

MIT (see `LICENSE`).
