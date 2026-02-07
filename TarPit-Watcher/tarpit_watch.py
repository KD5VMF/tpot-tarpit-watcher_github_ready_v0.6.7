#!/usr/bin/env python3
"""
TPOT TAR-PIT WATCH v0.6.7
A terminal (curses) watcher for T-Pot / honeypot hosts.

What it does
------------
- Reads Linux conntrack entries (tcp) and summarizes inbound activity to watched ports.
- Tracks active sessions + durations and maintains a longest-ended-session history (persisted).
- Shows:
  - SESSIONS (TOP) + TOP SOURCES (combined box)
  - PC INFO (CPU/mem/disk/net rates + totals)
  - DOCKER + ESTABLISHED (containers + longest active + longest ended history, with container mapped per port)
  - PORTS (ACTIVE/TOTAL) + WATCHED (active ports + lifetime hits + watched-port list)
- Saves stats continuously (autosave) and on quit.

Safety / ethics
---------------
This tool is defensive monitoring only. Use it on systems you own or are authorized to test/monitor.

Dependencies
------------
- python3 (standard library; no pip deps)
- conntrack (conntrack tool)
- iproute2 (ss/ip)
- docker (for container/port mapping; optional but recommended on T-Pot)

Run
---
  sudo ./tarpit_watch.py
or:
  ~/Tar-Start.sh
"""
from __future__ import annotations

import argparse
import curses
import datetime as _dt
import json
import os
import re
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

VERSION = "0.6.7"

# ------------------------- Defaults -------------------------
DEFAULT_EXCLUDE_ADMIN_PORTS = {64295, 64294, 64297}  # common TPOT admin SSH + webui ports
DEFAULT_AUTOSAVE_S = 60
DEFAULT_GRACE_S = 8.0
DEFAULT_POLL_S = 1.0
DEFAULT_TOPN = 10
DEFAULT_HISTORY_N = 50

FALLBACK_WATCH_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    465, 587, 993, 995,
    1433, 1521, 1723, 1883, 2049, 2181,
    2375, 2376,
    3306, 3389, 5432, 5900, 5985, 5986,
    6379, 6667,
    7001, 8000, 8008, 8080, 8088, 8443, 8888, 9000,
    9200, 9300,
    11211, 27017,
    64296, 64298, 64299, 64303, 64305,
]

# conntrack -L output (common format)
RE_CT = re.compile(
    r"^tcp\s+\d+\s+(?P<timeout>\d+)\s+(?P<state>[A-Z_]+)\s+"
    r"src=(?P<src>\d+\.\d+\.\d+\.\d+)\s+dst=(?P<dst>\d+\.\d+\.\d+\.\d+)\s+"
    r"sport=(?P<sport>\d+)\s+dport=(?P<dport>\d+)\s+"
    r"src=(?P<rsrc>\d+\.\d+\.\d+\.\d+)\s+dst=(?P<rdst>\d+\.\d+\.\d+\.\d+)\s+"
    r"sport=(?P<rsport>\d+)\s+dport=(?P<rdport>\d+)"
)

# ------------------------- Themes -------------------------
P_BORDER = 1
P_TITLE  = 2
P_TEXT   = 3
P_DIM    = 4
P_WARN   = 5
P_BAD    = 6

THEMES = [
    # 25 themes total (includes amber)
    "amber", "matrix", "ocean", "ice", "violet",
    "sunset", "mono", "classic", "forest", "neon",
    "steel", "crimson", "cyan", "gold", "lava",
    "mint", "plasma", "midnight", "desert", "emerald",
    "slate", "royal", "retro", "hacker", "solar",
]

def _pair(fg: int, bg: int = -1) -> Tuple[int, int]:
    return (fg, bg)

def init_theme(theme: str) -> None:
    if not curses.has_colors():
        return
    curses.start_color()
    curses.use_default_colors()

    C_BLACK = curses.COLOR_BLACK
    C_WHITE = curses.COLOR_WHITE
    C_RED = curses.COLOR_RED
    C_GREEN = curses.COLOR_GREEN
    C_YELLOW = curses.COLOR_YELLOW
    C_BLUE = curses.COLOR_BLUE
    C_MAGENTA = curses.COLOR_MAGENTA
    C_CYAN = curses.COLOR_CYAN

    # defaults
    border = _pair(C_YELLOW)
    title  = _pair(C_YELLOW)
    text   = _pair(C_WHITE)
    dim    = _pair(C_CYAN)
    warn   = _pair(C_YELLOW)
    bad    = _pair(C_RED)

    t = theme.lower().strip()

    if t == "amber":
        border, title, text, dim, warn, bad = _pair(C_YELLOW), _pair(C_YELLOW), _pair(C_WHITE), _pair(C_CYAN), _pair(C_YELLOW), _pair(C_RED)
    elif t == "matrix":
        border, title, text, dim, warn, bad = _pair(C_GREEN), _pair(C_GREEN), _pair(C_GREEN), _pair(C_CYAN), _pair(C_YELLOW), _pair(C_RED)
    elif t == "ocean":
        border, title, text, dim, warn, bad = _pair(C_CYAN), _pair(C_BLUE), _pair(C_WHITE), _pair(C_CYAN), _pair(C_YELLOW), _pair(C_RED)
    elif t == "ice":
        border, title, text, dim, warn, bad = _pair(C_CYAN), _pair(C_CYAN), _pair(C_WHITE), _pair(C_BLUE), _pair(C_YELLOW), _pair(C_RED)
    elif t == "violet":
        border, title, text, dim, warn, bad = _pair(C_MAGENTA), _pair(C_MAGENTA), _pair(C_WHITE), _pair(C_CYAN), _pair(C_YELLOW), _pair(C_RED)
    elif t == "sunset":
        border, title, text, dim, warn, bad = _pair(C_YELLOW), _pair(C_RED), _pair(C_WHITE), _pair(C_MAGENTA), _pair(C_YELLOW), _pair(C_RED)
    elif t == "mono":
        border, title, text, dim, warn, bad = _pair(C_WHITE), _pair(C_WHITE), _pair(C_WHITE), _pair(C_WHITE), _pair(C_WHITE), _pair(C_WHITE)
    elif t == "classic":
        border, title, text, dim, warn, bad = _pair(C_BLUE), _pair(C_BLUE), _pair(C_WHITE), _pair(C_CYAN), _pair(C_YELLOW), _pair(C_RED)
    elif t == "forest":
        border, title, text, dim, warn, bad = _pair(C_GREEN), _pair(C_GREEN), _pair(C_WHITE), _pair(C_YELLOW), _pair(C_YELLOW), _pair(C_RED)
    elif t == "neon":
        border, title, text, dim, warn, bad = _pair(C_CYAN), _pair(C_MAGENTA), _pair(C_WHITE), _pair(C_CYAN), _pair(C_YELLOW), _pair(C_RED)
    elif t == "steel":
        border, title, text, dim, warn, bad = _pair(C_BLUE), _pair(C_CYAN), _pair(C_WHITE), _pair(C_BLUE), _pair(C_YELLOW), _pair(C_RED)
    elif t == "crimson":
        border, title, text, dim, warn, bad = _pair(C_RED), _pair(C_RED), _pair(C_WHITE), _pair(C_MAGENTA), _pair(C_YELLOW), _pair(C_RED)
    elif t == "cyan":
        border, title, text, dim, warn, bad = _pair(C_CYAN), _pair(C_CYAN), _pair(C_WHITE), _pair(C_CYAN), _pair(C_YELLOW), _pair(C_RED)
    elif t == "gold":
        border, title, text, dim, warn, bad = _pair(C_YELLOW), _pair(C_YELLOW), _pair(C_WHITE), _pair(C_MAGENTA), _pair(C_YELLOW), _pair(C_RED)
    elif t == "lava":
        border, title, text, dim, warn, bad = _pair(C_RED), _pair(C_YELLOW), _pair(C_WHITE), _pair(C_RED), _pair(C_YELLOW), _pair(C_RED)
    elif t == "mint":
        border, title, text, dim, warn, bad = _pair(C_GREEN), _pair(C_CYAN), _pair(C_WHITE), _pair(C_GREEN), _pair(C_YELLOW), _pair(C_RED)
    elif t == "plasma":
        border, title, text, dim, warn, bad = _pair(C_MAGENTA), _pair(C_CYAN), _pair(C_WHITE), _pair(C_MAGENTA), _pair(C_YELLOW), _pair(C_RED)
    elif t == "midnight":
        border, title, text, dim, warn, bad = _pair(C_BLUE), _pair(C_BLUE), _pair(C_WHITE), _pair(C_CYAN), _pair(C_YELLOW), _pair(C_RED)
    elif t == "desert":
        border, title, text, dim, warn, bad = _pair(C_YELLOW), _pair(C_YELLOW), _pair(C_WHITE), _pair(C_RED), _pair(C_YELLOW), _pair(C_RED)
    elif t == "emerald":
        border, title, text, dim, warn, bad = _pair(C_GREEN), _pair(C_GREEN), _pair(C_WHITE), _pair(C_CYAN), _pair(C_YELLOW), _pair(C_RED)
    elif t == "slate":
        border, title, text, dim, warn, bad = _pair(C_WHITE), _pair(C_CYAN), _pair(C_WHITE), _pair(C_BLUE), _pair(C_YELLOW), _pair(C_RED)
    elif t == "royal":
        border, title, text, dim, warn, bad = _pair(C_MAGENTA), _pair(C_BLUE), _pair(C_WHITE), _pair(C_CYAN), _pair(C_YELLOW), _pair(C_RED)
    elif t == "retro":
        border, title, text, dim, warn, bad = _pair(C_GREEN), _pair(C_YELLOW), _pair(C_WHITE), _pair(C_GREEN), _pair(C_YELLOW), _pair(C_RED)
    elif t == "hacker":
        border, title, text, dim, warn, bad = _pair(C_GREEN), _pair(C_GREEN), _pair(C_WHITE), _pair(C_GREEN), _pair(C_YELLOW), _pair(C_RED)
    elif t == "solar":
        border, title, text, dim, warn, bad = _pair(C_YELLOW), _pair(C_CYAN), _pair(C_WHITE), _pair(C_BLUE), _pair(C_YELLOW), _pair(C_RED)

    curses.init_pair(P_BORDER, border[0], border[1])
    curses.init_pair(P_TITLE,  title[0],  title[1])
    curses.init_pair(P_TEXT,   text[0],   text[1])
    curses.init_pair(P_DIM,    dim[0],    dim[1])
    curses.init_pair(P_WARN,   warn[0],   warn[1])
    curses.init_pair(P_BAD,    bad[0],    bad[1])

# ------------------------- Utility -------------------------
def _now_local() -> _dt.datetime:
    return _dt.datetime.now().astimezone()

def _fmt_age(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    m, s = divmod(seconds, 60)
    if m < 60:
        return f"{m}m{s:02}s"
    h, rem = divmod(m, 60)
    if h < 24:
        return f"{h}h{rem:02}m"
    d, remh = divmod(h, 24)
    return f"{d}d{remh:02}h"

def _is_private_ipv4(ip: str) -> bool:
    if ip.startswith("10."): return True
    if ip.startswith("192.168."): return True
    if ip.startswith("127."): return True
    if ip.startswith("169.254."): return True
    if ip.startswith("172."):
        try:
            x = int(ip.split(".")[1])
            return 16 <= x <= 31
        except Exception:
            return False
    return False

def _run(cmd: List[str], timeout: float = 6.0) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:
        return 1, "", str(e)

def _safe_add(stdscr, y: int, x: int, s: str, attr: int = 0) -> None:
    try:
        H, W = stdscr.getmaxyx()
        if y < 0 or y >= H: return
        if x < 0 or x >= W: return
        maxlen = max(0, W - x)
        if maxlen <= 0: return
        if len(s) > maxlen:
            s = s[:maxlen]
        stdscr.addstr(y, x, s, attr)
    except curses.error:
        pass

def _safe_hline(stdscr, y: int, x: int, n: int, ch: str, attr: int = 0) -> None:
    if n <= 0: return
    try:
        for i in range(n):
            _safe_add(stdscr, y, x+i, ch, attr)
    except curses.error:
        pass

def _human_bytes(n: float) -> str:
    n = float(n)
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    i = 0
    while n >= 1024 and i < len(units)-1:
        n /= 1024.0
        i += 1
    if i == 0:
        return f"{int(n)}{units[i]}"
    return f"{n:.1f}{units[i]}"

def _human_rate_bytes_per_s(n: float) -> str:
    # show KiB/s plus Mbps-ish hint
    kib = n / 1024.0
    mbps = (n * 8) / 1_000_000.0
    return f"{kib:.1f} KiB/s ({mbps:.1f} Mbps)"

def _get_host_ips() -> List[str]:
    rc, out, _ = _run(["bash", "-lc", "hostname -I | tr ' ' '\\n' | sed '/^$/d'"], timeout=2.0)
    ips = [x.strip() for x in out.splitlines() if x.strip()]
    return ips

def _get_primary_ip() -> str:
    ips = _get_host_ips()
    # prefer non-loopback
    for ip in ips:
        if not ip.startswith("127."):
            return ip
    return ips[0] if ips else "0.0.0.0"

def _get_default_iface() -> Optional[str]:
    rc, out, _ = _run(["bash", "-lc", "ip route show default 2>/dev/null | head -n1"], timeout=2.0)
    m = re.search(r"\bdev\s+(\S+)", out)
    return m.group(1) if m else None

# ------------------------- Stats IO -------------------------
def _stats_path() -> Path:
    return Path.home() / ".tarpit_watch_stats.json"

def _snapshot_path() -> Path:
    return Path.home() / ".tarpit_watch_snapshot.txt"

def _atomic_write(path: Path, data: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(data, encoding="utf-8")
    tmp.replace(path)

def load_stats() -> Dict:
    p = _stats_path()
    if not p.exists():
        return {
            "version": VERSION,
            "created": _now_local().isoformat(),
            "updated": _now_local().isoformat(),
            "notes": [],
            "theme": THEMES[0],
            "lifetime_port_hits": {},
            "ended_history": [],
        }
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(d, dict):
            raise ValueError("stats not dict")
        d.setdefault("notes", [])
        d.setdefault("lifetime_port_hits", {})
        d.setdefault("ended_history", [])
        d.setdefault("theme", THEMES[0])
        d["version"] = VERSION
        return d
    except Exception as e:
        return {
            "version": VERSION,
            "created": _now_local().isoformat(),
            "updated": _now_local().isoformat(),
            "notes": [f"Failed to load stats; started new. error={e!r}"],
            "theme": THEMES[0],
            "lifetime_port_hits": {},
            "ended_history": [],
        }

def save_stats(stats: Dict) -> None:
    stats["version"] = VERSION
    stats["updated"] = _now_local().isoformat()
    _atomic_write(_stats_path(), json.dumps(stats, indent=2, sort_keys=True) + "\n")

# ------------------------- Session model -------------------------
@dataclass
class Session:
    key: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    state: str
    timeout_s: int
    first_seen: float
    last_seen: float

    def age_s(self, now: float) -> float:
        return max(0.0, now - self.first_seen)

# ------------------------- Collectors -------------------------
def parse_listen_ports(include_loopback: bool, exclude_admin: bool) -> List[int]:
    # ss -Hlnpt lists listening TCP ports
    rc, out, _ = _run(["bash", "-lc", "ss -Hlnpt 2>/dev/null"], timeout=3.0)
    ports: set[int] = set()
    for line in out.splitlines():
        # example: LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("docker-proxy",pid=..))
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[3]
        # local can be [::]:22 or 0.0.0.0:22 or 127.0.0.1:xxxx
        m = re.search(r":(\d+)$", local)
        if not m:
            continue
        ip_part = local.rsplit(":", 1)[0]
        if not include_loopback:
            if ip_part.startswith("127.") or ip_part.startswith("[::1]"):
                continue
        # we prefer exposed ports: 0.0.0.0, [::], or explicit non-loopback IP
        ports.add(int(m.group(1)))
    if exclude_admin:
        ports -= set(DEFAULT_EXCLUDE_ADMIN_PORTS)
    return sorted(ports)

def get_watched_ports(args_watch_ports: Optional[str], include_loopback: bool, exclude_admin: bool) -> List[int]:
    if args_watch_ports:
        ports: List[int] = []
        for tok in re.split(r"[,\s]+", args_watch_ports.strip()):
            if not tok:
                continue
            if "-" in tok:
                a, b = tok.split("-", 1)
                try:
                    aa = int(a); bb = int(b)
                    for p in range(min(aa, bb), max(aa, bb)+1):
                        ports.append(p)
                except Exception:
                    pass
            else:
                try:
                    ports.append(int(tok))
                except Exception:
                    pass
        ports = sorted(set(ports))
        if exclude_admin:
            ports = [p for p in ports if p not in DEFAULT_EXCLUDE_ADMIN_PORTS]
        return ports

    ports = parse_listen_ports(include_loopback=include_loopback, exclude_admin=exclude_admin)
    if not ports:
        ports = [p for p in FALLBACK_WATCH_PORTS if (p not in DEFAULT_EXCLUDE_ADMIN_PORTS or not exclude_admin)]
    return ports

def read_conntrack_tcp() -> List[dict]:
    # stderr suppressed because conntrack emits warnings if not root
    rc, out, _ = _run(["bash", "-lc", "conntrack -L -p tcp 2>/dev/null"], timeout=6.0)
    rows: List[dict] = []
    for line in out.splitlines():
        m = RE_CT.match(line.strip())
        if not m:
            continue
        try:
            rows.append({
                "timeout": int(m.group("timeout")),
                "state": m.group("state"),
                "src": m.group("src"),
                "dst": m.group("dst"),
                "sport": int(m.group("sport")),
                "dport": int(m.group("dport")),
                "rsrc": m.group("rsrc"),
                "rdst": m.group("rdst"),
                "rsport": int(m.group("rsport")),
                "rdport": int(m.group("rdport")),
            })
        except Exception:
            continue
    return rows

class DockerCache:
    def __init__(self, refresh_s: float = 8.0) -> None:
        self.refresh_s = refresh_s
        self.last = 0.0
        self.containers: List[dict] = []
        self.port_map: Dict[int, str] = {}  # host_port -> container (name)
        self.hints: List[str] = []

    def maybe_refresh(self, now: float) -> None:
        if (now - self.last) < self.refresh_s:
            return
        self.last = now
        rc, out, _ = _run(["bash", "-lc", "docker ps --format '{{.Names}}\t{{.Image}}\t{{.Ports}}' 2>/dev/null"], timeout=4.0)
        containers: List[dict] = []
        port_map: Dict[int, str] = {}
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            name = parts[0].strip()
            image = parts[1].strip()
            ports = parts[2].strip() if len(parts) >= 3 else ""
            containers.append({"name": name, "image": image, "ports": ports})
            # parse host port mappings
            # examples:
            # 0.0.0.0:22->2222/tcp, :::22->2222/tcp
            # 0.0.0.0:80-81->80-81/tcp
            for tok in ports.split(","):
                tok = tok.strip()
                if not tok:
                    continue
                m = re.search(r":(\d+)-(\d+)->", tok)
                if m:
                    a = int(m.group(1)); b = int(m.group(2))
                    for hp in range(min(a, b), max(a, b)+1):
                        port_map[hp] = name
                    continue
                m = re.search(r":(\d+)->", tok)
                if m:
                    hp = int(m.group(1))
                    port_map[hp] = name

        # hints: show these if present
        hint_keys = ["endlessh", "heralding", "ddospot", "suricata", "p0f", "cowrie", "nginx"]
        present = []
        lower_names = " ".join([c["name"].lower() for c in containers])
        for hk in hint_keys:
            if hk in lower_names:
                present.append(hk)
        self.containers = containers
        self.port_map = port_map
        self.hints = present

# ------------------------- System metrics -------------------------
class SysMetrics:
    def __init__(self) -> None:
        self.last_t = time.time()
        self.last_cpu: Optional[Tuple[int,int]] = None  # (idle,total)
        self.last_net: Dict[str, Tuple[int,int]] = {}  # iface -> (rx,tx)
        self.last_all: Optional[Tuple[int,int]] = None

    def cpu_percent(self) -> float:
        # /proc/stat first line: cpu  user nice system idle iowait irq softirq steal guest guest_nice
        try:
            line = Path("/proc/stat").read_text().splitlines()[0]
            parts = line.split()
            vals = list(map(int, parts[1:]))
            idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
            total = sum(vals)
            if self.last_cpu is None:
                self.last_cpu = (idle, total)
                return 0.0
            idle0, total0 = self.last_cpu
            di = idle - idle0
            dt = total - total0
            self.last_cpu = (idle, total)
            if dt <= 0:
                return 0.0
            used = (dt - di) / dt
            return max(0.0, min(100.0, used * 100.0))
        except Exception:
            return 0.0

    def loadavg(self) -> Tuple[float,float,float]:
        try:
            return os.getloadavg()
        except Exception:
            return (0.0, 0.0, 0.0)

    def mem(self) -> Tuple[int,int]:
        # returns (used_bytes, total_bytes)
        try:
            meminfo = Path("/proc/meminfo").read_text().splitlines()
            d = {}
            for l in meminfo:
                k, v = l.split(":", 1)
                d[k.strip()] = v.strip()
            total_kib = int(d.get("MemTotal","0 kB").split()[0])
            avail_kib = int(d.get("MemAvailable","0 kB").split()[0])
            used_kib = max(0, total_kib - avail_kib)
            return used_kib*1024, total_kib*1024
        except Exception:
            return (0, 0)

    def disk(self, path: str) -> Tuple[int,int,int]:
        # returns (used, total, free)
        try:
            st = os.statvfs(path)
            total = st.f_frsize * st.f_blocks
            free = st.f_frsize * st.f_bavail
            used = total - free
            return used, total, free
        except Exception:
            return (0,0,0)

    def net_iface_bytes(self, iface: str) -> Tuple[int,int]:
        rxp = Path(f"/sys/class/net/{iface}/statistics/rx_bytes")
        txp = Path(f"/sys/class/net/{iface}/statistics/tx_bytes")
        return int(rxp.read_text().strip()), int(txp.read_text().strip())

    def net_rates(self, iface: str, now: float) -> Tuple[float,float,int,int]:
        # returns (rx_Bps, tx_Bps, rx_total, tx_total)
        try:
            rx, tx = self.net_iface_bytes(iface)
            if iface not in self.last_net:
                self.last_net[iface] = (rx, tx)
                return (0.0, 0.0, rx, tx)
            rx0, tx0 = self.last_net[iface]
            dt = max(1e-6, now - self.last_t)
            self.last_net[iface] = (rx, tx)
            return ((rx-rx0)/dt, (tx-tx0)/dt, rx, tx)
        except Exception:
            return (0.0, 0.0, 0, 0)

    def net_all_rates(self, now: float) -> Tuple[float,float,int,int]:
        # sum non-loopback
        try:
            ifaces = [p.name for p in Path("/sys/class/net").iterdir() if p.is_dir()]
            rx = 0; tx = 0
            for i in ifaces:
                if i == "lo":
                    continue
                r, t = self.net_iface_bytes(i)
                rx += r; tx += t
            if self.last_all is None:
                self.last_all = (rx, tx)
                return (0.0, 0.0, rx, tx)
            rx0, tx0 = self.last_all
            dt = max(1e-6, now - self.last_t)
            self.last_all = (rx, tx)
            return ((rx-rx0)/dt, (tx-tx0)/dt, rx, tx)
        except Exception:
            return (0.0, 0.0, 0, 0)

    def tick(self, now: float) -> None:
        self.last_t = now

# ------------------------- Curses UI -------------------------
def make_attr(pair_id: int, bold: bool = False) -> int:
    a = curses.color_pair(pair_id)
    if bold:
        a |= curses.A_BOLD
    return a

def draw_box(stdscr, y: int, x: int, h: int, w: int, title: str, A: dict) -> Tuple[int,int,int,int]:
    # ensures minimum
    if h < 3 or w < 10:
        return (y+1, x+1, max(1, h-2), max(1, w-2))

    border_attr = A["border"]
    # corners
    _safe_add(stdscr, y, x, "┌" + "─"*(w-2) + "┐", border_attr)
    for i in range(1, h-1):
        _safe_add(stdscr, y+i, x, "│", border_attr)
        _safe_add(stdscr, y+i, x+w-1, "│", border_attr)
    _safe_add(stdscr, y+h-1, x, "└" + "─"*(w-2) + "┘", border_attr)

    if title:
        t = f" {title} "
        _safe_add(stdscr, y, x+2, t, A["title"])

    return (y+1, x+1, h-2, w-2)

def render_help(stdscr, A: dict) -> None:
    H, W = stdscr.getmaxyx()
    msg = [
        "TarPit Watcher help",
        "",
        "q           quit (saves stats)",
        "t           next theme",
        "p           toggle Private (RFC1918) sources hide/show",
        "a           toggle Admin ports hide/show (64295/64294/64297)",
        "l           toggle Loopback listen ports include/exclude",
        "w           toggle wrap for watched-port list",
        "e           toggle mode (ALL / ESTABLISHED-only)",
        "s           save stats + snapshot now",
        "r           reset lifetime port hits (history kept)",
        "h or ?      close this help",
        "",
        "Notes:",
        "- Sessions are derived from conntrack. Age is 'first seen by this watcher', not necessarily TCP start time.",
        "- Container labels come from parsing 'docker ps' port mappings where possible.",
    ]
    bw = min(W-4, 86)
    bh = min(H-4, len(msg)+2)
    y = (H - bh) // 2
    x = (W - bw) // 2
    iy, ix, ih, iw = draw_box(stdscr, y, x, bh, bw, "HELP", A)
    for i, line in enumerate(msg[:ih]):
        _safe_add(stdscr, iy+i, ix, line, A["text"])

def clamp_topn(lst: List, n: int) -> List:
    return lst[:max(0, n)]

def truncate(s: str, n: int) -> str:
    if len(s) <= n:
        return s
    if n <= 1:
        return s[:n]
    return s[:n-1] + "…"

# ------------------------- Main App -------------------------
class App:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.stats = load_stats()
        self.theme_idx = THEMES.index(self.stats.get("theme", THEMES[0])) if self.stats.get("theme") in THEMES else 0

        self.hide_private = True
        self.hide_admin = True
        self.include_loopback_listen = True   # matches your earlier "LoopbackPorts:IN"
        self.wrap_watch_ports = True
        self.mode = "ALL"  # or "EST"
        self.last_action = f"Loaded stats ({_stats_path()})"

        self.host_ip = _get_primary_ip()
        self.host_ips = set(_get_host_ips())

        self.sessions: Dict[str, Session] = {}
        self.port_hits_run: Dict[int,int] = {}  # current run (not persisted)
        self.last_autosave = time.time()

        self.docker = DockerCache(refresh_s=8.0)
        self.sys = SysMetrics()

        # for graceful exit
        self._stop = False

    def theme(self) -> str:
        return THEMES[self.theme_idx % len(THEMES)]

    def theme_label(self) -> str:
        idx = (self.theme_idx % len(THEMES)) + 1
        return f"{self.theme()} ({idx:02}/{len(THEMES)})"

    def set_action(self, s: str) -> None:
        self.last_action = s

    def toggle_theme(self) -> None:
        self.theme_idx = (self.theme_idx + 1) % len(THEMES)
        self.stats["theme"] = self.theme()
        self.set_action(f"Theme -> {self.theme_label()}")

    def toggle_private(self) -> None:
        self.hide_private = not self.hide_private
        self.set_action(f"Private sources -> {'HIDE' if self.hide_private else 'SHOW'}")

    def toggle_admin(self) -> None:
        self.hide_admin = not self.hide_admin
        self.set_action(f"Admin ports -> {'HIDE' if self.hide_admin else 'SHOW'}")

    def toggle_loopback(self) -> None:
        self.include_loopback_listen = not self.include_loopback_listen
        self.set_action(f"Loopback listen ports -> {'IN' if self.include_loopback_listen else 'OUT'}")

    def toggle_wrap(self) -> None:
        self.wrap_watch_ports = not self.wrap_watch_ports
        self.set_action(f"Wrap watched ports -> {'ON' if self.wrap_watch_ports else 'OFF'}")

    def toggle_mode(self) -> None:
        self.mode = "EST" if self.mode == "ALL" else "ALL"
        self.set_action(f"Mode -> {self.mode}")

    def reset_lifetime_hits(self) -> None:
        self.stats["lifetime_port_hits"] = {}
        self.set_action("Reset lifetime port hits (history kept)")
        save_stats(self.stats)

    def save_now(self) -> None:
        save_stats(self.stats)
        snap = self.build_snapshot_text()
        _atomic_write(_snapshot_path(), snap)
        self.set_action(f"Saved stats + snapshot ({_snapshot_path()})")

    def stop(self) -> None:
        self._stop = True

    def container_for_port(self, port: int) -> str:
        name = self.docker.port_map.get(port)
        if not name:
            return "unmapped"
        # shorten common prefixes
        return name

    def build_snapshot_text(self) -> str:
        now = _now_local()
        lines = []
        lines.append(f"TPOT TAR-PIT WATCH v{VERSION} snapshot")
        lines.append(f"Time: {now.isoformat()}")
        lines.append(f"Host: {self.host_ip}")
        lines.append(f"Theme: {self.theme_label()}")
        lines.append(f"Private:{'HIDE' if self.hide_private else 'SHOW'}  Admin:{'HIDE' if self.hide_admin else 'SHOW'}  Loopback:{'IN' if self.include_loopback_listen else 'OUT'}  Mode:{self.mode}")
        lines.append("")
        # ended history
        hist = list(self.stats.get("ended_history", []))
        hist.sort(key=lambda x: x.get("duration_s", 0), reverse=True)
        lines.append("Longest ESTABLISHED (ENDED history):")
        for item in hist[:20]:
            lines.append(f"- {item.get('src')}:{item.get('sport')} -> {item.get('dport')}  { _fmt_age(item.get('duration_s',0)) }  [{item.get('container','unmapped')}]")
        lines.append("")
        # port hits
        ph = self.stats.get("lifetime_port_hits", {})
        items = sorted(((int(k), int(v)) for k,v in ph.items()), key=lambda x: x[1], reverse=True)
        lines.append("Top total port hits (lifetime):")
        for p, c in items[:20]:
            lines.append(f"- {p}: {c}")
        lines.append("")
        return "\n".join(lines) + "\n"

    def update_sessions(self, watched_ports: List[int], now: float) -> Tuple[Dict[str,int], List[Session]]:
        self.host_ips = set(_get_host_ips())
        rows = read_conntrack_tcp()

        watched = set(watched_ports)
        state_counts: Dict[str,int] = {}
        seen_keys: set[str] = set()

        for r in rows:
            dport = r["dport"]
            if dport not in watched:
                continue

            src_ip = r["src"]
            if self.hide_private and _is_private_ipv4(src_ip):
                continue

            if self.hide_admin and dport in DEFAULT_EXCLUDE_ADMIN_PORTS:
                continue

            state = r["state"]
            if self.mode == "EST" and state != "ESTABLISHED":
                continue

            key = f"{src_ip}:{r['sport']}->{r['dst']}:{dport}"
            seen_keys.add(key)

            state_counts[state] = state_counts.get(state, 0) + 1

            if key not in self.sessions:
                self.sessions[key] = Session(
                    key=key,
                    src_ip=src_ip,
                    src_port=r["sport"],
                    dst_ip=r["dst"],
                    dst_port=dport,
                    state=state,
                    timeout_s=r["timeout"],
                    first_seen=now,
                    last_seen=now,
                )
                # increment port hits (run + lifetime)
                self.port_hits_run[dport] = self.port_hits_run.get(dport, 0) + 1
                lph = self.stats.get("lifetime_port_hits", {})
                lph[str(dport)] = int(lph.get(str(dport), 0)) + 1
                self.stats["lifetime_port_hits"] = lph
            else:
                s = self.sessions[key]
                s.state = state
                s.timeout_s = r["timeout"]
                s.last_seen = now

        # expire
        ended: List[Session] = []
        grace = float(self.args.grace)
        for key, sess in list(self.sessions.items()):
            if key in seen_keys:
                continue
            if (now - sess.last_seen) >= grace:
                ended.append(sess)
                del self.sessions[key]

        # record ended sessions into history (only if they ever were ESTABLISHED OR if mode is ALL we still keep)
        hist: List[dict] = list(self.stats.get("ended_history", []))
        for sess in ended:
            duration = sess.last_seen - sess.first_seen
            container = self.container_for_port(sess.dst_port)
            hist.append({
                "ended_ts": _now_local().isoformat(),
                "src": sess.src_ip,
                "sport": sess.src_port,
                "dst": sess.dst_ip,
                "dport": sess.dst_port,
                "state": sess.state,
                "duration_s": int(max(0.0, duration)),
                "container": container,
            })
        # keep top N
        hist.sort(key=lambda x: x.get("duration_s", 0), reverse=True)
        hist = hist[: int(self.args.history_n) ]
        self.stats["ended_history"] = hist

        active = list(self.sessions.values())
        return state_counts, active

    def compute_views(self, active: List[Session], now: float, topn: int) -> dict:
        # sessions list
        active_sorted = sorted(active, key=lambda s: (s.state != "ESTABLISHED", -(s.age_s(now))), reverse=False)
        sessions_top = clamp_topn(active_sorted, topn)

        # top sources
        by_ip: Dict[str, List[Session]] = {}
        for s in active:
            by_ip.setdefault(s.src_ip, []).append(s)
        src_rows = []
        for ip, lst in by_ip.items():
            oldest = max((x.age_s(now) for x in lst), default=0.0)
            states = sorted(set(x.state for x in lst))
            ports = sorted(set(x.dst_port for x in lst))
            src_rows.append({
                "ip": ip,
                "active": len(lst),
                "oldest_s": oldest,
                "states": states,
                "ports": ports,
            })
        src_rows.sort(key=lambda r: (r["active"], r["oldest_s"]), reverse=True)
        src_top = clamp_topn(src_rows, topn)

        # port active counts
        port_active: Dict[int,int] = {}
        for s in active:
            port_active[s.dst_port] = port_active.get(s.dst_port, 0) + 1
        port_active_items = sorted(port_active.items(), key=lambda x: x[1], reverse=True)

        # longest established active now
        est = [s for s in active if s.state == "ESTABLISHED"]
        est.sort(key=lambda s: s.age_s(now), reverse=True)
        est_top = clamp_topn(est, topn)

        # ended history is already in stats sorted desc
        ended_hist = list(self.stats.get("ended_history", []))
        ended_hist.sort(key=lambda x: x.get("duration_s", 0), reverse=True)

        return {
            "sessions_top": sessions_top,
            "sources_top": src_top,
            "port_active_items": port_active_items,
            "est_top": est_top,
            "ended_hist": ended_hist,
        }

    # ------------------------- Renderers -------------------------
    def render_header(self, stdscr, A: dict) -> None:
        now = _now_local()
        title = f"TPOT TAR-PIT WATCH v{VERSION} | {now.strftime('%a %b %d %Y %I:%M:%S %p %Z')} | Host {self.host_ip} | Theme:{self.theme_label()}"
        _safe_add(stdscr, 0, 0, truncate(title, stdscr.getmaxyx()[1]-1), A["title"])

        # status line: last action + current states
        states = f"Last action: {self.last_action}   [Mode:{self.mode}]  Private:{'HIDE' if self.hide_private else 'SHOW'}  AdminPorts:{'HIDE' if self.hide_admin else 'SHOW'}  LoopbackPorts:{'IN' if self.include_loopback_listen else 'OUT'}  Wrap:{'ON' if self.wrap_watch_ports else 'OFF'}"
        _safe_add(stdscr, 1, 0, truncate(states, stdscr.getmaxyx()[1]-1), A["dim"])

        # separator line
        H, W = stdscr.getmaxyx()
        _safe_hline(stdscr, 2, 0, W-1, "─", A["border"])

    def render_footer(self, stdscr, A: dict) -> None:
        H, W = stdscr.getmaxyx()
        keys = "[q]quit  [t]theme  [p]private  [a]admin  [l]loopback  [w]wrap  [e]mode  [s]save  [r]reset  [h]help"
        _safe_hline(stdscr, H-2, 0, W-1, "─", A["border"])
        _safe_add(stdscr, H-1, 0, truncate(keys, W-1), A["dim"])

    def render_sessions_sources_combined(self, stdscr, y: int, x: int, h: int, w: int, watched_ports: List[int], state_counts: Dict[str,int], view: dict, A: dict) -> None:
        # split interior into 2 columns
        left_w = max(18, w // 2)
        right_w = max(18, w - left_w - 1)

        # aligned headers to the real divider line (on the BOX border)
        xdiv = x + left_w
        ytop = y - 1
        ybot = y + h
        x0 = x - 1
        _safe_add(stdscr, ytop, xdiv, "┬", A["border"])
        _safe_add(stdscr, ybot, xdiv, "┴", A["border"])
        _safe_add(stdscr, ytop, x0+2, " SESSIONS (TOP) ", A["title"])
        _safe_add(stdscr, ytop, xdiv+1, " TOP SOURCES ", A["title"])

        # vertical divider
        for i in range(h):
            _safe_add(stdscr, y+i, xdiv, "│", A["border"])

        # header lines
        total = sum(state_counts.values())
        parts = [f"{k}:{v}" for k, v in sorted(state_counts.items(), key=lambda kv: kv[0])]
        header = f"Conntrack states (watched ports): total {total}"
        if parts:
            header += " | " + " ".join(parts)
        _safe_add(stdscr, y, x, truncate(header, left_w-1), A["dim"])
        _safe_add(stdscr, y+1, x, truncate(f"Showing: {self.mode} states | Active shown: {len(view['sessions_top'])}", left_w-1), A["dim"])

        # sessions list
        row = y+3
        now = time.time()
        for sess in view["sessions_top"]:
            if row >= y+h:
                break
            line = f"{sess.src_ip}:{sess.src_port} -> {sess.dst_port:<5} {_fmt_age(sess.age_s(now)):<6} {sess.state:<12} to:{sess.timeout_s}s"
            _safe_add(stdscr, row, x, truncate(line, left_w-1), A["text"])
            row += 1

        # sources list
        row = y
        sx = xdiv + 1
        for src in view["sources_top"]:
            if row >= y+h:
                break
            st = ",".join(src["states"])
            line = f"{src['ip']:<15} active:{src['active']:<2} oldest:{_fmt_age(src['oldest_s']):>5} states:{st}"
            _safe_add(stdscr, row, sx, truncate(line, right_w), A["text"])
            row += 1
            # ports subline
            ports = ",".join(map(str, src["ports"]))
            _safe_add(stdscr, row, sx+2, truncate(f"ports: {ports}", right_w-2), A["dim"])
            row += 1

    def render_pc_info(self, stdscr, y: int, x: int, h: int, w: int, tpot_dir: str, A: dict) -> None:
        now = time.time()
        cpu = self.sys.cpu_percent()
        la1, la5, la15 = self.sys.loadavg()
        mem_used, mem_total = self.sys.mem()
        du, dt, df = self.sys.disk("/")
        tu, tt, tf = self.sys.disk(tpot_dir)

        iface = _get_default_iface() or "?"
        rx_bps, tx_bps, rx_tot, tx_tot = (0.0, 0.0, 0, 0)
        all_rx_bps, all_tx_bps, all_rx_tot, all_tx_tot = (0.0, 0.0, 0, 0)
        if iface != "?":
            rx_bps, tx_bps, rx_tot, tx_tot = self.sys.net_rates(iface, now)
        all_rx_bps, all_tx_bps, all_rx_tot, all_tx_tot = self.sys.net_all_rates(now)

        row = y
        _safe_add(stdscr, row, x, "PC INFO", A["title"]); row += 1
        _safe_add(stdscr, row, x, f"CPU:  {cpu:.1f}%", A["text"]); row += 1
        _safe_add(stdscr, row, x, f"Load: {la1:.2f}  {la5:.2f}  {la15:.2f}", A["text"]); row += 1
        _safe_add(stdscr, row, x, f"Mem:  {_human_bytes(mem_used)} used / {_human_bytes(mem_total)} total", A["text"]); row += 2

        _safe_add(stdscr, row, x, f"Disk /:     {_human_bytes(du)} used ({(du/max(1,dt))*100:.1f}%) | free {_human_bytes(df)}", A["text"]); row += 1
        _safe_add(stdscr, row, x, f"Disk TPOT:  {_human_bytes(tu)} used ({(tu/max(1,tt))*100:.1f}%) | free {_human_bytes(tf)}", A["text"]); row += 2

        _safe_add(stdscr, row, x, f"Net primary IF: {iface}", A["text"]); row += 1
        _safe_add(stdscr, row, x, f"IF rate:  RX {_human_rate_bytes_per_s(rx_bps)} | TX {_human_rate_bytes_per_s(tx_bps)}", A["text"]); row += 1
        _safe_add(stdscr, row, x, f"IF total: RX {_human_bytes(rx_tot)} | TX {_human_bytes(tx_tot)}", A["text"]); row += 1
        _safe_add(stdscr, row, x, f"ALL rate: RX {_human_rate_bytes_per_s(all_rx_bps)} | TX {_human_rate_bytes_per_s(all_tx_bps)}", A["text"]); row += 1
        _safe_add(stdscr, row, x, f"ALL total: RX {_human_bytes(all_rx_tot)} | TX {_human_bytes(all_tx_tot)}", A["text"]); row += 1

        # tick time base
        self.sys.tick(now)

    def render_docker_established(self, stdscr, y: int, x: int, h: int, w: int, view: dict, A: dict) -> None:
        row = y
        _safe_add(stdscr, row, x, "DOCKER + ESTABLISHED", A["title"]); row += 1

        # docker summary
        cont = self.docker.containers
        hints = ", ".join(self.docker.hints) if self.docker.hints else "none"
        _safe_add(stdscr, row, x, f"Docker containers: {len(cont)} | Hints: {hints}", A["dim"]); row += 1

        # show a couple containers (name + image repo)
        shown = 0
        for c in cont:
            if shown >= 4:
                break
            name = c["name"]
            image = c["image"].split("@")[0]
            image = image.split(":")[0]
            line = f"{name:<18} {image}"
            _safe_add(stdscr, row, x, truncate(line, w), A["text"]); row += 1
            shown += 1
        row += 1

        # Longest active ESTABLISHED now
        _safe_add(stdscr, row, x, "Longest ESTABLISHED (ACTIVE now):", A["title"]); row += 1
        now = time.time()
        for sess in view["est_top"][:min(8, h//6 + 2)]:
            container = self.container_for_port(sess.dst_port)
            line = f"{sess.src_ip}:{sess.src_port} -> {sess.dst_port:<5} {_fmt_age(sess.age_s(now)):<6} [{container}]"
            _safe_add(stdscr, row, x, truncate(line, w), A["text"]); row += 1
            if row >= y+h:
                return
        row += 1

        # Longest ended history
        _safe_add(stdscr, row, x, "Longest ESTABLISHED (ENDED history):", A["title"]); row += 1
        for item in view["ended_hist"][:min(10, max(0, y+h-row))]:
            line = f"{item.get('src')}:{item.get('sport')} -> {item.get('dport'):<5} {_fmt_age(item.get('duration_s',0)):<6} [{item.get('container','unmapped')}]"
            _safe_add(stdscr, row, x, truncate(line, w), A["text"]); row += 1
            if row >= y+h:
                return

    def render_ports(self, stdscr, y: int, x: int, h: int, w: int, watched_ports: List[int], view: dict, A: dict) -> None:
        row = y
        _safe_add(stdscr, row, x, "PORTS (ACTIVE/TOTAL) + WATCHED", A["title"]); row += 1

        # active ports
        _safe_add(stdscr, row, x, "Top active ports:", A["dim"]); row += 1
        for p, c in view["port_active_items"][:6]:
            _safe_add(stdscr, row, x, f"{p:<6} active:{c}", A["text"]); row += 1
            if row >= y+h:
                return

        row += 1
        _safe_add(stdscr, row, x, "Top total port hits (lifetime stats):", A["dim"]); row += 1
        lph = self.stats.get("lifetime_port_hits", {})
        items = sorted(((int(k), int(v)) for k,v in lph.items()), key=lambda kv: kv[1], reverse=True)
        for p, c in items[:6]:
            _safe_add(stdscr, row, x, f"{p:<6} total:{c}", A["text"]); row += 1
            if row >= y+h:
                return

        row += 1
        _safe_add(stdscr, row, x, "Watched ports:", A["dim"]); row += 1
        wp = " ".join(str(p) for p in watched_ports)
        if self.wrap_watch_ports:
            # naive wrap
            col = 0
            for tok in wp.split():
                if row >= y+h:
                    break
                if col + len(tok) + 1 > w:
                    row += 1
                    col = 0
                _safe_add(stdscr, row, x+col, tok + " ", A["text"])
                col += len(tok) + 1
        else:
            _safe_add(stdscr, row, x, truncate(wp, w), A["text"])

    # ------------------------- Loop -------------------------
    def run(self, stdscr) -> None:
        curses.curs_set(0)
        stdscr.nodelay(True)
        stdscr.timeout(150)

        init_theme(self.theme())

        show_help = False
        tpot_dir = os.environ.get("TPOT_DIR", str(Path.home() / "tpotce"))

        while not self._stop:
            now = time.time()

            # refresh theme
            init_theme(self.theme())
            A = {
                "border": make_attr(P_BORDER),
                "title":  make_attr(P_TITLE, bold=True),
                "text":   make_attr(P_TEXT),
                "dim":    make_attr(P_DIM),
                "warn":   make_attr(P_WARN, bold=True),
                "bad":    make_attr(P_BAD, bold=True),
            }

            self.docker.maybe_refresh(now)

            watched_ports = get_watched_ports(self.args.watch_ports, include_loopback=self.include_loopback_listen, exclude_admin=self.hide_admin)
            state_counts, active = self.update_sessions(watched_ports, now)
            view = self.compute_views(active, now, int(self.args.topn))

            # autosave
            if (now - self.last_autosave) >= float(self.args.autosave):
                try:
                    save_stats(self.stats)
                    _atomic_write(_snapshot_path(), self.build_snapshot_text())
                    self.last_autosave = now
                    self.set_action(f"Autosaved stats + snapshot ({int(self.args.autosave)}s)")
                except Exception as e:
                    self.set_action(f"Autosave failed: {e!r}")

            # render
            stdscr.erase()
            self.render_header(stdscr, A)

            H, W = stdscr.getmaxyx()
            content_top = 3
            content_bottom = H - 2  # footer separator line at H-2, keys at H-1
            content_h = max(1, content_bottom - content_top)
            midy = content_top + content_h // 2
            midx = W // 2

            # Boxes
            # Top-left: combined sessions+sources (blank title)
            iy, ix, ih, iw = draw_box(stdscr, content_top, 0, max(3, midy-content_top), max(10, midx), "", A)
            self.render_sessions_sources_combined(stdscr, iy, ix, ih, iw, watched_ports, state_counts, view, A)

            # Top-right: PC INFO
            iy2, ix2, ih2, iw2 = draw_box(stdscr, content_top, midx, max(3, midy-content_top), max(10, W-midx), "", A)
            self.render_pc_info(stdscr, iy2, ix2, ih2, iw2, tpot_dir, A)

            # Bottom-left: Docker + Established
            iy3, ix3, ih3, iw3 = draw_box(stdscr, midy, 0, max(3, content_bottom-midy), max(10, midx), "", A)
            self.render_docker_established(stdscr, iy3, ix3, ih3, iw3, view, A)

            # Bottom-right: ports
            iy4, ix4, ih4, iw4 = draw_box(stdscr, midy, midx, max(3, content_bottom-midy), max(10, W-midx), "", A)
            self.render_ports(stdscr, iy4, ix4, ih4, iw4, watched_ports, view, A)

            self.render_footer(stdscr, A)

            if show_help:
                render_help(stdscr, A)

            stdscr.refresh()

            # input
            try:
                ch = stdscr.getch()
            except Exception:
                ch = -1

            if ch == -1:
                continue
            if show_help and ch in (ord('h'), ord('?')):
                show_help = False
                self.set_action("Closed help")
                continue

            if ch in (ord('q'), 27):  # q or ESC
                self.save_now()
                break
            elif ch == ord('t'):
                self.toggle_theme()
            elif ch == ord('p'):
                self.toggle_private()
            elif ch == ord('a'):
                self.toggle_admin()
            elif ch == ord('l'):
                self.toggle_loopback()
            elif ch == ord('w'):
                self.toggle_wrap()
            elif ch == ord('e'):
                self.toggle_mode()
            elif ch == ord('s'):
                self.save_now()
            elif ch == ord('r'):
                self.reset_lifetime_hits()
            elif ch in (ord('h'), ord('?')):
                show_help = True
                self.set_action("Opened help")

        # final save
        try:
            save_stats(self.stats)
        except Exception:
            pass

def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="TPOT TAR-PIT WATCH (conntrack watcher)")
    ap.add_argument("--watch-ports", default=None, help="Comma-separated ports or ranges (e.g. '22,80,443,3389,8080' or '20-25')")
    ap.add_argument("--poll", type=float, default=DEFAULT_POLL_S, help="UI poll interval (seconds)")
    ap.add_argument("--grace", type=float, default=DEFAULT_GRACE_S, help="Seconds before a missing conntrack entry is considered ended")
    ap.add_argument("--topn", type=int, default=DEFAULT_TOPN, help="Top N to show")
    ap.add_argument("--history-n", type=int, default=DEFAULT_HISTORY_N, help="How many ended sessions to keep in history")
    ap.add_argument("--autosave", type=int, default=DEFAULT_AUTOSAVE_S, help="Autosave interval in seconds")
    return ap.parse_args()

def main() -> None:
    args = parse_args()
    app = App(args)

    def _sig(*_a):
        app.stop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _sig)
        except Exception:
            pass

    curses.wrapper(app.run)

if __name__ == "__main__":
    main()
