"""Сетевое ядро VLAN IP Scanner: ping, TCP, NetBIOS, DNS, ARP, OUI, конфиг и история.

Только стандартная библиотека Python.
"""
import csv
import ipaddress
import json
import os
import random
import re
import select
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import devinfo

CREATE_NO_WINDOW = 0x08000000
OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"

DISCOVERY_PORTS = [445, 135, 3389, 22, 80, 443, 8006, 9100]
PORT_LABELS = {
    21: "ftp", 22: "ssh", 23: "telnet", 53: "dns", 80: "http", 135: "rpc",
    139: "netbios", 443: "https", 445: "smb", 515: "lpd", 631: "ipp",
    1433: "mssql", 3306: "mysql",
    3389: "rdp", 5900: "vnc", 8006: "proxmox", 8080: "http-alt",
    8443: "https-alt", 9100: "printer", 10050: "zabbix",
}
SCAN_PORTS = list(PORT_LABELS)

# Пример для первого запуска; свои VLAN задаются в программе и хранятся в config.json
DEFAULT_VLANS = [10, 20, 30]
DEFAULT_NAMES = {10: "Пример: рабочие места", 20: "Пример: серверы", 30: "Пример: принтеры"}
BUILTIN_OUI = {
    "BC2411": "Proxmox VM", "005056": "VMware", "000C29": "VMware",
    "00155D": "Microsoft Hyper-V", "525400": "QEMU/KVM",
}

WSAECONNREFUSED = 10061
_IN_PROGRESS = (10035, 10036, 115, 36)  # WSAEWOULDBLOCK, WSAEINPROGRESS, EINPROGRESS

MAC_LINE_RE = re.compile(r":\s*((?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2})\s*$")
IPV4_LINE_RE = re.compile(r"IPv4.*?:\s*(\d+\.\d+\.\d+\.\d+)")
ARP_RE = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+((?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2})")
TTL_RE = re.compile(r"TTL=(\d+)", re.I)
TIME_RE = re.compile(r"(?:time|время)\s*([=<])\s*(\d+)", re.I)


# ---------------------------------------------------------------- файлы
def app_dir():
    """Папка рядом с exe (или со скриптом при запуске из исходников)."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def app_path(name):
    return os.path.join(app_dir(), name)


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M")


def _read_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _write_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


# ---------------------------------------------------------------- конфиг
def make_vlan(vid, name="", subnet=None, enabled=True):
    return {"id": int(vid), "name": name,
            "subnet": subnet or f"192.168.{vid}.0/24", "enabled": bool(enabled)}


def default_config():
    return {
        "vlans": [make_vlan(v, DEFAULT_NAMES.get(v, "")) for v in DEFAULT_VLANS],
        "threads": 128,
        "ping_timeout_ms": 700,
        "ping_retries": 1,
        "tcp_timeout": 0.5,
        "port_timeout": 0.8,
        "netbios_timeout": 0.8,
        "snmp_community": "public",
        "snmp_timeout": 1.0,
        "domain": "",
        "dns": "",
        "ssh_user": "",
        "resolve_names": True,
        "tcp_discovery": False,
        "scan_ports": False,
        "geometry": "",
        "theme": "dark",
    }


def validate_subnet(text):
    """Возвращает нормализованную подсеть или бросает ValueError."""
    net = ipaddress.ip_network(text.strip(), strict=False)
    if net.version != 4:
        raise ValueError("нужна IPv4-подсеть")
    if net.num_addresses > 4096:
        raise ValueError("подсеть больше /20 — слишком много адресов")
    return str(net)


def _clean_vlan(v):
    try:
        vid = int(v["id"])
        if not 1 <= vid <= 4094:
            return None
        return make_vlan(vid, str(v.get("name", "")), validate_subnet(str(v["subnet"])),
                         v.get("enabled", True))
    except (KeyError, TypeError, ValueError):
        return None


def load_config():
    cfg = default_config()
    data = _read_json(app_path("config.json"), None)
    if isinstance(data, dict):
        for key, dval in cfg.items():
            if key == "vlans" or key not in data:
                continue
            val = data[key]
            if isinstance(dval, bool):
                ok = isinstance(val, bool)
            elif isinstance(dval, (int, float)):
                ok = (isinstance(val, (int, float)) and not isinstance(val, bool)
                      and (val > 0 or (key == "ping_retries" and val == 0)))
            else:
                ok = isinstance(val, type(dval))
            if ok:
                cfg[key] = val
        if isinstance(data.get("vlans"), list):
            seen, vlans = set(), []
            for v in data["vlans"]:
                c = _clean_vlan(v) if isinstance(v, dict) else None
                if c and c["id"] not in seen:
                    seen.add(c["id"])
                    vlans.append(c)
            cfg["vlans"] = vlans
    cfg["threads"] = max(1, min(int(cfg["threads"]), 512))
    save_config(cfg)
    return cfg


def save_config(cfg):
    try:
        _write_json(app_path("config.json"), cfg)
    except OSError:
        pass


# ---------------------------------------------------------------- процессы
def _startupinfo():
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = 0
    return si


def run_hidden(args, timeout=10):
    """Запуск консольной утилиты без окна; вывод в cp866."""
    try:
        p = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, creationflags=CREATE_NO_WINDOW,
                           startupinfo=_startupinfo(), timeout=timeout)
        return p.stdout.decode("cp866", errors="replace")
    except (OSError, subprocess.SubprocessError):
        return ""


# ---------------------------------------------------------------- проверки
def ping(ip, timeout_ms=700):
    """(rtt_ms, ttl) или None. Жив только при ответе с TTL= от самого ip."""
    out = run_hidden(["ping", "-n", "1", "-w", str(int(timeout_ms)), ip],
                     timeout=timeout_ms / 1000 + 5)
    for line in out.splitlines():
        m = TTL_RE.search(line)
        if not m or ip not in line:
            continue
        t = TIME_RE.search(line)
        rtt = 0.5 if (t and t.group(1) == "<") else float(t.group(2)) if t else 0.0
        return rtt, int(m.group(1))
    return None


def tcp_probe(ip, ports, timeout=0.5):
    """Параллельный неблокирующий connect. Возвращает (открытые порты, был_RST)."""
    pending, opened, rst = {}, [], False
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(False)
        try:
            err = s.connect_ex((ip, port))
        except OSError:
            s.close()
            continue
        if err == 0:
            opened.append(port)
            s.close()
        elif err in _IN_PROGRESS:
            pending[s] = port
        else:
            rst = rst or err == WSAECONNREFUSED
            s.close()
    deadline = time.monotonic() + timeout
    try:
        while pending:
            left = deadline - time.monotonic()
            if left <= 0:
                break
            socks = list(pending)
            _, w, x = select.select([], socks, socks, left)
            if not w and not x:
                break
            for s in set(w) | set(x):
                port = pending.pop(s, None)
                if port is None:
                    continue
                err = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if err == 0:
                    opened.append(port)
                elif err == WSAECONNREFUSED:
                    rst = True
                s.close()
    finally:
        for s in pending:
            s.close()
    return sorted(opened), rst


def _nb_encode(name16):
    return bytes(c for b in name16 for c in (0x41 + (b >> 4), 0x41 + (b & 0x0F)))


def _parse_nbstat(data, tid):
    if len(data) < 57 or struct.unpack(">H", data[:2])[0] != tid:
        return None
    if struct.unpack(">H", data[6:8])[0] == 0:
        return None
    off = 12
    if data[off] & 0xC0 == 0xC0:
        off += 2
    else:
        while off < len(data) and data[off]:
            off += data[off] + 1
        off += 1
    off += 10  # type, class, ttl, rdlength
    if off >= len(data):
        return None
    count, off = data[off], off + 1
    names = []
    for _ in range(count):
        e = data[off:off + 18]
        if len(e) < 18:
            break
        names.append((e[:15].decode("cp1251", "replace").strip(), e[15],
                      struct.unpack(">H", e[16:18])[0]))
        off += 18
    mac = data[off:off + 6]
    comp = next((n for n, sfx, fl in names if sfx == 0 and not fl & 0x8000), "")
    group = next((n for n, sfx, fl in names if sfx == 0 and fl & 0x8000), "")
    mac_s = ":".join(f"{b:02X}" for b in mac) if len(mac) == 6 and any(mac) else ""
    return {"name": comp, "domain": group, "mac": mac_s}


def netbios_query(ip, timeout=0.8):
    """NBSTAT (*) на UDP/137: имя ПК, домен/рабочая группа, MAC."""
    tid = random.randint(0, 0xFFFF)
    pkt = (struct.pack(">HHHHHH", tid, 0, 1, 0, 0, 0) + b"\x20"
           + _nb_encode(b"*" + b"\x00" * 15) + b"\x00" + struct.pack(">HH", 0x21, 1))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        try:
            s.sendto(pkt, (ip, 137))
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                data, addr = s.recvfrom(4096)
                if addr[0] == ip:
                    return _parse_nbstat(data, tid)
        except OSError:
            return None
    return None


def reverse_dns(ip):
    try:
        name = socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return ""
    return "" if name == ip else name


def arp_table():
    res = {}
    for ip, mac in ARP_RE.findall(run_hidden(["arp", "-a"])):
        mac = mac.upper().replace("-", ":")
        if mac not in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00") and not mac.startswith("01:00:5E"):
            res[ip] = mac
    return res


def local_macs():
    """IP -> MAC собственных интерфейсов (из ipconfig /all)."""
    res, mac = {}, None
    for line in run_hidden(["ipconfig", "/all"]).splitlines():
        if line and not line[0].isspace():
            mac = None
        m = MAC_LINE_RE.search(line)
        if m:
            mac = m.group(1).upper().replace("-", ":")
        m = IPV4_LINE_RE.search(line)
        if m and mac:
            res[m.group(1)] = mac
    return res


# ---------------------------------------------------------------- вендоры и ОС
class OuiDb:
    def __init__(self):
        self.map = {}
        self.load()

    def load(self):
        m = {}
        try:
            with open(app_path("oui.csv"), encoding="utf-8", errors="replace", newline="") as f:
                for row in csv.reader(f):
                    if len(row) >= 3 and len(row[1]) == 6:
                        m[row[1].upper()] = row[2].strip()
        except OSError:
            pass
        self.map = m

    def lookup(self, mac):
        key = mac.replace(":", "").replace("-", "").upper()[:6]
        if len(key) < 6:
            return ""
        if key in BUILTIN_OUI:
            return BUILTIN_OUI[key]
        if key in self.map:
            return self.map[key]
        try:
            return "случайный MAC" if int(key[:2], 16) & 0x02 else ""
        except ValueError:
            return ""


def download_oui():
    req = urllib.request.Request(OUI_URL, headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) VLAN-Scanner"})
    with urllib.request.urlopen(req, timeout=120) as r:
        data = r.read()
    if b"Assignment" not in data[:300]:
        raise ValueError("неожиданный формат файла")
    path = app_path("oui.csv")
    with open(path + ".tmp", "wb") as f:
        f.write(data)
    os.replace(path + ".tmp", path)


def guess_os(ttl, ports, printer=False):
    ports = set(ports)
    if 8006 in ports:
        return "Proxmox"
    if printer or ports & {9100, 515, 631}:
        return "Принтер"
    if ports & {3389, 445, 135}:
        return "Windows"
    if ttl:
        if ttl > 128:
            return "Сетевое устройство"
        if ttl > 64:
            return "Windows"
        return "Linux/Unix"
    return ""


def ports_text(ports):
    return ", ".join(f"{p} {PORT_LABELS.get(p, '')}".strip() for p in ports)


# ---------------------------------------------------------------- история
class History:
    def __init__(self):
        d = _read_json(app_path("history.json"), {})
        d = d if isinstance(d, dict) else {}
        hosts = d.get("hosts")
        self.hosts = hosts if isinstance(hosts, dict) else {}
        self.scanned = set(d.get("scanned_vlans") or [])

    def is_new(self, vlan, ip):
        """Новый = VLAN уже сканировался раньше, а этого IP в истории нет."""
        return vlan in self.scanned and ip not in self.hosts

    def update(self, h):
        rec = self.hosts.get(h["ip"]) or {"first": now_str()}
        rec["last"] = now_str()
        rec["vlan"] = h["vlan"]
        if h.get("name"):
            rec["name"] = h["name"]
        if h.get("mac"):
            rec["mac"] = h["mac"]
        self.hosts[h["ip"]] = rec
        return rec["first"]

    def mark_scanned(self, vlans):
        self.scanned |= set(vlans)

    def save(self):
        try:
            _write_json(app_path("history.json"),
                        {"scanned_vlans": sorted(self.scanned), "hosts": self.hosts})
        except OSError:
            pass


# ---------------------------------------------------------------- сканер
class Scanner(threading.Thread):
    """Фоновый скан. Результаты кладёт в очередь: ("host", dict), ("mac", ip, mac), ("done", stopped, sec)."""

    def __init__(self, targets, opts, out_q):
        super().__init__(daemon=True)
        self.targets, self.opts, self.q = targets, opts, out_q
        self.total, self.done, self.found = len(targets), 0, 0
        self.stop_event = threading.Event()
        self.started = time.monotonic()

    def stop(self):
        self.stop_event.set()

    def run(self):
        local = local_macs()
        found = {}
        ex = ThreadPoolExecutor(max_workers=int(self.opts.get("threads", 128)))
        try:
            futs = [ex.submit(self._probe, vlan, ip, local) for vlan, ip in self.targets]
            for f in as_completed(futs):
                self.done += 1
                try:
                    h = f.result()
                except Exception:
                    h = None
                if h:
                    found[h["ip"]] = h
                    self.found += 1
                    self.q.put(("host", h))
                if self.stop_event.is_set():
                    break
            # Повтор для тех, кто не ответил: спящие принтеры и Wi-Fi-телефоны часто
            # пропускают первый ping. Если устройство ответило на ARP — ждём дольше.
            arp = arp_table()
            base = self.opts["ping_timeout_ms"]
            for _ in range(int(self.opts.get("ping_retries", 1))):
                retry = [(v, ip) for v, ip in self.targets if ip not in found]
                if not retry or self.stop_event.is_set():
                    break
                self.total += len(retry)
                fast = dict(self.opts, ping_timeout_ms=max(1000, base))
                slow = dict(self.opts, ping_timeout_ms=max(1500, base))
                rfuts = [ex.submit(self._probe, v, ip, local, slow if ip in arp else fast)
                         for v, ip in retry]
                for f in as_completed(rfuts):
                    self.done += 1
                    try:
                        h = f.result()
                    except Exception:
                        h = None
                    if h:
                        found[h["ip"]] = h
                        self.found += 1
                        self.q.put(("host", h))
                    if self.stop_event.is_set():
                        break
        finally:
            ex.shutdown(wait=False, cancel_futures=True)
        arp = arp_table()
        arp.update(local)
        for ip, h in found.items():
            if not h["mac"] and ip in arp:
                self.q.put(("mac", ip, arp[ip]))
        self.q.put(("done", self.stop_event.is_set(), time.monotonic() - self.started))

    def _probe(self, vlan, ip, local, opts=None):
        o, stop = opts or self.opts, self.stop_event
        if stop.is_set():
            return None
        r = ping(ip, o["ping_timeout_ms"])
        rtt = ttl = None
        ports, how = [], ""
        if r:
            (rtt, ttl), how = r, "ping"
        elif o.get("tcp_discovery") and not stop.is_set():
            ports, rst = tcp_probe(ip, DISCOVERY_PORTS, o["tcp_timeout"])
            how = "tcp:" + ",".join(map(str, ports)) if ports else ("tcp:rst" if rst else "")
        if not how:
            return None
        h = {"vlan": vlan, "ip": ip, "rtt": rtt, "ttl": ttl, "how": how, "ports": ports,
             "ports_scanned": False, "dns": "", "netbios": "", "domain": "",
             "snmp_name": "", "model": "", "printer": False, "mac": local.get(ip, "")}
        if o.get("resolve_names") and not stop.is_set():
            # для своих IP hosts-файл (Docker и т.п.) даёт мусор — берём имя ПК
            h["dns"] = socket.gethostname() if ip in local else reverse_dns(ip)
            nb = netbios_query(ip, o.get("netbios_timeout", 0.8))
            if nb:
                h["netbios"], h["domain"] = nb["name"], nb["domain"]
                h["mac"] = h["mac"] or nb["mac"]
            if not stop.is_set():
                # принтеры, коммутаторы, камеры: SNMP и веб-морда (принтеры бывают и с NetBIOS)
                d = devinfo.collect(ip, o.get("snmp_community", "public"),
                                    o.get("snmp_timeout", 1.0))
                h["snmp_name"], h["model"], h["printer"] = d["name"], d["model"], d["printer"]
                h["mac"] = h["mac"] or d["mac"]
        if o.get("scan_ports") and not stop.is_set():
            opened, _ = tcp_probe(ip, SCAN_PORTS, o["port_timeout"])
            h["ports"] = sorted(set(ports) | set(opened))
            h["ports_scanned"] = True
        return h


def expand_targets(vlans):
    return [(v["id"], str(ip)) for v in vlans
            for ip in ipaddress.ip_network(v["subnet"], strict=False).hosts()]
