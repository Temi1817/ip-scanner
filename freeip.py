"""Окно «Свободные IP»: адреса VLAN, не ответившие при последнем полном скане."""
import ipaddress
import queue
import threading
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor
from tkinter import ttk

import scancore as sc
import theme

COLS = [("ip", "IP", 120), ("state", "Статус", 170), ("last", "Последний раз", 140),
        ("seen", "Кто был (по истории)", 260)]
FREE, SEEN, BUSY, OK = "свободен", "был занят раньше", "ЗАНЯТ (ответил)", "свободен ✓ проверен"


def free_ips(subnet, online, history):
    """[(ip, запись истории или None)] для адресов подсети, которых нет среди online."""
    return [(str(ip), history.get(str(ip)))
            for ip in ipaddress.ip_network(subnet, strict=False).hosts() if str(ip) not in online]


def check_ip(ip):
    """True, если адрес отвечает на ping или TCP (connect/RST) — значит занят."""
    if sc.ping(ip, 1000):
        return True
    ports, rst = sc.tcp_probe(ip, sc.DISCOVERY_PORTS, 0.7)
    return bool(ports or rst)


class FreeIpDialog(tk.Toplevel):
    def __init__(self, parent, vlans, hosts, history, current=None):
        """vlans — полностью просканированные VLAN; hosts — найденные хосты {ip: h}."""
        super().__init__(parent)
        self.title("Свободные IP")
        self.transient(parent)
        self.geometry("780x560")
        self.vlans = sorted(vlans, key=lambda v: v["id"])
        self.online = set(hosts)
        self.history = history
        self.checked = {}  # ip -> True (занят) / False (свободен) после ручной проверки
        self.q = queue.Queue()
        self.checking = False

        top = ttk.Frame(self, padding=(8, 8, 8, 4))
        top.pack(fill="x")
        ttk.Label(top, text="VLAN:").pack(side="left")
        self.names = [f"VLAN {v['id']} {v['name']} ({v['subnet']})".replace("  ", " ")
                      for v in self.vlans]
        self.v_vlan = tk.StringVar()
        cb = ttk.Combobox(top, textvariable=self.v_vlan, values=self.names, state="readonly", width=46)
        cb.pack(side="left", padx=4)
        cb.bind("<<ComboboxSelected>>", lambda _e: self.refresh())
        self.v_seen = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="Показывать занятые раньше", variable=self.v_seen,
                        command=self.refresh).pack(side="left", padx=8)

        self.summary = tk.StringVar()
        ttk.Label(self, textvariable=self.summary, padding=(8, 0)).pack(fill="x")

        mid = ttk.Frame(self, padding=(8, 4))
        mid.pack(fill="both", expand=True)
        self.t = ttk.Treeview(mid, columns=[c[0] for c in COLS], show="headings", selectmode="extended")
        for cid, text, w in COLS:
            self.t.heading(cid, text=text)
            self.t.column(cid, width=w, stretch=cid == "seen", anchor="w")
        ys =ttk.Scrollbar(mid, orient="vertical", command=self.t.yview)
        self.t.configure(yscrollcommand=ys.set)
        self.t.pack(side="left", fill="both", expand=True)
        ys.pack(side="right", fill="y")

        bot = ttk.Frame(self, padding=(8, 4, 8, 8))
        bot.pack(fill="x")
        self.btn_check = ttk.Button(bot, text="Проверить выбранные", command=self.check_selected)
        self.btn_check.pack(side="left", padx=2)
        ttk.Button(bot, text="Копировать", command=self.copy).pack(side="left", padx=2)
        ttk.Button(bot, text="Закрыть", command=self.destroy).pack(side="right", padx=2)
        self.status = tk.StringVar(value="Выделите адреса и нажмите «Проверить», прежде чем выдавать IP")
        ttk.Label(bot, textvariable=self.status, style="Status.TLabel").pack(side="left", padx=8)

        ids = [v["id"] for v in self.vlans]
        self.v_vlan.set(self.names[ids.index(current) if current in ids else 0])
        self.apply_theme()
        self.refresh()
        self.after(100, self.poll)

    def apply_theme(self):
        p = theme.P
        self.configure(background=p["bg"])
        self.t.tag_configure("seen", foreground=p["seen_fg"])
        self.t.tag_configure("busy", background=p["busy_bg"], foreground=p["busy_fg"])
        self.t.tag_configure("ok", background=p["ok_bg"], foreground=p["ok_fg"])
        theme.titlebar(self)

    def vlan(self):
        return self.vlans[self.names.index(self.v_vlan.get())]

    def state(self, ip, rec):
        if ip in self.checked:
            return (BUSY, "busy") if self.checked[ip] else (OK, "ok")
        return (SEEN, "seen") if rec else (FREE, "")

    def refresh(self):
        v = self.vlan()
        rows = free_ips(v["subnet"], self.online, self.history)
        total = len(list(ipaddress.ip_network(v["subnet"], strict=False).hosts()))
        seen = sum(1 for _, rec in rows if rec)
        self.t.delete(*self.t.get_children())
        for ip, rec in rows:
            if rec and not self.v_seen.get():
                continue
            text, tag = self.state(ip, rec)
            who = " · ".join(x for x in ((rec or {}).get("name", ""), (rec or {}).get("mac", "")) if x)
            self.t.insert("", "end", iid=ip, values=(ip, text, (rec or {}).get("last", ""), who),
                          tags=(tag,) if tag else ())
        self.summary.set(f"Занято (онлайн): {total - len(rows)} из {total}  ·  "
                         f"не ответили: {len(rows)}, из них {len(rows) - seen} никогда не видели, "
                         f"{seen} были заняты раньше (возможно, устройство выключено)")

    def selected_or_all(self):
        return list(self.t.selection()) or list(self.t.get_children())

    def copy(self):
        ips = self.selected_or_all()
        self.clipboard_clear()
        self.clipboard_append("\n".join(ips))
        self.status.set(f"Скопировано адресов: {len(ips)}")

    def check_selected(self):
        ips = list(self.t.selection())
        if not ips:
            self.status.set("Сначала выделите адреса в таблице (Ctrl/Shift — несколько)")
            return
        if self.checking:
            return
        self.checking = True
        self.btn_check.configure(state="disabled")
        self.status.set(f"Проверка {len(ips)} адресов…")

        def work():
            with ThreadPoolExecutor(max_workers=32) as ex:
                res = dict(zip(ips, ex.map(check_ip, ips)))
            arp = sc.arp_table()  # ответил на ARP — значит устройство есть, даже без ping
            self.q.put({ip: busy or ip in arp for ip, busy in res.items()})
        threading.Thread(target=work, daemon=True).start()

    def poll(self):
        if not self.winfo_exists():
            return
        try:
            res = self.q.get_nowait()
        except queue.Empty:
            self.after(100, self.poll)
            return
        self.checked.update(res)
        self.checking = False
        self.btn_check.configure(state="normal")
        busy = sum(res.values())
        self.status.set(f"Проверено {len(res)}: свободны {len(res) - busy}, заняты {busy}")
        self.refresh()
        self.t.selection_set([ip for ip in res if self.t.exists(ip)])
        self.after(100, self.poll)
