"""VLAN IP Scanner — сканер IP-адресов корпоративной сети по VLAN (tkinter GUI)."""
import csv
import ctypes
import ipaddress
import queue
import subprocess
import threading
import tkinter as tk
import webbrowser
from tkinter import filedialog, messagebox, ttk

import scancore as sc
import theme
from freeip import FreeIpDialog

COLS = [("vlan", "VLAN", 55), ("ip", "IP", 125), ("name", "Имя", 180), ("mac", "MAC", 165),
        ("vendor", "Вендор", 150), ("model", "Модель", 190), ("ping", "Ping мс", 65), ("os", "ОС", 125),
        ("ports", "Порты", 230), ("how", "Как найден", 100), ("new", "Новый", 55)]
VLAN_COLS = [("chk", "✓", 30), ("vlan", "VLAN", 50), ("name", "Название", 160),
             ("subnet", "Подсеть", 150), ("online", "Онлайн", 60)]
CHECK = {True: "✔", False: "○"}
CSV_EXTRA = ["Первый раз", "DNS", "NetBIOS", "Домен", "SNMP-имя"]


def enable_dpi_awareness():
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except (AttributeError, OSError):
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except (AttributeError, OSError):
            pass


def ip_key(ip):
    return int(ipaddress.ip_address(ip))


def ping_text(rtt):
    if rtt is None:
        return ""
    return "<1" if rtt < 1 else str(int(rtt))


class VlanDialog(tk.Toplevel):
    """Добавление/изменение VLAN. Результат в self.result."""

    def __init__(self, parent, title, vlan, taken_ids):
        super().__init__(parent)
        self.title(title)
        self.resizable(False, False)
        self.transient(parent)
        self.result, self.taken = None, taken_ids
        self.v_id = tk.StringVar(value=str(vlan["id"]) if vlan else "")
        self.v_name = tk.StringVar(value=vlan["name"] if vlan else "")
        self.v_net = tk.StringVar(value=vlan["subnet"] if vlan else "")
        self.auto_net = vlan is None
        f = ttk.Frame(self, padding=12)
        f.pack(fill="both", expand=True)
        for r, (lbl, var) in enumerate([("VLAN ID:", self.v_id), ("Название:", self.v_name),
                                        ("Подсеть:", self.v_net)]):
            ttk.Label(f, text=lbl).grid(row=r, column=0, sticky="w", pady=3)
            e = ttk.Entry(f, textvariable=var, width=32)
            e.grid(row=r, column=1, sticky="ew", pady=3)
            if r == 0:
                e.focus_set()
            if r == 2:
                e.bind("<Key>", lambda _e: setattr(self, "auto_net", False))
        self.v_id.trace_add("write", self._id_changed)
        b = ttk.Frame(f)
        b.grid(row=3, column=0, columnspan=2, pady=(10, 0), sticky="e")
        ttk.Button(b, text="OK", command=self._ok).pack(side="left", padx=4)
        ttk.Button(b, text="Отмена", command=self.destroy).pack(side="left")
        self.bind("<Return>", lambda _e: self._ok())
        self.bind("<Escape>", lambda _e: self.destroy())
        theme.titlebar(self)
        self.grab_set()
        self.wait_window()

    def _id_changed(self, *_):
        if self.auto_net and self.v_id.get().strip().isdigit():
            vid = int(self.v_id.get())
            if 1 <= vid <= 255:
                self.v_net.set(f"192.168.{vid}.0/24")

    def _ok(self):
        try:
            vid = int(self.v_id.get().strip())
            if not 1 <= vid <= 4094:
                raise ValueError
        except ValueError:
            messagebox.showerror("Ошибка", "VLAN ID — число от 1 до 4094", parent=self)
            return
        if vid in self.taken:
            messagebox.showerror("Ошибка", f"VLAN {vid} уже есть в списке", parent=self)
            return
        try:
            net = sc.validate_subnet(self.v_net.get())
        except ValueError as e:
            messagebox.showerror("Ошибка", f"Неверная подсеть: {e}", parent=self)
            return
        self.result = {"id": vid, "name": self.v_name.get().strip(), "subnet": net}
        self.destroy()


class App:
    def __init__(self, root):
        self.root = root
        self.cfg = sc.load_config()
        self.history = sc.History()
        self.oui = sc.OuiDb()
        self.hosts = {}
        self.q = queue.Queue()
        self.scanner = None
        self.scan_vlans, self.scan_full = set(), False
        self.complete_vlans = set()  # VLAN, просканированные до конца — для «Свободных IP»
        self.free_dlg = None
        self.sort_col, self.sort_rev = "ip", False
        self.vlans_dirty = False
        root.title("VLAN IP Scanner")
        self._place_window()
        root.minsize(900, 500)
        theme.setup_fonts(root)
        theme.apply(root, self.cfg["theme"])
        self._build_ui()
        self.apply_tags()
        self.refresh_vlans()
        n = len(self.oui.map)
        self.status.set(f"Готово. База вендоров: {n} записей" if n else
                        "Готово. База вендоров не загружена — нажмите «Обновить базу вендоров»")
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.after(100, self.poll)

    # ------------------------------------------------------------ UI
    def _place_window(self):
        """Восстанавливает размер окна, но не больше рабочей области экрана."""
        sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        maxw, maxh = sw - 20, sh - 90  # запас на рамку и панель задач
        geo = self.cfg.get("geometry", "")
        if geo == "zoomed":
            self.root.state("zoomed")
            return
        try:
            size, x, y = geo.split("+")[0], int(geo.split("+")[1]), int(geo.split("+")[2])
            w, h = map(int, size.split("x"))
        except (ValueError, IndexError):
            w, h, x, y = 1400, 780, None, None
        if w > maxw or h > maxh:
            self.root.state("zoomed")
            return
        if x is None or not (0 <= x <= sw - w and 0 <= y <= maxh - h + 40):
            x, y = (sw - w) // 2, max(0, (maxh - h) // 2)
        self.root.geometry(f"{w}x{h}+{x}+{y}")

    def _build_ui(self):
        top = ttk.Frame(self.root, padding=(6, 6, 6, 2))
        top.pack(fill="x")
        self.btn_scan = ttk.Button(top, text="▶ Сканировать", command=self.start_scan,
                                   style="Accent.TButton")
        self.btn_stop = ttk.Button(top, text="■ Стоп", command=self.stop_scan, state="disabled",
                                   style="Alert.TButton")
        self.btn_clear = ttk.Button(top, text="Очистить", command=self.clear)
        for b in (self.btn_scan, self.btn_stop, self.btn_clear,
                  ttk.Button(top, text="Экспорт CSV", command=self.export_csv),
                  ttk.Button(top, text="Свободные IP", command=self.show_free)):
            b.pack(side="left", padx=2)
        self.v_names = tk.BooleanVar(value=self.cfg["resolve_names"])
        self.v_tcp = tk.BooleanVar(value=self.cfg["tcp_discovery"])
        self.v_ports = tk.BooleanVar(value=self.cfg["scan_ports"])
        ttk.Separator(top, orient="vertical").pack(side="left", fill="y", padx=6)
        for text, var in [("Имена + MAC (DNS/NetBIOS)", self.v_names),
                          ("Искать без ping (TCP)", self.v_tcp), ("Сканировать порты", self.v_ports)]:
            ttk.Checkbutton(top, text=text, variable=var, command=self.save_opts).pack(side="left", padx=4)
        self.btn_theme = ttk.Button(top, width=3, command=self.toggle_theme)
        self.btn_theme.pack(side="right", padx=(6, 2))
        self.v_only_new = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Только новые", variable=self.v_only_new,
                        command=self.refresh_table).pack(side="right", padx=4)
        self.v_search = tk.StringVar()
        self.v_search.trace_add("write", lambda *_: self.refresh_table())
        ttk.Entry(top, textvariable=self.v_search, width=24).pack(side="right", padx=2)
        ttk.Label(top, text="Поиск:").pack(side="right")

        pw = ttk.PanedWindow(self.root, orient="horizontal")
        pw.pack(fill="both", expand=True, padx=6, pady=4)
        left = ttk.Frame(pw)
        right = ttk.Frame(pw)
        pw.add(left, weight=0)
        pw.add(right, weight=1)

        self.vt = ttk.Treeview(left, columns=[c[0] for c in VLAN_COLS], show="headings",
                               selectmode="extended")
        for cid, text, w in VLAN_COLS:
            self.vt.heading(cid, text=text)
            self.vt.column(cid, width=w, stretch=cid == "name",
                           anchor="w" if cid == "name" else "center")
        self.vt.pack(fill="both", expand=True)
        self.vt.bind("<Button-1>", self.on_vlan_click)
        self.vt.bind("<Double-1>", self.on_vlan_double)
        self.vt.bind("<<TreeviewSelect>>", lambda _e: self.refresh_table())
        bf = ttk.Frame(left)
        bf.pack(fill="x", pady=(4, 0))
        for i, (text, cmd) in enumerate([("Все", lambda: self.check_all(True)),
                                         ("Ничего", lambda: self.check_all(False)),
                                         ("Добавить", self.add_vlan), ("Изменить", self.edit_vlan),
                                         ("Удалить", self.delete_vlan)]):
            ttk.Button(bf, text=text, command=cmd, width=9).grid(row=0, column=i, padx=1, sticky="ew")
            bf.columnconfigure(i, weight=1)
        ttk.Button(left, text="Показать все VLAN",
                   command=lambda: self.vt.selection_remove(self.vt.selection())).pack(fill="x", pady=(3, 0))
        self.btn_oui = ttk.Button(left, text="Обновить базу вендоров", command=self.update_oui)
        self.btn_oui.pack(fill="x", pady=(3, 0))

        self.rt = ttk.Treeview(right, columns=[c[0] for c in COLS], show="headings",
                               selectmode="extended")
        for cid, text, w in COLS:
            self.rt.heading(cid, text=text, command=lambda c=cid: self.sort_by(c))
            self.rt.column(cid, width=w, stretch=cid in ("name", "vendor", "model", "ports"),
                           anchor="center" if cid in ("vlan", "ping", "new") else "w")
        ys =ttk.Scrollbar(right, orient="vertical", command=self.rt.yview)
        xs = ttk.Scrollbar(right, orient="horizontal", command=self.rt.xview)
        self.rt.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        self.rt.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        right.rowconfigure(0, weight=1)
        right.columnconfigure(0, weight=1)
        self.rt.bind("<Button-3>", self.on_context)
        self._update_sort_headings()

        bottom = ttk.Frame(self.root, padding=(6, 0, 6, 6))
        bottom.pack(fill="x")
        self.progress = ttk.Progressbar(bottom, mode="determinate")
        self.progress.pack(fill="x")
        self.status = tk.StringVar()
        ttk.Label(bottom, textvariable=self.status, anchor="w",
                  style="Status.TLabel").pack(fill="x", pady=(3, 0))

    def apply_tags(self):
        p = theme.P
        self.rt.tag_configure("new", background=p["new_bg"], foreground=p["new_fg"])
        self.vt.tag_configure("on", foreground=p["accent"])
        self.vt.tag_configure("off", foreground=p["dim"])
        self.btn_theme.configure(text="☀" if theme.is_dark() else "☾")

    def toggle_theme(self):
        self.cfg["theme"] = "light" if theme.is_dark() else "dark"
        sc.save_config(self.cfg)
        theme.apply(self.root, self.cfg["theme"])
        self.apply_tags()
        if self.free_dlg and self.free_dlg.winfo_exists():
            self.free_dlg.apply_theme()

    # ------------------------------------------------------------ VLAN список
    def vlan_by_id(self, vid):
        return next((v for v in self.cfg["vlans"] if v["id"] == vid), None)

    def refresh_vlans(self):
        sel = set(self.vt.selection())
        self.vt.delete(*self.vt.get_children())
        counts = {}
        for h in self.hosts.values():
            counts[h["vlan"]] = counts.get(h["vlan"], 0) + 1
        for v in sorted(self.cfg["vlans"], key=lambda v: v["id"]):
            iid = str(v["id"])
            self.vt.insert("", "end", iid=iid, values=(
                CHECK[v["enabled"]], v["id"], v["name"], v["subnet"],
                counts.get(v["id"], "")), tags=("on" if v["enabled"] else "off",))
        keep = [i for i in sel if self.vt.exists(i)]
        if keep:
            self.vt.selection_set(keep)
        self.vlans_dirty = False

    def update_vlan_counts(self):
        counts = {}
        for h in self.hosts.values():
            counts[h["vlan"]] = counts.get(h["vlan"], 0) + 1
        for iid in self.vt.get_children():
            self.vt.set(iid, "online", counts.get(int(iid), ""))
        self.vlans_dirty = False

    def on_vlan_click(self, e):
        if self.vt.identify_region(e.x, e.y) == "cell" and self.vt.identify_column(e.x) == "#1":
            iid = self.vt.identify_row(e.y)
            v = self.vlan_by_id(int(iid)) if iid else None
            if v:
                v["enabled"] = not v["enabled"]
                self.vt.set(iid, "chk", CHECK[v["enabled"]])
                self.vt.item(iid, tags=("on" if v["enabled"] else "off",))
                self.vt.focus(iid)  # «Изменить»/«Удалить» без выделения работают с этой строкой
                sc.save_config(self.cfg)
            return "break"
        return None

    def on_vlan_double(self, e):
        if self.vt.identify_column(e.x) != "#1" and self.vt.identify_row(e.y):
            self.edit_vlan(self.vt.identify_row(e.y))
        return "break"

    def check_all(self, state):
        for v in self.cfg["vlans"]:
            v["enabled"] = state
        sc.save_config(self.cfg)
        self.refresh_vlans()

    def add_vlan(self):
        d = VlanDialog(self.root, "Добавить VLAN", None, {v["id"] for v in self.cfg["vlans"]})
        if d.result:
            self.cfg["vlans"].append(sc.make_vlan(d.result["id"], d.result["name"], d.result["subnet"]))
            sc.save_config(self.cfg)
            self.refresh_vlans()

    def edit_vlan(self, iid=None):
        iid = iid or (self.vt.focus() or (self.vt.selection() or [None])[0])
        v = self.vlan_by_id(int(iid)) if iid else None
        if not v:
            messagebox.showinfo("Изменить", "Щёлкните по строке VLAN (по номеру или названию)")
            return
        d = VlanDialog(self.root, f"Изменить VLAN {v['id']}", v,
                       {x["id"] for x in self.cfg["vlans"] if x is not v})
        if d.result:
            if d.result["id"] != v["id"]:
                for h in self.hosts.values():
                    if h["vlan"] == v["id"]:
                        h["vlan"] = d.result["id"]
            # другая подсеть — прошлый скан к ней не относится
            if d.result["id"] != v["id"] or d.result["subnet"] != v["subnet"]:
                self.complete_vlans.discard(v["id"])
            v.update(d.result)
            sc.save_config(self.cfg)
            self.refresh_vlans()
            self.refresh_table()

    def delete_vlan(self):
        ids = [int(i) for i in self.vt.selection() or [self.vt.focus()] if i]
        if not ids:
            messagebox.showinfo("Удалить", "Щёлкните по строке VLAN (по номеру или названию), "
                                           "затем «Удалить». Ctrl+клик — несколько VLAN.")
            return
        if not messagebox.askyesno("Удалить", "Удалить VLAN " + ", ".join(map(str, ids)) + "?"):
            return
        self.cfg["vlans"] = [v for v in self.cfg["vlans"] if v["id"] not in ids]
        sc.save_config(self.cfg)
        self.refresh_vlans()
        self.refresh_table()

    def save_opts(self):
        self.cfg["resolve_names"] = self.v_names.get()
        self.cfg["tcp_discovery"] = self.v_tcp.get()
        self.cfg["scan_ports"] = self.v_ports.get()
        sc.save_config(self.cfg)

    # ------------------------------------------------------------ таблица
    def row_values(self, h):
        return (h["vlan"], h["ip"], h["name"], h["mac"], h["vendor"], h["model"], ping_text(h["rtt"]),
                h["os"], sc.ports_text(h["ports"]), h["how"], "NEW" if h["new"] else "")

    def visible(self, h):
        sel = {int(i) for i in self.vt.selection()}
        if sel and h["vlan"] not in sel:
            return False
        if self.v_only_new.get() and not h["new"]:
            return False
        q = self.v_search.get().strip().lower()
        if q:
            text = " ".join(map(str, self.row_values(h))) + " " + " ".join(
                (h["dns"], h["netbios"], h["domain"], h["snmp_name"]))
            return q in text.lower()
        return True

    def sort_key(self, h):
        c = self.sort_col
        if c == "ip":
            return (ip_key(h["ip"]),)
        if c == "vlan":
            return (h["vlan"], ip_key(h["ip"]))
        if c == "ping":
            return (h["rtt"] if h["rtt"] is not None else 1e9, ip_key(h["ip"]))
        idx = [x[0] for x in COLS].index(c)
        return (str(self.row_values(h)[idx]).lower(), ip_key(h["ip"]))

    def sort_by(self, col):
        self.sort_rev = not self.sort_rev if col == self.sort_col else False
        self.sort_col = col
        self._update_sort_headings()
        self.refresh_table()

    def _update_sort_headings(self):
        for cid, text, _ in COLS:
            arrow = (" ▼" if self.sort_rev else " ▲") if cid == self.sort_col else ""
            self.rt.heading(cid, text=text + arrow)

    def refresh_table(self):
        sel = set(self.rt.selection())
        self.rt.delete(*self.rt.get_children())
        rows = sorted((h for h in self.hosts.values() if self.visible(h)),
                      key=self.sort_key, reverse=self.sort_rev)
        for h in rows:
            self.rt.insert("", "end", iid=h["ip"], values=self.row_values(h),
                           tags=("new",) if h["new"] else ())
        keep = [i for i in sel if self.rt.exists(i)]
        if keep:
            self.rt.selection_set(keep)

    def upsert_row(self, h):
        exists = self.rt.exists(h["ip"])
        if not self.visible(h):
            if exists:
                self.rt.delete(h["ip"])
            return
        tags = ("new",) if h["new"] else ()
        if exists:
            self.rt.item(h["ip"], values=self.row_values(h), tags=tags)
        else:
            self.rt.insert("", "end", iid=h["ip"], values=self.row_values(h), tags=tags)

    def enrich(self, h):
        h["name"] = h["dns"] or h["netbios"] or h["snmp_name"]
        h["vendor"] = self.oui.lookup(h["mac"]) if h["mac"] else ""
        h["os"] = sc.guess_os(h["ttl"], h["ports"], h["printer"])

    # ------------------------------------------------------------ скан
    def scan_opts(self, **over):
        o = {k: self.cfg[k] for k in ("threads", "ping_timeout_ms", "tcp_timeout",
                                      "port_timeout", "netbios_timeout", "ping_retries",
                                      "snmp_community", "snmp_timeout")}
        o.update(resolve_names=self.v_names.get(), tcp_discovery=self.v_tcp.get(),
                 scan_ports=self.v_ports.get())
        o.update(over)
        return o

    def start_scan(self):
        if self.scanner:
            return
        vlans = [v for v in self.cfg["vlans"] if v["enabled"]]
        if not vlans:
            messagebox.showinfo("Сканирование", "Отметьте галочкой хотя бы один VLAN")
            return
        ids = {v["id"] for v in vlans}
        for ip in [ip for ip, h in self.hosts.items() if h["vlan"] in ids]:
            del self.hosts[ip]
        self.complete_vlans -= ids
        self.refresh_table()
        self.update_vlan_counts()
        self._run(sc.expand_targets(vlans), self.scan_opts(), ids, full=True)

    def rescan_selected(self):
        if self.scanner:
            return
        targets = [(self.hosts[i]["vlan"], i) for i in self.rt.selection() if i in self.hosts]
        if targets:
            self._run(targets, self.scan_opts(resolve_names=True, tcp_discovery=True,
                                              scan_ports=True), {t[0] for t in targets}, full=False)

    def _run(self, targets, opts, vlan_ids, full):
        self.scan_vlans, self.scan_full = vlan_ids, full
        self.progress.configure(maximum=max(1, len(targets)), value=0)
        self.btn_scan.configure(state="disabled")
        self.btn_clear.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.scanner = sc.Scanner(targets, opts, self.q)
        self.scanner.start()

    def stop_scan(self):
        if self.scanner:
            self.scanner.stop()
            self.btn_stop.configure(state="disabled")
            self.status.set("Остановка…")

    def clear(self):
        self.hosts.clear()
        self.complete_vlans.clear()
        self.refresh_table()
        self.update_vlan_counts()
        self.status.set("Очищено")

    def on_host(self, h):
        old = self.hosts.get(h["ip"])
        if old:
            for k in ("dns", "netbios", "domain", "mac", "snmp_name", "model", "printer"):
                h[k] = h[k] or old[k]
            if not h["ports_scanned"]:
                h["ports"] = sorted(set(h["ports"]) | set(old["ports"]))
            h["new"] = old["new"]
        else:
            h["new"] = self.history.is_new(h["vlan"], h["ip"])
        self.enrich(h)
        h["first"] = self.history.update(h)
        self.hosts[h["ip"]] = h
        self.upsert_row(h)
        self.vlans_dirty = True

    def on_mac(self, ip, mac):
        h = self.hosts.get(ip)
        if h and not h["mac"]:
            h["mac"] = mac
            self.enrich(h)
            self.history.update(h)
            self.upsert_row(h)

    def status_text(self, prefix=""):
        s = self.scanner
        parts = [f"VLAN {v}: {sum(1 for h in self.hosts.values() if h['vlan'] == v)}"
                 for v in sorted(self.scan_vlans)]
        t = int(sc.time.monotonic() - s.started) if s else 0
        return (f"{prefix}Проверено {s.done}/{s.total}, найдено {s.found}  |  "
                + ", ".join(parts) + f"  |  {t // 60:02d}:{t % 60:02d}")

    def on_done(self, stopped, secs):
        s = self.scanner
        if self.scan_full and not stopped:
            self.history.mark_scanned(self.scan_vlans)
            self.complete_vlans |= self.scan_vlans
        self.history.save()
        self.refresh_table()
        self.update_vlan_counts()
        self.progress.configure(value=s.total if not stopped else s.done)
        self.status.set(self.status_text("Остановлено. " if stopped else "Готово. ")
                        .rsplit("|", 1)[0] + f"|  время {secs:.1f} с")
        self.scanner = None
        self.btn_scan.configure(state="normal")
        self.btn_clear.configure(state="normal")
        self.btn_stop.configure(state="disabled")

    def poll(self):
        try:
            for _ in range(500):
                msg = self.q.get_nowait()
                if msg[0] == "host":
                    self.on_host(msg[1])
                elif msg[0] == "mac":
                    self.on_mac(msg[1], msg[2])
                elif msg[0] == "done":
                    self.on_done(msg[1], msg[2])
                elif msg[0] == "oui":
                    self.on_oui_done(msg[1])
        except queue.Empty:
            pass
        if self.scanner:
            self.progress.configure(value=self.scanner.done)
            if not self.scanner.stop_event.is_set():
                self.status.set(self.status_text())
        if self.vlans_dirty:
            self.update_vlan_counts()
        self.root.after(100, self.poll)

    # ------------------------------------------------------------ свободные IP
    def show_free(self):
        vlans = [v for v in self.cfg["vlans"] if v["id"] in self.complete_vlans]
        if not vlans:
            messagebox.showinfo("Свободные IP", "Сначала просканируйте VLAN до конца (без «Стоп»)")
            return
        if self.free_dlg and self.free_dlg.winfo_exists():
            self.free_dlg.destroy()
        sel = [int(i) for i in self.vt.selection()]
        self.free_dlg = FreeIpDialog(self.root, vlans, self.hosts, self.history.hosts,
                                     sel[0] if sel else None)

    # ------------------------------------------------------------ вендоры
    def update_oui(self):
        self.btn_oui.configure(state="disabled")
        self.status.set("Скачивание базы вендоров IEEE…")

        def work():
            try:
                sc.download_oui()
                self.q.put(("oui", None))
            except Exception as e:  # noqa: BLE001 — сообщаем пользователю любую ошибку
                self.q.put(("oui", str(e)))
        threading.Thread(target=work, daemon=True).start()

    def on_oui_done(self, err):
        self.btn_oui.configure(state="normal")
        if err:
            self.status.set(f"Не удалось скачать базу вендоров: {err}")
            return
        self.oui.load()
        for h in self.hosts.values():
            self.enrich(h)
        self.refresh_table()
        self.status.set(f"База вендоров обновлена: {len(self.oui.map)} записей")

    # ------------------------------------------------------------ экспорт
    def export_csv(self):
        items = self.rt.get_children()
        if not items:
            messagebox.showinfo("Экспорт", "Нет данных для экспорта")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV", "*.csv")],
            initialfile=f"vlan-scan-{sc.datetime.now():%Y%m%d-%H%M}.csv")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8-sig", newline="") as f:
                w = csv.writer(f, delimiter=";")
                w.writerow([c[1] for c in COLS] + CSV_EXTRA)
                for ip in items:
                    h = self.hosts[ip]
                    w.writerow(list(self.row_values(h)) +
                               [h.get("first", ""), h["dns"], h["netbios"], h["domain"], h["snmp_name"]])
        except OSError as e:
            messagebox.showerror("Экспорт", f"Не удалось сохранить файл:\n{e}")
            return
        self.status.set(f"Экспортировано {len(items)} строк: {path}")

    # ------------------------------------------------------------ контекстное меню
    def on_context(self, e):
        iid = self.rt.identify_row(e.y)
        if not iid:
            return
        if iid not in self.rt.selection():
            self.rt.selection_set(iid)
        self.rt.focus(iid)
        h = self.hosts[iid]
        ip = h["ip"]
        m = tk.Menu(self.root, tearoff=0)
        m.add_command(label="Копировать IP", command=self.copy_ips)
        m.add_command(label="Копировать строки", command=self.copy_rows)
        m.add_separator()
        m.add_command(label=f"RDP {ip}", command=lambda: self.launch(["mstsc", f"/v:{ip}"]))
        user = self.cfg.get("ssh_user", "").strip()
        target = f"{user}@{ip}" if user else ip
        m.add_command(label=f"SSH {target}", command=lambda: self.console(["ssh", target]))
        m.add_command(label=f"Открыть \\\\{ip}", command=lambda: self.launch(["explorer", f"\\\\{ip}"]))
        m.add_command(label=f"http://{ip}", command=lambda: webbrowser.open(f"http://{ip}"))
        m.add_command(label=f"https://{ip}", command=lambda: webbrowser.open(f"https://{ip}"))
        if 8006 in h["ports"]:
            m.add_command(label=f"Proxmox https://{ip}:8006",
                          command=lambda: webbrowser.open(f"https://{ip}:8006"))
        m.add_command(label=f"ping -t {ip}", command=lambda: self.console(["ping", "-t", ip]))
        m.add_separator()
        m.add_command(label="Пересканировать выделенные с портами", command=self.rescan_selected,
                      state="disabled" if self.scanner else "normal")
        try:
            m.tk_popup(e.x_root, e.y_root)
        finally:
            m.grab_release()

    def copy_ips(self):
        self._clip("\n".join(self.rt.selection()))

    def copy_rows(self):
        lines = ["\t".join(c[1] for c in COLS)]
        lines += ["\t".join(map(str, self.row_values(self.hosts[i]))) for i in self.rt.selection()]
        self._clip("\n".join(lines))

    def _clip(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)

    def launch(self, args):
        try:
            subprocess.Popen(args)
        except OSError as e:
            messagebox.showerror("Ошибка запуска", str(e))

    def console(self, args):
        """Команда в новом окне cmd, которое остаётся открытым."""
        try:
            subprocess.Popen(["cmd", "/k"] + args, creationflags=subprocess.CREATE_NEW_CONSOLE)
        except OSError as e:
            messagebox.showerror("Ошибка запуска", str(e))

    def on_close(self):
        if self.scanner:
            self.scanner.stop()
        self.history.save()
        self.cfg["geometry"] = ("zoomed" if self.root.state() == "zoomed"
                                else self.root.geometry())
        self.save_opts()
        self.root.destroy()


def main():
    enable_dpi_awareness()
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
