"""Темы оформления: тёмная неоновая «Матрица» и светлая. Только ttk (clam) + стандартный tkinter."""
import ctypes
from tkinter import font as tkfont
from tkinter import ttk

THEMES = {
    "dark": {
        "bg": "#050A05", "panel": "#0C140C", "field": "#081008", "border": "#1F4D2B",
        "hover": "#143D20", "fg": "#B8FFC8", "dim": "#5E8F6A", "accent": "#00FF66",
        "accent2": "#00B347", "on_accent": "#031A0A", "sel_bg": "#0B6B2E", "sel_fg": "#EFFFF3",
        "alert": "#FF3355", "new_bg": "#262600", "new_fg": "#E6FF00",
        "seen_fg": "#FFC400", "busy_bg": "#3D0A12", "busy_fg": "#FF5C77",
        "ok_bg": "#0F3D1F", "ok_fg": "#00FF66",
    },
    "light": {
        "bg": "#EEF5F0", "panel": "#FFFFFF", "field": "#FFFFFF", "border": "#A8C8B0",
        "hover": "#DCEFE2", "fg": "#102016", "dim": "#5B7363", "accent": "#00873A",
        "accent2": "#006B2E", "on_accent": "#FFFFFF", "sel_bg": "#00873A", "sel_fg": "#FFFFFF",
        "alert": "#C62839", "new_bg": "#FFF3A0", "new_fg": "#102016",
        "seen_fg": "#8A6D00", "busy_bg": "#FFD0D0", "busy_fg": "#7A0012",
        "ok_bg": "#D6F5D6", "ok_fg": "#0B5A26",
    },
}
MONO = ("Cascadia Mono", "Consolas", "Courier New")
P = dict(THEMES["dark"])  # текущая палитра — читают окна для цветов строк


def is_dark():
    return P["bg"] == THEMES["dark"]["bg"]


def setup_fonts(root, size=10):
    """Моноширинный шрифт для всего интерфейса (меняем стандартные именованные шрифты)."""
    fams = set(tkfont.families(root))
    family = next((f for f in MONO if f in fams), "TkFixedFont")
    for name in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkFixedFont", "TkTooltipFont",
                 "TkCaptionFont", "TkSmallCaptionFont", "TkIconFont"):
        tkfont.nametofont(name).configure(family=family, size=size)
    tkfont.nametofont("TkHeadingFont").configure(family=family, size=size, weight="bold")


def titlebar(win, dark=None):
    """Тёмный заголовок окна Windows 10/11 (DWMWA_USE_IMMERSIVE_DARK_MODE)."""
    dark = is_dark() if dark is None else dark
    try:
        win.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(win.winfo_id())
        val = ctypes.c_int(1 if dark else 0)
        for attr in (20, 19):  # 19 — старые сборки Windows 10
            if ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, attr, ctypes.byref(val), 4) == 0:
                break
    except (AttributeError, OSError):
        pass


def apply(root, name):
    P.clear()
    P.update(THEMES.get(name, THEMES["dark"]))
    c = P
    s = ttk.Style(root)
    s.theme_use("clam")
    line = tkfont.nametofont("TkDefaultFont").metrics("linespace")
    s.configure(".", background=c["bg"], foreground=c["fg"], fieldbackground=c["field"],
                bordercolor=c["border"], darkcolor=c["panel"], lightcolor=c["panel"],
                troughcolor=c["panel"], focuscolor=c["accent"], selectbackground=c["sel_bg"],
                selectforeground=c["sel_fg"], insertcolor=c["accent"], arrowcolor=c["accent"])
    s.map(".", foreground=[("disabled", c["dim"])])
    s.configure("TFrame", background=c["bg"])
    s.configure("TLabel", background=c["bg"], foreground=c["fg"])
    s.configure("Status.TLabel", foreground=c["accent"])
    s.configure("TSeparator", background=c["border"])
    s.configure("TPanedwindow", background=c["bg"])
    s.configure("Sash", sashthickness=6, gripcount=0, background=c["bg"])

    s.configure("TButton", background=c["panel"], foreground=c["accent"], bordercolor=c["border"],
                lightcolor=c["panel"], darkcolor=c["panel"], padding=(10, 4), relief="flat")
    s.map("TButton", background=[("disabled", c["bg"]), ("pressed", c["sel_bg"]), ("active", c["hover"])],
          bordercolor=[("disabled", c["border"]), ("active", c["accent"]), ("focus", c["accent2"])],
          foreground=[("disabled", c["dim"])])
    s.configure("Accent.TButton", background=c["accent"], foreground=c["on_accent"],
                bordercolor=c["accent"], lightcolor=c["accent"], darkcolor=c["accent"])
    s.map("Accent.TButton", background=[("disabled", c["panel"]), ("pressed", c["accent2"]),
                                        ("active", c["accent2"])],
          foreground=[("disabled", c["dim"])], bordercolor=[("disabled", c["border"])])
    s.configure("Alert.TButton", foreground=c["alert"])
    s.map("Alert.TButton", bordercolor=[("disabled", c["border"]), ("active", c["alert"])],
          foreground=[("disabled", c["dim"])])

    s.configure("TCheckbutton", background=c["bg"], foreground=c["fg"],
                indicatorbackground=c["field"], indicatorforeground=c["accent"],
                upperbordercolor=c["border"], lowerbordercolor=c["border"])
    s.map("TCheckbutton", background=[("active", c["bg"])], foreground=[("active", c["accent"])],
          indicatorbackground=[("selected", c["sel_bg"])])
    s.configure("TEntry", fieldbackground=c["field"], foreground=c["fg"], bordercolor=c["border"],
                lightcolor=c["field"], darkcolor=c["field"], padding=3)
    s.map("TEntry", bordercolor=[("focus", c["accent"])], lightcolor=[("focus", c["accent"])])
    s.configure("TCombobox", fieldbackground=c["field"], background=c["panel"], foreground=c["fg"],
                bordercolor=c["border"], lightcolor=c["field"], darkcolor=c["field"], padding=3)
    s.map("TCombobox", fieldbackground=[("readonly", c["field"])], foreground=[("readonly", c["fg"])],
          selectbackground=[("readonly", c["field"])], selectforeground=[("readonly", c["accent"])],
          bordercolor=[("focus", c["accent"])], background=[("active", c["hover"])])

    s.configure("Treeview", background=c["field"], fieldbackground=c["field"], foreground=c["fg"],
                bordercolor=c["border"], lightcolor=c["field"], darkcolor=c["field"],
                rowheight=int(line * 1.45))
    s.map("Treeview", background=[("selected", c["sel_bg"])], foreground=[("selected", c["sel_fg"])])
    s.configure("Treeview.Heading", background=c["panel"], foreground=c["accent"], relief="flat",
                bordercolor=c["border"], lightcolor=c["panel"], darkcolor=c["border"], padding=(4, 4))
    s.map("Treeview.Heading", background=[("active", c["hover"])])
    for o in ("Vertical", "Horizontal"):
        s.configure(f"{o}.TScrollbar", background=c["panel"], troughcolor=c["bg"],
                    bordercolor=c["bg"], lightcolor=c["panel"], darkcolor=c["panel"],
                    arrowcolor=c["accent"], gripcount=0)
        s.map(f"{o}.TScrollbar", background=[("active", c["hover"])])
    s.configure("Horizontal.TProgressbar", background=c["accent"], troughcolor=c["panel"],
                bordercolor=c["border"], lightcolor=c["accent"], darkcolor=c["accent2"], thickness=10)

    # классические виджеты: меню ПКМ, выпадающий список Combobox, фон окон
    for pat, val in [("*Menu.background", c["panel"]), ("*Menu.foreground", c["fg"]),
                     ("*Menu.activeBackground", c["sel_bg"]), ("*Menu.activeForeground", c["sel_fg"]),
                     ("*Menu.disabledForeground", c["dim"]), ("*Menu.relief", "flat"),
                     ("*TCombobox*Listbox.background", c["field"]),
                     ("*TCombobox*Listbox.foreground", c["fg"]),
                     ("*TCombobox*Listbox.selectBackground", c["sel_bg"]),
                     ("*TCombobox*Listbox.selectForeground", c["sel_fg"]),
                     ("*Toplevel.background", c["bg"])]:
        root.option_add(pat, val)
    root.configure(background=c["bg"])
    titlebar(root)
