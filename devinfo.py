"""Сведения об устройстве: SNMP v1 (sysName, sysDescr, MAC) и HTTP (title, Server).

Нужно для принтеров, коммутаторов и прочих устройств без DNS/NetBIOS-имени.
Только стандартная библиотека.
"""
import html
import random
import re
import socket
import ssl
import urllib.request

OID_SYSDESCR = "1.3.6.1.2.1.1.1.0"
OID_SYSNAME = "1.3.6.1.2.1.1.5.0"
OID_IFPHYS = "1.3.6.1.2.1.2.2.1.6"

PRINTER_WORDS = ("printer", "jetdirect", "laserjet", "designjet", "officejet", "mfp",
                 "multifunction", "canon", "xerox", "kyocera", "ricoh", "brother",
                 "epson", "pantum", "konica", "lexmark", "sharp", "mf4", "i-sensys",
                 "multi-environment")
BRANDS = ("canon", "hp", "xerox", "kyocera", "ricoh", "brother", "epson", "pantum",
          "konica", "lexmark", "sharp", "samsung")
GENERIC_TITLES = ("device status", "index", "home", "login", "вход", "web image monitor")
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.S | re.I)


# ---------------------------------------------------------------- SNMP (BER)
def _tlv(tag, body):
    n = len(body)
    if n < 128:
        ln = bytes([n])
    elif n < 256:
        ln = bytes([0x81, n])
    else:
        ln = bytes([0x82, n >> 8, n & 0xFF])
    return bytes([tag]) + ln + body


def _int(v):
    return _tlv(0x02, v.to_bytes((v.bit_length() + 8) // 8 or 1, "big", signed=True))


def _oid(oid):
    p = [int(x) for x in oid.split(".")]
    out = bytes([40 * p[0] + p[1]])
    for n in p[2:]:
        chunk = [n & 0x7F]
        n >>= 7
        while n:
            chunk.append(0x80 | (n & 0x7F))
            n >>= 7
        out += bytes(reversed(chunk))
    return _tlv(0x06, out)


def _oid_str(b):
    parts = [b[0] // 40, b[0] % 40]
    n = 0
    for c in b[1:]:
        n = (n << 7) | (c & 0x7F)
        if not c & 0x80:
            parts.append(n)
            n = 0
    return ".".join(map(str, parts))


def _read(d, i):
    tag, ln = d[i], d[i + 1]
    i += 2
    if ln & 0x80:
        k = ln & 0x7F
        ln = int.from_bytes(d[i:i + k], "big")
        i += k
    return tag, d[i:i + ln], i + ln


def _request(pdu_tag, community, oids, rid, version=0):
    vbs = b"".join(_tlv(0x30, _oid(o) + b"\x05\x00") for o in oids)
    pdu = _tlv(pdu_tag, _int(rid) + _int(0) + _int(0) + _tlv(0x30, vbs))
    return _tlv(0x30, _int(version) + _tlv(0x04, community.encode()) + pdu)  # 0=v1, 1=v2c


def _parse(data, rid):
    """Список (oid, tag, value) или None при ошибке/чужом ответе."""
    _, msg, _ = _read(data, 0)
    i = 0
    for _ in range(2):  # version, community
        _, _, i = _read(msg, i)
    _, pdu, _ = _read(msg, i)
    _, r, j = _read(pdu, 0)
    _, err, j = _read(pdu, j)
    _, _, j = _read(pdu, j)
    if int.from_bytes(r, "big", signed=True) != rid or any(err):
        return None
    _, vbl, _ = _read(pdu, j)
    res, k = [], 0
    while k < len(vbl):
        _, vb, k = _read(vbl, k)
        _, oid, m = _read(vb, 0)
        tag, val, _ = _read(vb, m)
        res.append((_oid_str(oid), tag, val))
    return res


def _snmp(ip, pdu_tag, oids, community, timeout, version=0):
    rid = random.randint(1, 2 ** 30)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        try:
            s.sendto(_request(pdu_tag, community, oids, rid, version), (ip, 161))
            data, _ = s.recvfrom(8192)
            return _parse(data, rid)
        except (OSError, IndexError, ValueError):
            return None


def _text(val):
    return val.decode("utf-8", "replace").replace("\x00", "").strip()


def snmp_info(ip, community="public", timeout=1.0):
    """{'name', 'descr', 'mac'} или None, если SNMP не отвечает."""
    for version in (0, 1):  # одни устройства понимают только v1, другие только v2c
        r = _snmp(ip, 0xA0, [OID_SYSNAME, OID_SYSDESCR], community, timeout, version)
        if r:
            break
    else:
        return None
    vals = {oid: val for oid, tag, val in r if tag == 0x04}
    info = {"name": _text(vals.get(OID_SYSNAME, b"")),
            "descr": _text(vals.get(OID_SYSDESCR, b"")), "mac": ""}
    oid = OID_IFPHYS
    for _ in range(6):  # первые интерфейсы: ищем настоящий MAC (loopback пустой)
        r = _snmp(ip, 0xA1, [oid], community, timeout, version)
        if not r or not r[0][0].startswith(OID_IFPHYS + "."):
            break
        oid, tag, val = r[0]
        if tag == 0x04 and len(val) == 6 and any(val) and val != b"\xff" * 6:
            info["mac"] = ":".join(f"{b:02X}" for b in val)
            break
    return info


# ---------------------------------------------------------------- HTTP
def http_info(ip, timeout=1.5):
    """(title, Server) веб-интерфейса или None."""
    ctx = ssl._create_unverified_context()  # у принтеров самоподписанные сертификаты
    for url in (f"http://{ip}/", f"https://{ip}/"):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                body = r.read(65536).decode("utf-8", "replace")
                server = r.headers.get("Server", "") or ""
        except urllib.error.HTTPError as e:
            body, server = "", e.headers.get("Server", "") or ""
        except (OSError, ValueError, ssl.SSLError):
            continue
        m = TITLE_RE.search(body)
        title = " ".join(html.unescape(m.group(1)).split()) if m else ""
        return title, server
    return None


# ---------------------------------------------------------------- итог
def describe(title, server, sysdescr):
    """Человекочитаемая модель устройства из того, что удалось собрать."""
    if ";" in server:  # HP: "HP HTTP Server; HP DesignJet T730 - F9A29A; Serial..."
        return server.split(";")[1].strip()
    brand = next((b for b in BRANDS if server.lower().startswith(b)), "")
    t = title.split(":")[-1].strip() if title else ""
    t = re.sub(r"^.*»\s*", "", t) if "»" in t else t
    if t and t.lower() not in GENERIC_TITLES:
        brand_txt = "HP" if brand == "hp" else brand.title()
        return f"{brand_txt} {t}" if brand and brand not in t.lower() else t
    if sysdescr:
        return re.split(r"[;,]", sysdescr)[0].strip()
    if brand:
        return "HP" if brand == "hp" else brand.title()
    return ""


def is_printer(*texts):
    s = " ".join(texts).lower()
    return any(w in s for w in PRINTER_WORDS)


def collect(ip, community="public", timeout=1.0):
    """Сводные сведения: name, model, mac, printer."""
    snmp = snmp_info(ip, community, timeout) or {"name": "", "descr": "", "mac": ""}
    title, server = http_info(ip, timeout + 0.5) or ("", "")
    model = describe(title, server, snmp["descr"])
    return {"name": snmp["name"], "model": model, "mac": snmp["mac"],
            "printer": is_printer(model, snmp["descr"], server, title)}
