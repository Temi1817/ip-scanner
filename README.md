# VLAN IP Scanner

**English** · [Русский](README.ru.md)

A Windows desktop tool that scans a corporate network VLAN by VLAN and shows every live host: name, MAC, vendor, device model, OS guess and open ports. It also finds free IP addresses, highlights new devices, and exports results to CSV.

Pure Python standard library (tkinter GUI), no dependencies. Ships as a single `.exe` that needs no Python.

![Dark theme](assets/screenshot-dark.png)

## Features

- **VLAN list**: add, edit and delete VLANs with their subnets. Tick ✓ to include a VLAN in the scan; click rows to filter the host table.
- **Fast background scan**: 128 threads by default, a full /24 takes seconds. The window stays responsive and **Stop** cancels instantly.
- **Host discovery**: ICMP ping, plus a retry for hosts that missed the first ping (sleeping printers, Wi-Fi phones). Optional TCP discovery finds hosts that block ping.
- **Host details**:
  - **name**: reverse DNS, NetBIOS or SNMP;
  - **MAC address and vendor**: IEEE OUI database plus built-in Proxmox, VMware, Hyper-V and QEMU prefixes; randomized MACs are flagged;
  - **device model**: SNMP or the device's web page;
  - **OS guess**: Windows, Linux/Unix, printer, network device, Proxmox;
  - **open ports**: 20 common ports.
- **New devices**: the scan history marks hosts that appeared since the previous scan and highlights them.
- **Free IPs**: lists addresses that did not respond and marks the ones that were taken before (the device may just be off). **Check selected** re-tests addresses right before you assign one.
- **Right-click actions**: copy IP or rows, RDP, SSH, open `\\IP`, http/https, Proxmox web UI (:8006), `ping -t`, rescan with ports.
- **CSV export**: UTF-8 with BOM and `;` separator, so it opens correctly in Excel.
- **Themes**: dark neon "Matrix" theme and a light theme; switch with the ☀/☾ button.

| Free IPs | Light theme |
| --- | --- |
| ![Free IPs](assets/screenshot-free-ip.png) | ![Light theme](assets/screenshot-light.png) |

## How it works

| What | How |
| --- | --- |
| Is the host alive | `ping -n 1 -w 700`, alive only on a `TTL=` reply from that exact IP; one retry with a longer timeout |
| Without ping | TCP connect to 445, 135, 3389, 22, 80, 443, 8006, 9100 (an open port or a RST both count) |
| Name | reverse DNS, NetBIOS NBSTAT (UDP/137), SNMP `sysName` |
| MAC | own interfaces, NetBIOS, `arp -a` (local VLAN), SNMP `ifPhysAddress` (works through routers) |
| Vendor | IEEE `oui.csv` + built-in virtualization prefixes |
| Model | SNMP `sysDescr` (v1, then v2c), web page title and `Server` header |
| OS | open ports and TTL |
| Ports | 21, 22, 23, 53, 80, 135, 139, 443, 445, 515, 631, 1433, 3306, 3389, 5900, 8006, 8080, 8443, 9100, 10050 |

## Getting started

### Run the exe

1. Build it (see below) or download `VLAN-Scanner.exe` from Releases if one is published.
2. Put it in any folder and run it. Settings and history are saved next to the exe.
3. Click **Update vendor database** once to download the IEEE vendor list (~4 MB).
4. Add your VLANs (**Add**), tick them and press **▶ Scan**.

### Run from source

Requirements: Windows 10/11, Python 3.9+ (tested on 3.12).

```bat
git clone https://github.com/Temi1817/ip-scanner.git
cd ip-scanner
python vlan_scanner.py
```

### Build the exe

```bat
build_exe.bat
```

The script installs PyInstaller and builds `dist\VLAN-Scanner.exe` (single file, no console).

## Configuration

On first launch the program creates `config.json` next to itself from built-in defaults. An example with all settings is in [`config.example.json`](config.example.json). Most settings are changed from the UI; these can be edited by hand:

| Key | Default | Meaning |
| --- | --- | --- |
| `threads` | 128 | parallel probes |
| `ping_timeout_ms` | 700 | ping timeout |
| `ping_retries` | 1 | retries for hosts that did not answer (`0` turns retries off) |
| `tcp_timeout` / `port_timeout` | 0.5 / 0.8 | TCP discovery / port scan timeout, seconds |
| `snmp_community` | `public` | SNMP community string |
| `ssh_user` | empty | user for the SSH menu item (`user@ip`) |
| `theme` | `dark` | `dark` or `light` |

## Files

| File | Purpose |
| --- | --- |
| `vlan_scanner.py` | main window, entry point |
| `scancore.py` | ping, TCP, NetBIOS, DNS, ARP, vendors, OS guess, config, history, scanner thread |
| `devinfo.py` | SNMP v1/v2c and HTTP device info |
| `freeip.py` | Free IPs window |
| `theme.py` | dark and light themes |
| `config.json`, `history.json`, `oui.csv` | created at runtime next to the program, not stored in the repo |

## Privacy

Everything stays on your computer. Scan results, VLAN names and history are stored only in `config.json` and `history.json` next to the program, and `.gitignore` keeps them out of git. The only internet request is the optional vendor database download from `standards-oui.ieee.org`.

## Disclaimer

Scan only networks you own or are authorized to administer.
