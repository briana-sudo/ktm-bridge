r"""
KTM Bridge — Phase 0 probe.

Built to the Notion brief:
  KTM Bridge Project     https://app.notion.com/p/3afca70abea68178aae3d73b9b82d414
  Phase 0 Probe Brief    https://app.notion.com/p/3afca70abea681569a9df9ecdfc67f63

WHAT THIS IS
A single portable Windows executable. Brian copies it to the KTM office PC and
double-clicks it once. It runs read-only environment checks and writes a plain
text report to his Desktop.

WHAT IT DOES NOT DO
  * installs nothing
  * changes nothing on the machine
  * sends NO KTM data anywhere. The only network traffic is a HEAD request to
    six named public endpoints to find out whether a non-browser process can
    reach the internet at all. No content is transmitted, no report is
    uploaded. The report stays on the Desktop and Brian relays it by hand.

WHY IT EXISTS
Three assumptions hold the whole bridge up and none has been tested:
  1. Can an unsigned portable exe even RUN at KTM? Group policy blocks
     installers; whether AppLocker/SmartScreen/SRP also blocks arbitrary exes
     is unknown. If this fails the copy-and-run architecture is dead and has
     to be redesigned. This is the single most important answer.
  2. Does the KTM network let a non-browser process out over HTTPS? Chrome
     works; a raw process may be blocked or forced through a proxy.
  3. What are the REAL mapped drives and UNC roots? \\SERVER\Jobs\{Job#} has
     been an assumption since April 2026 and has never been confirmed.

Standard library only, deliberately. Every third-party import is another way
for PyInstaller to produce a broken or antivirus-flagged binary.

Build:  pyinstaller --onefile --console --name probe probe.py
        --console is mandatory. The console is the fallback surface when the
        file write fails.
"""
from __future__ import annotations

import ctypes
import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import traceback
import urllib.error
import urllib.request
from datetime import datetime

REPORT_VERSION = "probe-v1"
REPORT_NAME = "KTM_Probe_Report.txt"
TIMEOUT = 8

ENDPOINTS = [
    "https://api.anthropic.com",
    "https://github.com",
    "https://login.tailscale.com",
    "https://controlplane.tailscale.com",
    "https://api.cloudflare.com",
    "https://www.google.com",          # control: if this fails, nothing is out
]

AV_NAMES = ("crowdstrike", "cylance", "sentinel", "carbonblack", "cbdefense",
            "mcafee", "symantec", "sophos", "eset", "trendmicro", "defender",
            "msmpeng", "sentinelone", "tanium", "qualys", "rapid7", "bit9",
            "digitalguardian", "forcepoint", "zscaler", "netskope")


# ── helpers ──────────────────────────────────────────────────────────────────
def hr():
    return "-" * 72


def desktop_dir():
    """Desktop from the registry first - it may be redirected to OneDrive or a
    network home drive, which is exactly the kind of thing we must not guess."""
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders")
        val, _ = winreg.QueryValueEx(key, "Desktop")
        winreg.CloseKey(key)
        return os.path.expandvars(val)
    except Exception:  # noqa: BLE001
        return os.path.join(os.environ.get("USERPROFILE", ""), "Desktop")


def write_candidates():
    exe_dir = os.path.dirname(
        sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__))
    return [
        ("Desktop", desktop_dir()),
        ("USERPROFILE", os.environ.get("USERPROFILE", "")),
        ("temp", tempfile.gettempdir()),
        ("exe folder", exe_dir),
    ]


# ── the nine checks ──────────────────────────────────────────────────────────
def check_1_launch():
    return [
        "The binary executed. If you are reading this, the exe ran.",
        f"  sys.executable   : {sys.executable}",
        f"  sys.frozen       : {getattr(sys, 'frozen', False)}  "
        f"(True = running as a packed exe, False = loose script)",
        f"  _MEIPASS         : {getattr(sys, '_MEIPASS', '(not set)')}",
        f"  cwd              : {os.getcwd()}",
        f"  python           : {sys.version.split()[0]}",
    ]


def check_2_windows():
    out = [
        f"  platform.platform() : {platform.platform()}",
        f"  platform.version()  : {platform.version()}",
        f"  win32_ver()         : {platform.win32_ver()}",
        f"  machine / arch      : {platform.machine()} / {platform.architecture()[0]}",
        "",
        "  registry HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion:",
    ]
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        for name in ("ProductName", "DisplayVersion", "ReleaseId",
                     "CurrentBuild", "UBR", "EditionID", "InstallationType"):
            try:
                v, _ = winreg.QueryValueEx(key, name)
                out.append(f"    {name:18}: {v}")
            except Exception as exc:  # noqa: BLE001
                out.append(f"    {name:18}: (unreadable: {type(exc).__name__})")
        winreg.CloseKey(key)
    except Exception as exc:  # noqa: BLE001
        out.append(f"    registry unreadable: {exc}")
    return out


def check_3_identity():
    try:
        login = os.getlogin()
    except Exception:  # noqa: BLE001
        login = "(os.getlogin failed)"
    try:
        elevated = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception as exc:  # noqa: BLE001
        elevated = f"(unknown: {type(exc).__name__})"
    return [
        f"  os.getlogin()   : {login}",
        f"  USERNAME        : {os.environ.get('USERNAME', '')}",
        f"  USERDOMAIN      : {os.environ.get('USERDOMAIN', '')}",
        f"  USERPROFILE     : {os.environ.get('USERPROFILE', '')}",
        f"  elevated (admin): {elevated}",
    ]


DRIVE_TYPES = {0: "unknown", 1: "no root dir", 2: "REMOVABLE", 3: "FIXED",
               4: "NETWORK", 5: "CDROM", 6: "RAM disk"}


def unc_for(letter):
    """Resolve a mapped drive letter back to its UNC target."""
    try:
        buf = ctypes.create_unicode_buffer(1024)
        size = ctypes.c_ulong(1024)
        rc = ctypes.windll.mpr.WNetGetConnectionW(
            ctypes.c_wchar_p(letter.rstrip("\\")), buf, ctypes.byref(size))
        return buf.value if rc == 0 else f"(WNetGetConnection rc={rc})"
    except Exception as exc:  # noqa: BLE001
        return f"(failed: {type(exc).__name__})"


def drives():
    found = []
    try:
        mask = ctypes.windll.kernel32.GetLogicalDrives()
    except Exception:  # noqa: BLE001
        return found
    for i in range(26):
        if not (mask >> i) & 1:
            continue
        letter = f"{chr(65 + i)}:\\"
        try:
            t = ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(letter))
        except Exception:  # noqa: BLE001
            t = 0
        found.append((letter, t, DRIVE_TYPES.get(t, str(t))))
    return found


def check_4_drives():
    out = ["  THIS IS THE ANSWER TO THE UNCONFIRMED \\\\SERVER\\Jobs QUESTION.", ""]
    for letter, t, label in drives():
        line = f"  {letter}  {label}"
        if t == 4:
            line += f"   ->  {unc_for(letter)}"
        out.append(line)
    if len(out) == 2:
        out.append("  (no drives enumerated - GetLogicalDrives returned nothing)")
    return out


def check_5_unc():
    out = []
    net = [d for d in drives() if d[1] == 4]
    if not net:
        out.append("  no network drives found to test")
    for letter, _t, _label in net:
        out.append(f"  {letter}")
        try:
            entries = os.listdir(letter)
            out.append(f"    readable, {len(entries)} entries. First 25:")
            for e in sorted(entries)[:25]:
                out.append(f"      {e}")
        except Exception as exc:  # noqa: BLE001
            out.append(f"    NOT readable from a plain process: "
                       f"{type(exc).__name__}: {exc}")
    return out


def check_6_write():
    out = []
    for label, path in write_candidates():
        if not path:
            out.append(f"  {label:14}: (path unset)")
            continue
        probe = os.path.join(path, "_ktm_probe_write_test.tmp")
        try:
            with open(probe, "w", encoding="utf-8") as fh:
                fh.write("test")
            os.remove(probe)
            out.append(f"  {label:14}: WRITABLE   {path}")
        except Exception as exc:  # noqa: BLE001
            out.append(f"  {label:14}: denied     {path}  ({type(exc).__name__})")
    return out


def classify(url):
    req = urllib.request.Request(url, method="HEAD",
                                 headers={"User-Agent": "KTM-Bridge-Probe/1"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return f"OK ({r.status})"
    except urllib.error.HTTPError as e:
        if e.code == 407:
            return "PROXY-REQUIRED (407)"
        return f"OK (reached, HTTP {e.code})"
    except urllib.error.URLError as e:
        reason = getattr(e, "reason", e)
        text = str(reason).lower()
        if isinstance(reason, socket.timeout) or "timed out" in text:
            return "TIMEOUT"
        if "getaddrinfo" in text or "name or service" in text or \
           "no such host" in text or "name resolution" in text:
            return "DNS-FAIL"
        if "refused" in text or "reset" in text or "forcibly closed" in text:
            return "BLOCKED"
        if "certificate" in text or "ssl" in text:
            return f"TLS-INTERCEPTED? ({reason})"
        return f"FAIL ({reason})"
    except Exception as exc:  # noqa: BLE001
        return f"FAIL ({type(exc).__name__}: {exc})"


def check_7_outbound():
    out = ["  Can a NON-BROWSER process reach the internet? This decides the",
           "  bridge transport.", ""]
    for url in ENDPOINTS:
        out.append(f"  {url:42} {classify(url)}")
    out += ["", "  system proxy (HKCU\\...\\Internet Settings):"]
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
        for name in ("ProxyEnable", "ProxyServer", "AutoConfigURL",
                     "ProxyOverride"):
            try:
                v, _ = winreg.QueryValueEx(key, name)
                out.append(f"    {name:14}: {v}")
            except Exception:  # noqa: BLE001
                out.append(f"    {name:14}: (not set)")
        winreg.CloseKey(key)
    except Exception as exc:  # noqa: BLE001
        out.append(f"    unreadable: {exc}")
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"):
        if os.environ.get(var):
            out.append(f"    env {var}: {os.environ[var]}")
    return out


def check_8_runtime():
    out = []
    for exe in ("python.exe", "python3.exe", "py.exe", "pythonw.exe"):
        p = shutil.which(exe)
        if not p:
            out.append(f"  {exe:14}: not on PATH")
            continue
        try:
            r = subprocess.run([p, "-V"], capture_output=True, text=True,
                               timeout=10)
            ver = (r.stdout or r.stderr).strip()
        except Exception as exc:  # noqa: BLE001
            ver = f"(version check failed: {type(exc).__name__})"
        out.append(f"  {exe:14}: {p}   {ver}")
    return out


def check_9_context():
    out = []
    for var in ("COMPUTERNAME", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE",
                "LOGONSERVER", "USERDNSDOMAIN", "USERDOMAIN_ROAMINGPROFILE",
                "SESSIONNAME", "OS"):
        out.append(f"  {var:26}: {os.environ.get(var, '(unset)')}")
    out += ["", "  security tooling visible in tasklist (informational only):"]
    try:
        r = subprocess.run(["tasklist"], capture_output=True, text=True,
                           timeout=25)
        txt = (r.stdout or "").lower()
        hits = sorted({n for n in AV_NAMES if n in txt})
        out.append("    " + (", ".join(hits) if hits else "none of the known names matched"))
    except Exception as exc:  # noqa: BLE001
        out.append(f"    tasklist unavailable: {type(exc).__name__}: {exc}")
    return out


CHECKS = [
    ("1. EXE LAUNCH CONFIRMATION", check_1_launch),
    ("2. WINDOWS EDITION AND BUILD", check_2_windows),
    ("3. USER IDENTITY AND PRIVILEGE", check_3_identity),
    ("4. DRIVE INVENTORY AND UNC MAP", check_4_drives),
    ("5. UNC / SHARE READABILITY", check_5_unc),
    ("6. WRITE PERMISSION BY LOCATION", check_6_write),
    ("7. OUTBOUND REACHABILITY AND PROXY", check_7_outbound),
    ("8. PYTHON RUNTIME ALREADY PRESENT", check_8_runtime),
    ("9. ENVIRONMENT CONTEXT", check_9_context),
]


def build_report():
    L = [
        "KTM BRIDGE - PHASE 0 PROBE REPORT",
        f"report version : {REPORT_VERSION}",
        f"generated      : {datetime.now().isoformat(timespec='seconds')}",
        "",
        "Read-only environment check. Nothing was installed, nothing was",
        "changed, and no KTM data left this machine.",
        hr(),
        "",
    ]
    for title, fn in CHECKS:
        L.append(title)
        try:
            L += fn()
        except Exception:  # noqa: BLE001
            # One broken check must never cost the other eight.
            L.append("  CHECK FAILED - the rest of the report is still valid:")
            for line in traceback.format_exc().splitlines():
                L.append(f"    {line}")
        L += ["", hr(), ""]
    L.append("END OF REPORT")
    return "\n".join(L)


def write_report(text):
    for label, path in write_candidates():
        if not path:
            continue
        dest = os.path.join(path, REPORT_NAME)
        try:
            with open(dest, "w", encoding="utf-8") as fh:
                fh.write(text)
            return dest, label
        except Exception:  # noqa: BLE001
            continue
    return None, None


def main():
    print("KTM Bridge Probe - running, do not close this window")
    print("This reads your settings only. It installs nothing and sends no")
    print("KTM data anywhere. Takes about 30 seconds.")
    print()
    try:
        text = build_report()
    except Exception:  # noqa: BLE001
        text = ("KTM BRIDGE PROBE - CATASTROPHIC FAILURE\n\n"
                + traceback.format_exc())

    dest, label = write_report(text)

    # Echo the whole report regardless. If every write location is denied this
    # is the only way the data survives - Brian can photograph the screen.
    print(hr())
    print(text)
    print(hr())
    if dest:
        print(f"\nReport written to [{label}]:\n  {dest}")
    else:
        print("\nCOULD NOT WRITE THE REPORT ANYWHERE.")
        print("Everything is on screen above - photograph it or select-and-copy.")
    print("\nNothing was installed. Nothing was changed. No data was sent.")
    try:
        input("\nPress Enter to close. ")
    except Exception:  # noqa: BLE001
        pass


if __name__ == "__main__":
    main()
