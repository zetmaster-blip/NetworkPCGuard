# -*- coding: utf-8 -*-
"""
NetworkPCGuard - ネットワークPC外形監視（不正アクセス兆候）GUIツール
=====================================================================
同一LAN上から「PCだけ」を抽出し、外側(ネットワーク側)から定期的に
"外形ポート"を軽くスキャンして、前回との差分＝不正アクセスの兆候を検知する。

  ★ できること（外形監視）:
    - 新しく開いた危険ポート（RDP/Telnet/VNC/RATの既定ポート/DB露出 など）
    - ポートの消失 / 応答性の変化 / 新規PCの出現 / MACのIP移動
    - 平文サービス(Telnet/FTP/HTTP)の露出

  ★ できないこと（正直な限界）:
    - 「実際に侵入され乗っ取られたか」の確証は出せない（それはPC内部＝ログイン履歴・
      イベントログ・プロセスを見る必要がある。ProcessGuard の領域）。
    - このツールが出すのは "外から見える変化" ＝ 侵入の"兆候"であって、侵入そのものの証拠ではない。

  ★ 相棒ツール（役割分担）:
    - NetworkDeviceList … 全機器の棚卸し（このツールの探索エンジン/OUI辞書を流用）
    - WiresharkAnalyzer … 通信の中身の異常（ビーコン/スキャン/平文）
    - ProcessGuard      … このPC自身の内部（プロセス/署名/注入）
    - arp_device_monitor … なりすまし(ARP)

  ★ 自己診断（大事）:
    このツール自身が各PCへTCP接続(ポートスキャン)を行うため、
    WiresharkAnalyzer や ルーターのIPS に "スキャン" として映ることがある（＝自作の足音）。
    宛先はLAN内・厳選ポートのみ・connectスキャン(rawなし)に限定して足音を抑えている。

- Python 標準ライブラリのみ（依存ゼロ・venv不要）
- 管理者権限不要 / TCP connect スキャンのみ（raw socket 不使用）
- 内部パスは __file__ 基準（再配置可能）。設定は env-config 相当を最小限で内蔵。

有限会社 丸枝 / 他ツール（NetworkDeviceList, ProcessGuard, WiresharkAnalyzer）と同じ流儀。
"""

import os
import re
import csv
import json
import html
import time
import socket
import threading
import subprocess
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

APP_TITLE = "ネットワークPC外形監視"
APP_SUBTITLE = "不正アクセスの兆候を外側から見張る（外形ポート監視）"
VERSION = "1.0"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SNAP_DIR = os.path.join(BASE_DIR, "snapshots")
HIST_DIR = os.path.join(BASE_DIR, "history")
OUI_IEEE_FILE = os.path.join(BASE_DIR, "oui_ieee.json")
OUI_USER_FILE = os.path.join(BASE_DIR, "oui_user.json")
BASELINE_FILE = os.path.join(BASE_DIR, "baseline.json")
ALERTS_LOG = os.path.join(BASE_DIR, "alerts_log.csv")
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")

CREATE_NO_WINDOW = 0x08000000

# ---------------------------------------------------------------------------
# 配色（一族の流儀・派手系 / このツールは "監視" なので赤みを足す）
# ---------------------------------------------------------------------------
PALETTE = {
    "grad_a": "#7f1d1d", "grad_b": "#b91c1c", "grad_c": "#ea580c",  # 赤→橙（警戒色）
    "bg": "#f1f5f9", "panel": "#e2e8f0", "info_bg": "#fef2f2",
    "status_bg": "#0f172a", "status_fg": "#e2e8f0",
    "head_bg": "#7f1d1d", "head_fg": "#ffffff",
    "even": "#ffffff", "odd": "#f8fafc",
    "pc_strong": "#dbeafe",   # PC濃厚=薄青
    "pc_maybe": "#eff6ff",    # PCの可能性
    "danger": "#fee2e2",      # 危険=薄赤
    "new": "#fef3c7",         # 新規=薄黄
    "self": "#dcfce7",        # このPC=薄緑
    "btn_scan": "#b91c1c", "btn_mon": "#dc2626", "btn_stop": "#334155",
    "btn_csv": "#0d9488", "btn_html": "#7c3aed", "btn_base": "#a16207",
    "btn_detail": "#475569",
}

# ---------------------------------------------------------------------------
# OUI（MAC先頭3バイト）→ (メーカー名, 推定種別)  ※NetworkDeviceList から流用
# ---------------------------------------------------------------------------
OUI_DB = {
    "AC-44-F2": ("YAMAHA CORPORATION", "ルーター"),
    "B0-B9-8A": ("NETGEAR", "ネットワーク機器 (スイッチ/AP)"),
    "00-1D-73": ("Buffalo Inc.", "ルーター/AP (Buffalo)"),
    "10-6F-3F": ("Buffalo Inc.", "ルーター/AP (Buffalo)"),
    "4C-E1-76": ("Buffalo Inc.", "ルーター/AP (Buffalo)"),
    "50-C7-BF": ("TP-Link", "ルーター/AP (TP-Link)"),
    "C0-25-E9": ("TP-Link", "ルーター/AP (TP-Link)"),
    "00-0C-29": ("VMware, Inc.", "仮想マシン"),
    "00-50-56": ("VMware, Inc.", "仮想マシン"),
    "08-00-27": ("PCS Systemtechnik (VirtualBox)", "仮想マシン"),
    "00-15-5D": ("Microsoft (Hyper-V)", "仮想マシン"),
    "00-00-0C": ("Cisco Systems", "ネットワーク機器 (Cisco)"),
    "BC-32-5F": ("Zhejiang Dahua Technology Co., Ltd.", "防犯カメラ / NVR"),
    "08-ED-ED": ("Zhejiang Dahua Technology Co., Ltd.", "防犯カメラ / NVR"),
    "24-52-6A": ("Zhejiang Dahua Technology Co., Ltd.", "防犯カメラ / NVR"),
    "C0-39-5A": ("Zhejiang Dahua Technology Co., Ltd.", "防犯カメラ / NVR"),
    "B4-4C-3B": ("Zhejiang Dahua Technology Co., Ltd.", "防犯カメラ / NVR"),
    "A8-31-62": ("Hangzhou Huacheng Network Technology Co.,Ltd", "防犯カメラ (EZVIZ系)"),
    "7C-DD-E9": ("ATOM tech Inc.", "ネットワークカメラ (ATOM Cam)"),
    "00-12-12": ("Hangzhou Hikvision", "防犯カメラ (Hikvision)"),
    "4C-BD-8F": ("Hangzhou Hikvision", "防犯カメラ (Hikvision)"),
    "44-19-B6": ("Hangzhou Hikvision", "防犯カメラ (Hikvision)"),
    "4C-EF-C0": ("Amazon Technologies Inc.", "Echo / Alexa / Fire 系"),
    "CC-F7-35": ("Amazon Technologies Inc.", "Echo / Alexa / Fire 系"),
    "F4-03-2A": ("Amazon Technologies Inc.", "Echo / Alexa / Fire 系"),
    "74-D6-37": ("Amazon Technologies Inc.", "Echo / Alexa / Fire 系"),
    "A4-08-01": ("Amazon Technologies Inc.", "Echo / Alexa / Fire 系"),
    "D4-91-0F": ("Amazon Technologies Inc.", "Echo / Alexa / Fire 系"),
    "AC-41-6A": ("Amazon Technologies Inc.", "Echo / Alexa / Fire 系"),
    "5C-41-5A": ("Amazon.com, LLC", "Echo / Alexa / Fire 系"),
    "D8-D4-3C": ("Sony Corporation", "TV / AV機器"),
    "80-99-E7": ("Sony Corporation", "TV / AV機器"),
    "D8-6C-63": ("Google, Inc.", "Chromecast / Nest 系"),
    "DC-E5-5B": ("Google, Inc.", "Chromecast / Nest 系"),
    "78-2B-64": ("Bose Corporation", "スピーカー"),
    "00-17-88": ("Philips Lighting BV", "スマート照明 (Hue)"),
    "90-09-D0": ("Synology Incorporated", "NAS (ストレージ)"),
    "00-11-32": ("Synology Incorporated", "NAS (ストレージ)"),
    "00-08-9B": ("ICP / QNAP", "NAS (ストレージ)"),
    "24-5E-BE": ("QNAP Systems, Inc.", "NAS (ストレージ)"),
    "30-05-5C": ("Brother industries, LTD.", "プリンタ / 複合機"),
    "00-80-77": ("Brother industries, LTD.", "プリンタ / 複合機"),
    "00-00-85": ("Canon Inc.", "プリンタ / 複合機"),
    "00-26-AB": ("Seiko Epson Corporation", "プリンタ / 複合機"),
    "44-D2-44": ("Seiko Epson Corporation", "プリンタ / 複合機"),
    "00-00-74": ("Ricoh Company Ltd.", "プリンタ / 複合機"),
    # --- PC / サーバ（NIC・オンボード） ---
    "10-7C-61": ("ASUSTek COMPUTER INC.", "PC"),
    "2C-F0-5D": ("ASUSTek COMPUTER INC.", "PC"),
    "00-1B-21": ("Intel Corporate", "PC"),
    "00-1E-67": ("Intel Corporate", "PC"),
    "3C-FD-FE": ("Intel Corporate", "PC"),
    "A0-36-9F": ("Intel Corporate", "PC"),
    "00-E0-4C": ("Realtek Semiconductor Corp.", "PC"),
    "52-54-00": ("Realtek/QEMU", "PC / 仮想"),
    "00-21-9B": ("Dell Inc.", "PC (Dell)"),
    "18-66-DA": ("Dell Inc.", "PC (Dell)"),
    "00-1A-A0": ("Dell Inc.", "PC (Dell)"),
    "3C-D9-2B": ("Hewlett Packard", "PC (HP)"),
    "00-1F-29": ("Hewlett Packard", "PC (HP)"),
    "00-21-5A": ("Hewlett Packard", "PC (HP)"),
    "00-21-CC": ("Lenovo", "PC (Lenovo)"),
    "54-EE-75": ("Lenovo", "PC (Lenovo)"),
    "B8-27-EB": ("Raspberry Pi Foundation", "Raspberry Pi / IoT"),
    "DC-A6-32": ("Raspberry Pi Trading Ltd", "Raspberry Pi / IoT"),
    "F0-18-98": ("Apple, Inc.", "Apple端末 (iPhone/iPad/Mac)"),
    "A4-83-E7": ("Apple, Inc.", "Apple端末 (iPhone/iPad/Mac)"),
    "8C-85-90": ("Apple, Inc.", "Apple端末 (iPhone/iPad/Mac)"),
    "34-23-87": ("Samsung Electronics", "スマホ/タブレット (Samsung)"),
    "E8-50-8B": ("Samsung Electronics", "スマホ/タブレット (Samsung)"),
    "F8-A2-D6": ("Xiaomi Communications", "スマホ/IoT (Xiaomi)"),
    "48-3F-DA": ("Espressif Inc. (ESP32)", "IoT (ESP/自作系)"),
    "24-0A-C4": ("Espressif Inc. (ESP32)", "IoT (ESP/自作系)"),
    "98-B6-E9": ("Nintendo Co., Ltd.", "ゲーム機 (Nintendo)"),
    "DC-A4-CA": ("Nintendo Co., Ltd.", "ゲーム機 (Nintendo)"),
}

# メーカー名 → 推定種別（OUI直引きに無い時の補完）
VENDOR_KEYWORD_TYPE = [
    ("dahua", "防犯カメラ / NVR"), ("hikvision", "防犯カメラ (Hikvision)"),
    ("ezviz", "防犯カメラ (EZVIZ系)"), ("huacheng", "防犯カメラ (EZVIZ系)"),
    ("atom", "ネットワークカメラ (ATOM Cam)"), ("ring", "防犯カメラ / ドアベル (Ring)"),
    ("axis", "防犯カメラ (Axis)"), ("amazon", "Echo / Alexa / Fire 系"),
    ("google", "Chromecast / Nest 系"), ("sony", "TV / AV機器"),
    ("bose", "スピーカー"), ("philips", "スマート照明 / 家電"),
    ("synology", "NAS (ストレージ)"), ("qnap", "NAS (ストレージ)"),
    ("brother", "プリンタ / 複合機"), ("canon", "プリンタ / 複合機"),
    ("epson", "プリンタ / 複合機"), ("ricoh", "プリンタ / 複合機"),
    ("yamaha", "ルーター"), ("netgear", "ネットワーク機器 (スイッチ/AP)"),
    ("buffalo", "ルーター/AP (Buffalo)"), ("tp-link", "ルーター/AP (TP-Link)"),
    ("cisco", "ネットワーク機器 (Cisco)"), ("apple", "Apple端末 (iPhone/iPad/Mac)"),
    ("samsung", "スマホ/タブレット (Samsung)"), ("xiaomi", "スマホ/IoT (Xiaomi)"),
    ("espressif", "IoT (ESP/自作系)"), ("raspberry", "Raspberry Pi / IoT"),
    ("nintendo", "ゲーム機 (Nintendo)"),
    ("intel", "PC"), ("realtek", "PC"), ("asus", "PC"), ("dell", "PC (Dell)"),
    ("hewlett", "PC (HP)"), ("lenovo", "PC (Lenovo)"),
    ("vmware", "仮想マシン"), ("hyper-v", "仮想マシン"), ("virtualbox", "仮想マシン"),
]

# PCらしいNICベンダーのキーワード（PC判定の加点用）
PC_VENDOR_KW = ("intel", "realtek", "asus", "dell", "hewlett", "lenovo",
                "micro-star", "msi", "gigabyte", "asrock", "microsoft",
                "hon hai", "wistron", "quanta", "clevo", "tongfang")
# 明確にPCでない種別（減点/除外用）
NONPC_TYPE_KW = ("カメラ", "nvr", "プリンタ", "複合機", "nas", "ストレージ",
                 "ルーター", "スイッチ", "ap", "スピーカー", "tv", "av機器",
                 "照明", "echo", "alexa", "fire", "chromecast", "nest",
                 "ゲーム機", "iot", "hue", "ドアベル")

IEEE_DB = {"oui": {}, "long": {}}

# ---------------------------------------------------------------------------
# 監視対象ポート表  port -> (表示名, 役割, 平文フラグ)
#   役割: pc=PC/ホスト識別  danger=露出が要警戒  watch=注意  info=良性識別
# ---------------------------------------------------------------------------
PORT_CATALOG = {
    21:   ("FTP", "danger", True),
    22:   ("SSH", "watch", False),
    23:   ("Telnet", "danger", True),
    25:   ("SMTP", "watch", False),
    53:   ("DNS", "info", False),
    80:   ("HTTP", "watch", True),
    110:  ("POP3", "watch", True),
    135:  ("MSRPC", "pc", False),
    139:  ("NetBIOS", "pc", False),
    143:  ("IMAP", "watch", True),
    443:  ("HTTPS", "info", False),
    445:  ("SMB", "pc", False),
    515:  ("LPD印刷", "info", False),
    631:  ("IPP印刷", "info", False),
    1080: ("SOCKSプロキシ", "danger", False),
    1433: ("MSSQL", "danger", False),
    1521: ("Oracle", "danger", False),
    3128: ("Squidプロキシ", "watch", False),
    3306: ("MySQL", "danger", False),
    3389: ("RDPリモートデスクトップ", "danger", False),
    4444: ("Metasploit既定/RAT疑い", "danger", False),
    5357: ("WSD", "pc", False),
    5432: ("PostgreSQL", "danger", False),
    5900: ("VNC遠隔操作", "danger", False),
    5901: ("VNC遠隔操作", "danger", False),
    5938: ("TeamViewer遠隔操作", "danger", False),
    5985: ("WinRM", "pc", False),
    5986: ("WinRM(暗号)", "pc", False),
    6379: ("Redis", "danger", False),
    6568: ("AnyDesk/RAT疑い", "danger", False),
    8080: ("HTTP代替/プロキシ", "watch", False),
    8443: ("HTTPS代替", "watch", False),
    9200: ("Elasticsearch", "danger", False),
    27017:("MongoDB", "danger", False),
    62078:("Apple-iTunes同期", "info", False),
}
SCAN_PORTS = sorted(PORT_CATALOG.keys())
PC_HINT_PORTS = {135, 139, 445, 3389, 5357, 5985, 5986}   # Windows/PC寄り
DANGER_PORTS = {p for p, (_, role, _) in PORT_CATALOG.items() if role == "danger"}

DEFAULT_CONFIG = {"interval_min": 30, "port_timeout": 0.5, "ping_timeout_ms": 600,
                  "scan_workers": 200, "show_nonpc": False,
                  # メーカー名(小文字の部分一致) → そのメーカーでは通常の振る舞いとして開閉するポート。
                  # 危険度の判定から外し、開閉は「低」で記録だけ残す（2026-10-18 改修・議長承認）。
                  "benign_vendor_ports": {"amazon": [1080]}}


def benign_ports_for(vendor, cfg=None):
    """そのメーカーで既知の良性ポート集合を返す（設定の benign_vendor_ports による）。"""
    table = (cfg or DEFAULT_CONFIG).get("benign_vendor_ports") or {}
    low_v = (vendor or "").lower()
    out = set()
    for kw, ports in table.items():
        if kw and kw.lower() in low_v:
            out.update(int(p) for p in ports)
    return out


# ---------------------------------------------------------------------------
# OUI / MAC ユーティリティ（NetworkDeviceList 由来）
# ---------------------------------------------------------------------------
def ieee_count():
    return len(IEEE_DB.get("oui", {})) + len(IEEE_DB.get("long", {}))


def load_ieee_oui():
    global IEEE_DB
    try:
        with open(OUI_IEEE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and "oui" in data:
            IEEE_DB = {"oui": data.get("oui", {}), "long": data.get("long", {})}
        elif isinstance(data, dict):
            IEEE_DB = {"oui": data, "long": {}}
    except Exception:
        IEEE_DB = {"oui": {}, "long": {}}
    return ieee_count()


def load_user_oui():
    try:
        with open(OUI_USER_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        for k, v in data.items():
            key = normalize_oui(k)
            if key and isinstance(v, (list, tuple)) and len(v) >= 2:
                OUI_DB[key] = (str(v[0]), str(v[1]))
    except Exception:
        pass


def normalize_mac(mac):
    if not mac:
        return ""
    h = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(h) != 12:
        return ""
    h = h.lower()
    return "-".join(h[i:i + 2] for i in range(0, 12, 2))


def normalize_oui(s):
    h = re.sub(r"[^0-9a-fA-F]", "", s or "")
    if len(h) < 6:
        return ""
    h = h[:6].upper()
    return "-".join(h[i:i + 2] for i in range(0, 6, 2))


def mac_oui(mac):
    n = normalize_mac(mac)
    return n[:8].upper() if n else ""


def is_locally_administered(mac):
    n = normalize_mac(mac)
    if not n:
        return False
    try:
        return bool(int(n[:2], 16) & 0x02)
    except ValueError:
        return False


def is_multicast_or_broadcast(mac):
    n = normalize_mac(mac)
    if not n or n == "ff-ff-ff-ff-ff-ff":
        return True
    try:
        return bool(int(n[:2], 16) & 0x01)
    except ValueError:
        return True


def ieee_lookup(mac):
    n = normalize_mac(mac)
    if not n:
        return ""
    hex12 = n.replace("-", "").upper()
    long_map = IEEE_DB.get("long", {})
    for L in (9, 7):
        key = hex12[:L]
        if key in long_map:
            return long_map[key]
    oui = "-".join(hex12[i:i + 2] for i in range(0, 6, 2))
    return IEEE_DB.get("oui", {}).get(oui, "")


def guess_type_from_vendor(vendor):
    low = (vendor or "").lower()
    for kw, t in VENDOR_KEYWORD_TYPE:
        if kw in low:
            return t
    return ""


def vendor_and_type(mac):
    oui = mac_oui(mac)
    note = "ランダム化MACの可能性" if is_locally_administered(mac) else ""
    if oui in OUI_DB:
        v, t = OUI_DB[oui]
        if not t:
            t = guess_type_from_vendor(v)
        return v, t, note
    v = ieee_lookup(mac)
    if v:
        return v, guess_type_from_vendor(v), note
    return "(不明)", "", note


# ---------------------------------------------------------------------------
# サブプロセス
# ---------------------------------------------------------------------------
def _popen(args):
    si = None
    try:
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    except Exception:
        si = None
    return subprocess.Popen(
        args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL, startupinfo=si, creationflags=CREATE_NO_WINDOW,
    )


def run_ps(script, timeout=60):
    args = ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-Command",
            "[Console]::OutputEncoding=[Text.Encoding]::UTF8; $ProgressPreference='SilentlyContinue'; " + script]
    try:
        p = _popen(args)
        out, _ = p.communicate(timeout=timeout)
        return out.decode("utf-8", errors="replace")
    except Exception:
        try:
            p.kill()
        except Exception:
            pass
        return ""


# ---------------------------------------------------------------------------
# ネットワーク収集
# ---------------------------------------------------------------------------
def get_interfaces():
    script = (
        "$cfgs = Get-NetIPConfiguration | Where-Object { $_.IPv4Address -ne $null }; "
        "$out = foreach($c in $cfgs){ "
        "$ad = Get-NetAdapter -InterfaceIndex $c.InterfaceIndex -ErrorAction SilentlyContinue; "
        "[pscustomobject]@{ alias=$c.InterfaceAlias; index=$c.InterfaceIndex; "
        "ip=($c.IPv4Address.IPAddress | Select-Object -First 1); "
        "prefix=($c.IPv4Address.PrefixLength | Select-Object -First 1); "
        "gateway=($c.IPv4DefaultGateway.NextHop | Select-Object -First 1); "
        "mac=$ad.MacAddress } }; $out | ConvertTo-Json -Compress"
    )
    raw = run_ps(script, timeout=40).strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except Exception:
        return []
    if isinstance(data, dict):
        data = [data]
    result = []
    for d in data:
        ip = (d.get("ip") or "").strip()
        if not ip or ip.startswith("169.254."):
            continue
        try:
            prefix = int(d.get("prefix") or 24)
        except (TypeError, ValueError):
            prefix = 24
        result.append({"alias": d.get("alias") or "", "index": d.get("index"),
                       "ip": ip, "prefix": prefix,
                       "gateway": (d.get("gateway") or "").strip(),
                       "mac": normalize_mac(d.get("mac") or "")})
    result.sort(key=lambda x: (0 if x["gateway"] else 1, x["ip"]))
    return result


def enumerate_hosts(ip, prefix, max_hosts=2048):
    try:
        net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
    except Exception:
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
    hosts = list(net.hosts())
    if len(hosts) > max_hosts:
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
        hosts = list(net.hosts())
    return [str(h) for h in hosts]


def ping_ttl(ip, timeout_ms=600):
    """1回pingし (応答有無, TTL値 or None) を返す。TTLはOS推定に使う。"""
    try:
        p = _popen(["ping", "-n", "1", "-w", str(timeout_ms), ip])
        out, _ = p.communicate(timeout=(timeout_ms / 1000.0) + 2.0)
    except Exception:
        return False, None
    text = out.upper()
    if b"TTL=" not in text:
        return False, None
    m = re.search(rb"TTL=(\d+)", text)
    ttl = int(m.group(1)) if m else None
    return True, ttl


def read_arp_table():
    result = {}
    try:
        p = _popen(["arp", "-a"])
        out, _ = p.communicate(timeout=15)
    except Exception:
        return result
    text = out.decode("cp932", errors="ignore")
    ip_re = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
    mac_re = re.compile(r"([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})")
    for line in text.splitlines():
        ipm = ip_re.search(line)
        macm = mac_re.search(line)
        if not ipm or not macm:
            continue
        mac = normalize_mac(macm.group(1))
        if not mac or is_multicast_or_broadcast(mac):
            continue
        ip = ipm.group(1)
        try:
            ipobj = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if ipobj.is_multicast or ip.endswith(".255") or ip.endswith(".0"):
            continue
        result[ip] = mac
    return result


def resolve_hostname(ip):
    try:
        socket.setdefaulttimeout(1.2)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def scan_ports(ip, ports, timeout=0.5):
    """TCP connect スキャン。開いているポート番号の集合を返す。"""
    open_ports = set()
    lock = threading.Lock()

    def probe(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            rc = s.connect_ex((ip, port))
            s.close()
            if rc == 0:
                with lock:
                    open_ports.add(port)
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=min(len(ports), 40)) as ex:
        list(ex.map(probe, ports))
    return sorted(open_ports)


# ---------------------------------------------------------------------------
# PC判定
# ---------------------------------------------------------------------------
def classify_pc(vendor, dtype, host, ports, ttl):
    """(判定ラベル, スコア, 理由リスト) を返す。
    判定: 'PC濃厚' / 'PCの可能性' / '非PC(機器)' / '判定不能'"""
    score, reasons = 0, []
    pset = set(ports)
    low_v = (vendor or "").lower()
    low_t = (dtype or "").lower()
    low_h = (host or "").lower()

    if pset & {135, 139, 445}:
        score += 3
        reasons.append("Windows共有(135/139/445)")
    if 3389 in pset:
        score += 2
        reasons.append("RDP(3389)")
    if pset & {5985, 5986, 5357}:
        score += 1
        reasons.append("WinRM/WSD")
    if ttl is not None:
        if 110 <= ttl <= 128:
            score += 2
            reasons.append(f"TTL≒128 (Windows系, 実測{ttl})")
        elif 50 <= ttl <= 64:
            reasons.append(f"TTL≒64 (Linux/Mac/IoT系, 実測{ttl})")
    if any(kw in low_v for kw in PC_VENDOR_KW):
        score += 2
        reasons.append("PC向けNICメーカー")
    if any(kw in low_h for kw in ("desktop-", "laptop-", "-pc", "pc-", "win")):
        score += 1
        reasons.append("PCらしいホスト名")

    nonpc = any(kw in low_t for kw in NONPC_TYPE_KW)
    if nonpc:
        reasons.append(f"種別=非PC寄り({dtype})")

    if score >= 4:
        return "PC濃厚", score, reasons
    if score >= 2 and not (nonpc and score < 3):
        return "PCの可能性", score, reasons
    if nonpc and score < 2:
        return "非PC(機器)", score, reasons
    if "apple" in low_v:
        return "判定不能", score, reasons + ["Apple=Mac(PC)かiPhone/iPad(非PC)か外形からは不明"]
    return "判定不能", score, reasons


def device_danger(ports, ignore=()):
    """開放ポート集合から最大危険度と危険ポート名リストを返す。
    ignore＝そのメーカーで既知の良性ポート（危険度に数えない）。"""
    dports = sorted((set(ports) & DANGER_PORTS) - set(ignore))
    plain = [p for p in ports if PORT_CATALOG.get(p, ("", "", False))[2]]
    names = [f"{p}:{PORT_CATALOG[p][0]}" for p in dports]
    if dports:
        return "高", names
    if plain:
        return "中", [f"{p}:{PORT_CATALOG.get(p, ('?',))[0]}(平文)" for p in plain]
    return "-", []


def ports_label(ports):
    if not ports:
        return "(開放なし)"
    return " ".join(f"{p}/{PORT_CATALOG.get(p, ('?',))[0]}" for p in ports)


# ---------------------------------------------------------------------------
# スキャン本体
# ---------------------------------------------------------------------------
class Scanner:
    def __init__(self, cfg, progress_cb=None, log_cb=None):
        self.cfg = cfg
        self.progress_cb = progress_cb or (lambda d, t, m: None)
        self.log_cb = log_cb or (lambda m: None)
        self.cancel = False

    def scan(self, ip, prefix):
        hosts = enumerate_hosts(ip, prefix)
        total = len(hosts)
        self.log_cb(f"対象 {total} アドレスに応答確認(ping)中…")
        alive, ttl_map = {}, {}
        done = [0]
        lock = threading.Lock()

        def worker(h):
            if self.cancel:
                return
            ok, ttl = ping_ttl(h, self.cfg["ping_timeout_ms"])
            with lock:
                done[0] += 1
                if ok:
                    alive[h] = True
                    ttl_map[h] = ttl
                self.progress_cb(done[0], total, f"ping {done[0]}/{total}（応答 {len(alive)}）")

        with ThreadPoolExecutor(max_workers=64) as ex:
            list(ex.map(worker, hosts))
        if self.cancel:
            return []

        self.log_cb("ARPテーブルを読取り中…")
        arp = read_arp_table()
        try:
            net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        except Exception:
            net = None

        targets = set(alive.keys())
        for aip in arp.keys():
            if net is not None:
                try:
                    if ipaddress.ip_address(aip) in net:
                        targets.add(aip)
                except ValueError:
                    pass
        targets = sorted(targets, key=lambda x: tuple(int(o) for o in x.split(".")))

        # ポートスキャン（対象ホストのみ・厳選ポート）
        self.log_cb(f"{len(targets)} 台の外形ポートを確認中…（自作の足音に注意）")
        devices = []
        pdone = [0]
        ptotal = len(targets)

        def port_worker(dip):
            if self.cancel:
                return None
            ports = scan_ports(dip, SCAN_PORTS, self.cfg["port_timeout"])
            with lock:
                pdone[0] += 1
                self.progress_cb(pdone[0], ptotal, f"ポート確認 {pdone[0]}/{ptotal}: {dip}")
            return dip, ports

        results = {}
        with ThreadPoolExecutor(max_workers=max(8, self.cfg["scan_workers"] // len(SCAN_PORTS) + 4)) as ex:
            for r in ex.map(port_worker, targets):
                if r:
                    results[r[0]] = r[1]
        if self.cancel:
            return []

        self.log_cb("ホスト名を解決中…")
        for dip in targets:
            mac = arp.get(dip, "")
            vendor, dtype, note = vendor_and_type(mac) if mac else ("(MAC未取得)", "", "")
            host = resolve_hostname(dip)
            ports = results.get(dip, [])
            ttl = ttl_map.get(dip)
            verdict, score, reasons = classify_pc(vendor, dtype, host, ports, ttl)
            benign = benign_ports_for(vendor, self.cfg)
            danger, dnames = device_danger(ports, benign)
            devices.append({
                "ip": dip, "mac": mac, "host": host, "vendor": vendor, "type": dtype,
                "note": note, "ports": ports, "ttl": ttl, "verdict": verdict,
                "score": score, "reasons": reasons, "danger": danger, "danger_ports": dnames,
                "alive": dip in alive,
                "benign_ports": sorted(set(ports) & benign),
            })

        self.log_cb(f"完了：{len(devices)} 台を確認（うちPC濃厚/可能性 "
                    f"{sum(1 for d in devices if d['verdict'].startswith('PC'))} 台）。")
        return devices


# ---------------------------------------------------------------------------
# ベースライン / 差分（不正アクセスの兆候検知の中核）
# ---------------------------------------------------------------------------
def _dev_key(d):
    return d.get("mac") or ("ip:" + d.get("ip", ""))


def load_baseline():
    try:
        with open(BASELINE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_baseline(devices):
    base = {}
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for d in devices:
        base[_dev_key(d)] = {
            "ip": d["ip"], "mac": d["mac"], "host": d["host"], "vendor": d["vendor"],
            "verdict": d["verdict"], "ports": d["ports"], "ttl": d["ttl"],
            "alive": d.get("alive", True),
            "approved": stamp,
        }
    try:
        with open(BASELINE_FILE, "w", encoding="utf-8") as f:
            json.dump(base, f, ensure_ascii=False, indent=1)
        return True
    except Exception:
        return False


def _prev_alive(prev):
    """ベースライン側の機器が、その時ping応答していたか。
    2026-10-18 より前の基準には alive が無い → TTL が取れていれば応答あり、と読む。"""
    if "alive" in prev:
        return bool(prev["alive"])
    return prev.get("ttl") is not None


def diff_baseline(baseline, devices):
    """ベースラインと現在を比較しアラート配列を返す。
    alert = {level:高/中/低, key, ip, host, kind, detail}
    ★2026-10-18 改修：
      ・今回ping応答なし（ARP表＝住所録だけで載った）機器は、新規/ポート変化の判定に使わない
      ・前回応答なし（＝前回は測れていない）機器のポート差分は「初回の観測(低)」として扱う
      ・メーカーで既知の良性ポート（benign_ports）の開閉は「低」で記録だけ"""
    alerts = []
    seen = set()
    for d in devices:
        key = _dev_key(d)
        label = d["host"] or d["ip"]
        prev = baseline.get(key)
        if not d.get("alive", True):
            # 住所録だけで載った＝今は電源断/離脱の可能性。存在の証拠にしない。
            # seen に入れない → 基準で応答していたPCなら下の「消失」で拾う。
            continue
        seen.add(key)
        if prev is None:
            # 新規機器。PCなら注目度UP、危険ポートありなら高。
            if d["verdict"].startswith("PC"):
                lvl = "高" if d["danger"] == "高" else "中"
                alerts.append({"level": lvl, "key": key, "ip": d["ip"], "host": label,
                               "kind": "新規PC出現",
                               "detail": f"{d['verdict']} / {d['vendor']} / 開放:{ports_label(d['ports'])}"})
            elif d["danger"] == "高":
                alerts.append({"level": "中", "key": key, "ip": d["ip"], "host": label,
                               "kind": "新規機器(危険ポート有)",
                               "detail": f"{d['vendor']} / 危険:{', '.join(d['danger_ports'])}"})
            continue
        # 既知機器：ポート差分
        cur = set(d["ports"])
        old = set(prev.get("ports", []))
        benign = set(d.get("benign_ports", [])) | (benign_ports_for(d.get("vendor", "")) & (cur | old))
        if not _prev_alive(prev):
            # 前回は応答が無く測れていない＝差分は「新しく開いた」とは言えない
            if cur:
                alerts.append({"level": "低", "key": key, "ip": d["ip"], "host": label,
                               "kind": "初回の観測(前回は応答なし)",
                               "detail": f"開放:{ports_label(sorted(cur))}"})
            closed = []
            newly = []
        else:
            newly = sorted(cur - old)
            closed = sorted(old - cur)
        for p in newly:
            nm = PORT_CATALOG.get(p, ("?", "watch", False))
            if p in benign:
                alerts.append({"level": "低", "key": key, "ip": d["ip"], "host": label,
                               "kind": "ポート開閉(既知の振る舞い)",
                               "detail": f"{p}/{nm[0]} 開（このメーカーでは通常）"})
                continue
            lvl = "高" if p in DANGER_PORTS else ("中" if nm[2] else "低")
            alerts.append({"level": lvl, "key": key, "ip": d["ip"], "host": label,
                           "kind": "ポート新規開放",
                           "detail": f"{p}/{nm[0]}" + ("（危険）" if p in DANGER_PORTS else
                                     ("（平文）" if nm[2] else ""))})
        for p in closed:
            nm = PORT_CATALOG.get(p, ("?",))[0]
            alerts.append({"level": "低", "key": key, "ip": d["ip"], "host": label,
                           "kind": "ポート閉鎖", "detail": f"{p}/{nm}"})
        # IP移動（同一MACが別IP）
        if prev.get("ip") and prev["ip"] != d["ip"] and d["mac"]:
            alerts.append({"level": "中", "key": key, "ip": d["ip"], "host": label,
                           "kind": "IP移動",
                           "detail": f"{prev['ip']} → {d['ip']}（DHCP更新なら良性）"})
        # ホスト名変化
        if prev.get("host") and d["host"] and prev["host"] != d["host"]:
            alerts.append({"level": "低", "key": key, "ip": d["ip"], "host": label,
                           "kind": "ホスト名変化", "detail": f"{prev['host']} → {d['host']}"})
    # 消失（ベースラインにあり今回無し）
    for key, prev in baseline.items():
        if key in seen:
            continue
        if not _prev_alive(prev):
            continue  # 前回も応答なし＝「消えた」とは言えない
        if str(prev.get("verdict", "")).startswith("PC"):
            alerts.append({"level": "低", "key": key, "ip": prev.get("ip", ""),
                           "host": prev.get("host") or prev.get("ip", ""),
                           "kind": "PC消失(応答なし)",
                           "detail": f"前回:{prev.get('vendor', '')} / {ports_label(prev.get('ports', []))}"})
    order = {"高": 0, "中": 1, "低": 2}
    alerts.sort(key=lambda a: order.get(a["level"], 3))
    return alerts


def append_alerts_log(alerts):
    if not alerts:
        return
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    new = not os.path.exists(ALERTS_LOG)
    try:
        with open(ALERTS_LOG, "a", encoding="utf-8-sig", newline="") as f:
            w = csv.writer(f)
            if new:
                w.writerow(["日時", "重大度", "種類", "IP", "ホスト/機器", "詳細"])
            for a in alerts:
                w.writerow([stamp, a["level"], a["kind"], a["ip"], a["host"], a["detail"]])
    except Exception:
        pass


def save_history(devices, alerts):
    os.makedirs(HIST_DIR, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(HIST_DIR, f"scan_{stamp}.json")
    slim = [{"ip": d["ip"], "mac": d["mac"], "host": d["host"], "vendor": d["vendor"],
             "verdict": d["verdict"], "ports": d["ports"], "danger": d["danger"],
             "alive": d.get("alive", True), "ttl": d.get("ttl"),
             "benign_ports": d.get("benign_ports", [])}
            for d in devices]
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"time": stamp, "alerts": alerts, "devices": slim}, f,
                      ensure_ascii=False, indent=1)
    except Exception:
        pass
    try:
        snaps = sorted(os.path.join(HIST_DIR, n) for n in os.listdir(HIST_DIR)
                       if n.startswith("scan_") and n.endswith(".json"))
        for old in snaps[:-30]:
            try:
                os.remove(old)
            except Exception:
                pass
    except Exception:
        pass


# ---------------------------------------------------------------------------
# 設定
# ---------------------------------------------------------------------------
def load_config():
    cfg = dict(DEFAULT_CONFIG)
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            cfg.update(json.load(f))
    except Exception:
        pass
    return cfg


def save_config(cfg):
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# HTML / CSV 出力
# ---------------------------------------------------------------------------
CSV_HEADER = ["判定", "IPアドレス", "MACアドレス", "ホスト名", "メーカー", "開放ポート", "危険度", "危険ポート", "TTL"]


def export_csv(path, rows):
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(CSV_HEADER)
        for r in rows:
            w.writerow([r["verdict"], r["ip"], r["mac"], r["host"], r["vendor"],
                        ports_label(r["ports"]), r["danger"], ", ".join(r["danger_ports"]),
                        r["ttl"] if r["ttl"] is not None else ""])


def export_html(path, rows, alerts, meta):
    def td(s, cls=""):
        c = f' class="{cls}"' if cls else ""
        return f"<td{c}>{html.escape(str(s))}</td>"

    pc_rows = [r for r in rows if r["verdict"].startswith("PC")]
    body = []
    for r in rows:
        cls = ""
        if r["danger"] == "高":
            cls = "danger"
        elif r["verdict"] == "PC濃厚":
            cls = "pcs"
        elif r["verdict"] == "PCの可能性":
            cls = "pcm"
        body.append(f"<tr class='{cls}'>" + td(r["verdict"]) + td(r["ip"]) + td(r["mac"])
                    + td(r["host"]) + td(r["vendor"]) + td(ports_label(r["ports"]))
                    + td(r["danger"]) + td(", ".join(r["danger_ports"])) + "</tr>")

    alert_rows = []
    for a in alerts:
        alert_rows.append(f"<tr class='a{a['level']}'>" + td(a["level"]) + td(a["kind"])
                          + td(a["ip"]) + td(a["host"]) + td(a["detail"]) + "</tr>")
    alerts_html = ("".join(alert_rows) if alert_rows
                   else "<tr><td colspan='5'>今回のスキャンでは前回との差分（兆候）は検出されませんでした。</td></tr>")

    doc = f"""<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8">
<title>{html.escape(APP_TITLE)} レポート</title><style>
 body{{font-family:"Segoe UI","Meiryo",sans-serif;margin:0;background:#f1f5f9;color:#0f172a;}}
 .hd{{background:linear-gradient(90deg,#7f1d1d,#b91c1c,#ea580c);color:#fff;padding:22px 28px;}}
 .hd h1{{margin:0;font-size:22px;}} .hd .sub{{opacity:.92;font-size:13px;margin-top:6px;}}
 .wrap{{padding:20px 28px;}}
 .cards{{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:18px;}}
 .card{{background:#fff;border-radius:10px;padding:14px 18px;box-shadow:0 1px 3px rgba(0,0,0,.1);min-width:120px;}}
 .card .n{{font-size:26px;font-weight:bold;color:#b91c1c;}} .card .l{{font-size:12px;color:#64748b;}}
 table{{border-collapse:collapse;width:100%;background:#fff;border-radius:8px;overflow:hidden;font-size:13px;margin-bottom:20px;}}
 th{{background:#7f1d1d;color:#fff;padding:8px 10px;text-align:left;}}
 td{{padding:6px 10px;border-bottom:1px solid #e2e8f0;}}
 tr.danger td{{background:#fee2e2 !important;}} tr.pcs td{{background:#dbeafe;}} tr.pcm td{{background:#eff6ff;}}
 tr.a高 td{{background:#fecaca;font-weight:bold;}} tr.a中 td{{background:#fef3c7;}} tr.a低 td{{background:#f1f5f9;}}
 .panel h2{{font-size:15px;color:#334155;margin:18px 0 8px;}}
 .note{{background:#fff7ed;border-left:4px solid #ea580c;padding:10px 14px;font-size:12px;color:#7c2d12;border-radius:0 8px 8px 0;margin-bottom:16px;}}
 .foot{{color:#94a3b8;font-size:11px;margin:20px 28px;}}
</style></head><body>
<div class="hd"><h1>🛡 {html.escape(APP_TITLE)}</h1><div class="sub">{html.escape(APP_SUBTITLE)}</div></div>
<div class="wrap">
 <div class="note">⚠ このレポートが示すのは「外から見える変化＝不正アクセスの<b>兆候</b>」であり、侵入そのものの確証ではありません。
   本当に乗っ取られたかはPC内部（ログイン履歴・イベントログ・プロセス）の確認が必要です。</div>
 <div class="cards">
  <div class="card"><div class="n">{len(pc_rows)}</div><div class="l">PC濃厚/可能性</div></div>
  <div class="card"><div class="n">{len(rows)}</div><div class="l">確認機器 合計</div></div>
  <div class="card"><div class="n">{sum(1 for r in rows if r['danger']=='高')}</div><div class="l">危険ポート露出</div></div>
  <div class="card"><div class="n">{len(alerts)}</div><div class="l">今回の兆候(差分)</div></div>
 </div>
 <div class="panel"><h2>🚨 兆候（前回ベースラインとの差分）</h2>
 <table><thead><tr><th>重大度</th><th>種類</th><th>IP</th><th>ホスト/機器</th><th>詳細</th></tr></thead>
 <tbody>{alerts_html}</tbody></table></div>
 <div class="panel"><h2>🖥 機器一覧（外形）</h2>
 <table><thead><tr>{''.join(f'<th>{html.escape(h)}</th>' for h in ['判定','IP','MAC','ホスト名','メーカー','開放ポート','危険度','危険ポート'])}</tr></thead>
 <tbody>{''.join(body)}</tbody></table></div>
</div>
<div class="foot">{html.escape(APP_TITLE)} v{VERSION} / 生成 {html.escape(meta.get('generated',''))}
 / 読み取り寄り(TCP connectスキャンのみ) / このPCから見える範囲に基づく</div>
</body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------
class GradientHeader(tk.Canvas):
    def __init__(self, master, height=64, **kw):
        super().__init__(master, height=height, highlightthickness=0, bd=0, **kw)
        self.bind("<Configure>", self._draw)

    @staticmethod
    def _lerp(c1, c2, t):
        a = tuple(int(c1[i:i + 2], 16) for i in (1, 3, 5))
        b = tuple(int(c2[i:i + 2], 16) for i in (1, 3, 5))
        r = tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))
        return f"#{r[0]:02x}{r[1]:02x}{r[2]:02x}"

    def _draw(self, _=None):
        self.delete("all")
        w, h = self.winfo_width(), self.winfo_height()
        if w <= 1:
            return
        mid = w // 2
        for x in range(w):
            if x < mid:
                col = self._lerp(PALETTE["grad_a"], PALETTE["grad_b"], x / max(mid, 1))
            else:
                col = self._lerp(PALETTE["grad_b"], PALETTE["grad_c"], (x - mid) / max(w - mid, 1))
            self.create_line(x, 0, x, h, fill=col)
        self.create_text(18, h // 2 - 8, anchor="w", text=f"🛡 {APP_TITLE}",
                         fill="#ffffff", font=("Meiryo", 15, "bold"))
        self.create_text(20, h // 2 + 12, anchor="w", text=APP_SUBTITLE,
                         fill="#fee2e2", font=("Meiryo", 8))
        self.create_text(w - 14, h // 2, anchor="e",
                         text=f"v{VERSION}  管理者権限不要 / TCP connectのみ",
                         fill="#fed7aa", font=("Meiryo", 9))


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_TITLE}  v{VERSION}")
        self.geometry("1180x760")
        self.configure(bg=PALETTE["bg"])
        self.minsize(1000, 620)

        self.cfg = load_config()
        self.devices = []
        self.interfaces = []
        self.alerts = []
        self.scanning = False
        self.monitoring = False
        self.scanner = None
        self._stop_evt = threading.Event()

        load_ieee_oui()
        load_user_oui()
        self._build_style()
        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(300, self._detect_interfaces)

    def _build_style(self):
        st = ttk.Style(self)
        try:
            st.theme_use("clam")
        except Exception:
            pass
        st.configure("Treeview", rowheight=24, font=("Meiryo", 9),
                     background="#ffffff", fieldbackground="#ffffff")
        st.configure("Treeview.Heading", background=PALETTE["head_bg"],
                     foreground=PALETTE["head_fg"], font=("Meiryo", 9, "bold"))
        for name, color in [
            ("Scan.TButton", PALETTE["btn_scan"]), ("Mon.TButton", PALETTE["btn_mon"]),
            ("Stop.TButton", PALETTE["btn_stop"]), ("Csv.TButton", PALETTE["btn_csv"]),
            ("Html.TButton", PALETTE["btn_html"]), ("Base.TButton", PALETTE["btn_base"]),
            ("Detail.TButton", PALETTE["btn_detail"]),
        ]:
            st.configure(name, foreground="#fff", background=color,
                         font=("Meiryo", 9, "bold"), padding=(10, 6), borderwidth=0)
            st.map(name, background=[("active", color), ("disabled", "#94a3b8")])

    def _build_ui(self):
        GradientHeader(self).pack(fill="x")

        bar = tk.Frame(self, bg=PALETTE["panel"])
        bar.pack(fill="x")
        inner = tk.Frame(bar, bg=PALETTE["panel"])
        inner.pack(fill="x", padx=10, pady=8)

        tk.Label(inner, text="対象サブネット:", bg=PALETTE["panel"],
                 font=("Meiryo", 9)).pack(side="left")
        self.subnet_var = tk.StringVar()
        self.subnet_combo = ttk.Combobox(inner, textvariable=self.subnet_var, width=22,
                                          state="readonly")
        self.subnet_combo.pack(side="left", padx=(4, 10))

        tk.Label(inner, text="間隔(分):", bg=PALETTE["panel"], font=("Meiryo", 9)).pack(side="left")
        self.interval_var = tk.StringVar(value=str(self.cfg["interval_min"]))
        ttk.Spinbox(inner, from_=1, to=1440, width=5, textvariable=self.interval_var).pack(side="left", padx=(2, 10))

        self.scan_btn = ttk.Button(inner, text="▶ 今すぐ1回", style="Scan.TButton", command=self.scan_once)
        self.scan_btn.pack(side="left", padx=3)
        self.mon_btn = ttk.Button(inner, text="🔁 定期監視 開始", style="Mon.TButton", command=self.toggle_monitor)
        self.mon_btn.pack(side="left", padx=3)
        ttk.Button(inner, text="✔ ベースライン更新", style="Base.TButton", command=self.update_baseline).pack(side="left", padx=3)
        ttk.Button(inner, text="📄 CSV", style="Csv.TButton", command=self.export_csv_dialog).pack(side="left", padx=3)
        ttk.Button(inner, text="🌐 HTML", style="Html.TButton", command=self.export_html_dialog).pack(side="left", padx=3)
        ttk.Button(inner, text="🔍 詳細", style="Detail.TButton", command=self.show_detail).pack(side="left", padx=3)

        opt = tk.Frame(self, bg=PALETTE["bg"])
        opt.pack(fill="x", padx=10, pady=(6, 0))
        self.shownonpc_var = tk.BooleanVar(value=self.cfg["show_nonpc"])
        tk.Checkbutton(opt, text="PC以外の機器も表示", variable=self.shownonpc_var,
                       bg=PALETTE["bg"], font=("Meiryo", 8),
                       command=self._refresh_table).pack(side="left")
        tk.Label(opt, text="絞り込み:", bg=PALETTE["bg"], font=("Meiryo", 9)).pack(side="left", padx=(14, 2))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._refresh_table())
        tk.Entry(opt, textvariable=self.search_var, width=32, font=("Meiryo", 9)).pack(side="left")
        self.count_lbl = tk.Label(opt, text="", bg=PALETTE["bg"], fg="#475569", font=("Meiryo", 9))
        self.count_lbl.pack(side="right")

        self.info_lbl = tk.Label(self, text="インターフェースを検出中…", bg=PALETTE["info_bg"],
                                 fg="#7f1d1d", font=("Meiryo", 9), anchor="w", padx=10, justify="left")
        self.info_lbl.pack(fill="x", padx=10, pady=(6, 6))

        # 上下分割：機器一覧 / 兆候アラート
        paned = tk.PanedWindow(self, orient="vertical", bg=PALETTE["bg"], sashwidth=6)
        paned.pack(fill="both", expand=True, padx=10, pady=(0, 6))

        tblwrap = tk.Frame(paned, bg=PALETTE["bg"])
        cols = ("verdict", "ip", "mac", "host", "vendor", "ports", "danger")
        headers = {"verdict": ("判定", 90), "ip": ("IP", 115), "mac": ("MAC", 140),
                   "host": ("ホスト名", 150), "vendor": ("メーカー", 190),
                   "ports": ("開放ポート", 300), "danger": ("危険度", 60)}
        self.tree = ttk.Treeview(tblwrap, columns=cols, show="headings", selectmode="browse")
        for c in cols:
            txt, w = headers[c]
            self.tree.heading(c, text=txt, command=lambda cc=c: self._sort_by(cc))
            self.tree.column(c, width=w, anchor=("center" if c in ("verdict", "danger") else "w"),
                             stretch=(c in ("ports", "vendor")))
        ysb = ttk.Scrollbar(tblwrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=ysb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        ysb.grid(row=0, column=1, sticky="ns")
        tblwrap.rowconfigure(0, weight=1)
        tblwrap.columnconfigure(0, weight=1)
        self.tree.bind("<Double-1>", lambda e: self.show_detail())
        self.tree.tag_configure("pcs", background=PALETTE["pc_strong"])
        self.tree.tag_configure("pcm", background=PALETTE["pc_maybe"])
        self.tree.tag_configure("danger", background=PALETTE["danger"])
        self.tree.tag_configure("self", background=PALETTE["self"])
        self.tree.tag_configure("nonpc", foreground="#94a3b8")
        # 2026-10-18：ping応答なし（ARP表＝住所録だけで載った）機器
        self.tree.tag_configure("offline", foreground="#9ca3af", background="#f3f4f6")
        paned.add(tblwrap, minsize=200)

        alertwrap = tk.Frame(paned, bg=PALETTE["bg"])
        tk.Label(alertwrap, text="🚨 兆候（前回ベースラインとの差分）", bg=PALETTE["bg"],
                 fg="#7f1d1d", font=("Meiryo", 10, "bold"), anchor="w").pack(fill="x")
        acols = ("level", "kind", "ip", "host", "detail")
        aheaders = {"level": ("重大度", 60), "kind": ("種類", 150), "ip": ("IP", 115),
                    "host": ("ホスト/機器", 150), "detail": ("詳細", 420)}
        self.atree = ttk.Treeview(alertwrap, columns=acols, show="headings", height=6, selectmode="browse")
        for c in acols:
            txt, w = aheaders[c]
            self.atree.heading(c, text=txt)
            self.atree.column(c, width=w, anchor=("center" if c == "level" else "w"),
                              stretch=(c == "detail"))
        aysb = ttk.Scrollbar(alertwrap, orient="vertical", command=self.atree.yview)
        self.atree.configure(yscrollcommand=aysb.set)
        self.atree.pack(side="left", fill="both", expand=True)
        aysb.pack(side="right", fill="y")
        self.atree.tag_configure("高", background="#fecaca", foreground="#7f1d1d")
        self.atree.tag_configure("中", background="#fef3c7")
        self.atree.tag_configure("低", background="#f1f5f9", foreground="#64748b")
        paned.add(alertwrap, minsize=140)

        self.prog = ttk.Progressbar(self, mode="determinate")
        self.prog.pack(fill="x", padx=10, pady=(0, 4))
        self.status = tk.Label(self, text="準備完了", bg=PALETTE["status_bg"],
                               fg=PALETTE["status_fg"], anchor="w", padx=10, font=("Meiryo", 9))
        self.status.pack(fill="x")

    # -- インターフェース ---------------------------------------------------
    def _detect_interfaces(self):
        def work():
            ifs = get_interfaces()
            self.after(0, lambda: self._on_interfaces(ifs))
        threading.Thread(target=work, daemon=True).start()

    def _on_interfaces(self, ifs):
        self.interfaces = ifs
        if not ifs:
            self.info_lbl.config(text="⚠ 有効なネットワークインターフェースを検出できませんでした。")
            return
        values = []
        for itf in ifs:
            net = ipaddress.ip_network(f"{itf['ip']}/{itf['prefix']}", strict=False)
            values.append(f"{net.with_prefixlen}  [{itf['alias']}]  自分={itf['ip']}")
        self.subnet_combo["values"] = values
        self.subnet_combo.current(0)
        p = ifs[0]
        base = load_baseline()
        bhint = (f"ベースライン: {len(base)}機器 登録済" if base
                 else "ベースライン未作成（初回スキャンで自動作成→以降その差分を兆候として警告）")
        self.info_lbl.config(
            text=f"このPC {p['ip']} / ルーター {p.get('gateway') or '?'} ｜ {bhint}\n"
                 f"⚠ このツールは各PCへTCP接続(ポート確認)します＝WiresharkAnalyzer/ルーターIPSに"
                 f"『スキャン』として映ることがあります（自作の足音・厳選{len(SCAN_PORTS)}ポートのみ）。")
        self.status.config(text=f"{len(ifs)} インターフェース検出。")

    def _selected_interface(self):
        idx = self.subnet_combo.current()
        if idx < 0 or idx >= len(self.interfaces):
            return self.interfaces[0] if self.interfaces else None
        return self.interfaces[idx]

    def _sync_cfg(self):
        try:
            self.cfg["interval_min"] = max(1, int(self.interval_var.get()))
        except ValueError:
            self.cfg["interval_min"] = 30
        self.cfg["show_nonpc"] = self.shownonpc_var.get()
        save_config(self.cfg)

    # -- スキャン実行 -------------------------------------------------------
    def scan_once(self):
        if self.scanning:
            return
        self._run_scan(loop=False)

    def toggle_monitor(self):
        if self.monitoring:
            self.monitoring = False
            self._stop_evt.set()
            self.mon_btn.config(text="🔁 定期監視 開始", style="Mon.TButton")
            self.status.config(text="定期監視を停止しました。")
            return
        self._sync_cfg()
        self.monitoring = True
        self._stop_evt.clear()
        self.mon_btn.config(text="■ 監視停止", style="Stop.TButton")
        self._run_scan(loop=True)

    def _run_scan(self, loop):
        itf = self._selected_interface()
        if not itf:
            messagebox.showwarning(APP_TITLE, "対象インターフェースがありません。")
            self.monitoring = False
            return
        self._sync_cfg()
        self.scanning = True
        self.scan_btn.config(text="● 実行中…")
        self.scanner = Scanner(self.cfg, progress_cb=self._progress, log_cb=self._log)

        def work():
            try:
                devices = self.scanner.scan(itf["ip"], itf["prefix"])
            except Exception as e:
                self.after(0, lambda: self._scan_error(str(e)))
                return
            self.after(0, lambda: self._scan_done(devices, itf, loop))

        threading.Thread(target=work, daemon=True).start()

    def _progress(self, done, total, msg):
        self.after(0, lambda: (self.prog.config(maximum=max(total, 1), value=done),
                               self.status.config(text=msg)))

    def _log(self, msg):
        self.after(0, lambda: self.status.config(text=msg))

    def _scan_error(self, msg):
        self.scanning = False
        self.scan_btn.config(text="▶ 今すぐ1回")
        messagebox.showerror(APP_TITLE, f"スキャン中にエラー:\n{msg}")
        if self.monitoring:
            self._schedule_next()

    def _scan_done(self, devices, itf, loop):
        self.scanning = False
        self.scan_btn.config(text="▶ 今すぐ1回")
        self.prog.config(value=0)

        my_ip, my_mac = itf["ip"], itf["mac"]
        for d in devices:
            if d["ip"] == my_ip or (my_mac and d["mac"] == my_mac):
                d["is_self"] = True
                if not d["verdict"].startswith("PC"):
                    d["verdict"] = "PC濃厚"
            else:
                d["is_self"] = False

        baseline = load_baseline()
        if not baseline:
            save_baseline(devices)
            self.alerts = []
            first = True
        else:
            self.alerts = diff_baseline(baseline, devices)
            append_alerts_log(self.alerts)
            first = False
        save_history(devices, self.alerts)

        self.devices = devices
        self._refresh_table()
        self._refresh_alerts()

        hi = sum(1 for a in self.alerts if a["level"] == "高")
        stamp = datetime.now().strftime("%H:%M:%S")
        if first:
            self.status.config(text=f"[{stamp}] 初回スキャン完了。ベースラインを作成しました"
                                    f"（{len(devices)}機器）。以降この状態からの変化を兆候として警告します。")
        else:
            self.status.config(text=f"[{stamp}] 完了。兆候 {len(self.alerts)}件"
                                    f"（うち高 {hi}件）。次回まで待機。" if self.monitoring
                               else f"[{stamp}] 完了。兆候 {len(self.alerts)}件（うち高 {hi}件）。")
        if hi and not first:
            self._notify_high()

        if self.monitoring and loop:
            self._schedule_next()

    def _schedule_next(self):
        if not self.monitoring:
            return
        ms = self.cfg["interval_min"] * 60 * 1000
        nxt = datetime.fromtimestamp(time.time() + self.cfg["interval_min"] * 60).strftime("%H:%M")
        cur = self.status.cget("text")
        self.status.config(text=f"{cur}  → 次回 {nxt}")
        self._next_job = self.after(ms, lambda: self._run_scan(loop=True) if self.monitoring else None)

    def _notify_high(self):
        highs = [a for a in self.alerts if a["level"] == "高"]
        msg = "\n".join(f"・[{a['kind']}] {a['host']} ({a['ip']}): {a['detail']}" for a in highs[:8])
        messagebox.showwarning(f"{APP_TITLE} — 高リスクの兆候 {len(highs)}件",
                               "外形に危険な変化を検知しました（＝侵入の兆候。確証はPC内部要確認）:\n\n"
                               + msg + "\n\n※ DHCPやメンテで正当な変化のこともあります。詳細を確認してください。")

    # -- 表示更新 -----------------------------------------------------------
    def _visible_devices(self):
        q = self.search_var.get().strip().lower()
        show_nonpc = self.shownonpc_var.get()
        out = []
        for d in self.devices:
            if not show_nonpc and not d["verdict"].startswith("PC") and not d.get("is_self"):
                continue
            if q:
                blob = f"{d['ip']} {d['mac']} {d['host']} {d['vendor']} {ports_label(d['ports'])} {d['verdict']}".lower()
                if q not in blob:
                    continue
            out.append(d)
        return out

    def _refresh_table(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        rows = self._visible_devices()
        for d in rows:
            tag = ""
            offline = not d.get("alive", True)
            if d.get("is_self"):
                tag = "self"
            elif offline:
                tag = "offline"
            elif d["danger"] == "高":
                tag = "danger"
            elif d["verdict"] == "PC濃厚":
                tag = "pcs"
            elif d["verdict"] == "PCの可能性":
                tag = "pcm"
            elif not d["verdict"].startswith("PC"):
                tag = "nonpc"
            self.tree.insert("", "end", values=(
                d["verdict"] + ("(このPC)" if d.get("is_self") else "")
                + ("（応答なし・住所録のみ）" if offline and not d.get("is_self") else ""),
                d["ip"], d["mac"],
                d["host"], d["vendor"], ports_label(d["ports"]), d["danger"]),
                tags=(tag,))
        npc = sum(1 for d in self.devices if d["verdict"].startswith("PC"))
        self.count_lbl.config(text=f"表示 {len(rows)} / 全 {len(self.devices)}（PC {npc}）")

    def _refresh_alerts(self):
        for i in self.atree.get_children():
            self.atree.delete(i)
        for a in self.alerts:
            self.atree.insert("", "end", values=(a["level"], a["kind"], a["ip"], a["host"], a["detail"]),
                              tags=(a["level"],))

    def _sort_by(self, col):
        idx = {"verdict": "verdict", "ip": "ip", "mac": "mac", "host": "host",
               "vendor": "vendor", "danger": "danger"}.get(col)
        if not idx:
            return
        rev = getattr(self, "_sort_rev", {}).get(col, False)
        if col == "ip":
            self.devices.sort(key=lambda d: tuple(int(o) for o in d["ip"].split(".")), reverse=rev)
        else:
            self.devices.sort(key=lambda d: str(d.get(idx, "")), reverse=rev)
        if not hasattr(self, "_sort_rev"):
            self._sort_rev = {}
        self._sort_rev[col] = not rev
        self._refresh_table()

    def show_detail(self):
        sel = self.tree.selection()
        rows = self._visible_devices()
        if not sel:
            return
        try:
            d = rows[self.tree.index(sel[0])]
        except Exception:
            return
        lines = [
            f"IP: {d['ip']}", f"MAC: {d['mac']}", f"ホスト名: {d['host'] or '(なし)'}",
            f"メーカー: {d['vendor']}", f"推定種別: {d['type'] or '(不明)'}",
            f"TTL: {d['ttl'] if d['ttl'] is not None else '(不明)'}",
            "ping応答: " + ("あり" if d.get("alive", True)
                          else "なし（Windowsの住所録＝ARP表にだけ残っていた。電源断の可能性）"),
            f"判定: {d['verdict']} (スコア {d['score']})",
            "判定理由: " + ("、".join(d["reasons"]) or "(なし)"),
            f"危険度: {d['danger']}",
            "開放ポート:",
        ]
        for p in d["ports"]:
            nm, role, plain = PORT_CATALOG.get(p, ("?", "watch", False))
            mark = {"danger": "🔴危険", "pc": "🖥PC識別", "watch": "🟡注意", "info": "ℹ良性"}.get(role, "")
            lines.append(f"   {p:>5} {nm} {mark}" + ("（平文）" if plain else ""))
        if not d["ports"]:
            lines.append("   (開放ポートなし＝ステルス/FWで閉じている／応答なしなら測れていない)")
        if d.get("benign_ports"):
            lines.append("既知の振る舞い（危険度に数えない）: "
                         + " ".join(str(p) for p in d["benign_ports"]))
        if d["note"]:
            lines.append(f"備考: {d['note']}")
        messagebox.showinfo(f"詳細 — {d['host'] or d['ip']}", "\n".join(lines))

    def update_baseline(self):
        if not self.devices:
            messagebox.showinfo(APP_TITLE, "先にスキャンを実行してください。")
            return
        if not messagebox.askyesno(APP_TITLE,
                                   f"現在の状態（{len(self.devices)}機器）を『正常なベースライン』として保存します。\n"
                                   "以降はこの状態からの変化を兆候として警告します。よろしいですか？"):
            return
        if save_baseline(self.devices):
            self.alerts = []
            self._refresh_alerts()
            self.status.config(text=f"ベースラインを更新しました（{len(self.devices)}機器）。")
        else:
            messagebox.showerror(APP_TITLE, "ベースライン保存に失敗しました。")

    def export_csv_dialog(self):
        if not self.devices:
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")],
                                            initialfile=f"pcguard_{datetime.now():%Y%m%d_%H%M%S}.csv")
        if path:
            export_csv(path, self._visible_devices())
            self.status.config(text=f"CSV出力: {path}")

    def export_html_dialog(self):
        if not self.devices:
            return
        path = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML", "*.html")],
                                            initialfile=f"pcguard_{datetime.now():%Y%m%d_%H%M%S}.html")
        if path:
            export_html(path, self.devices, self.alerts,
                        {"generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
            self.status.config(text=f"HTML出力: {path}")
            try:
                os.startfile(path)
            except Exception:
                pass

    def _on_close(self):
        self.monitoring = False
        self._stop_evt.set()
        if self.scanner:
            self.scanner.cancel = True
        self._sync_cfg()
        self.destroy()


if __name__ == "__main__":
    App().mainloop()
