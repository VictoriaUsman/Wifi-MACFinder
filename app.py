import subprocess
import re
import socket
import time
import threading
import uuid
from flask import Flask, render_template, jsonify

app = Flask(__name__)

_lock = threading.Lock()
_state = {
    "devices": [],
    "last_scan": None,
    "scanning": False,
    "subnet": "",
    "local_ip": "",
    "error": "",
}

# Vendor substrings that are exclusively or predominantly mobile manufacturers
_MOBILE_VENDOR_KEYWORDS = [
    "xiaomi", "oneplus", "oppo", "vivo", "realme", "nothing technology",
    "motorola mobility", "zte corporation", "sony mobile", "blackberry",
    "htc corporation", "wiko", "meizu", "nubia", "fairphone", "shift",
    "umidigi", "tcl communication",
]

# (os keywords to match, canonical OS label, implied device type)
_OS_RULES = [
    (["iphone os", "ios", "ipad os"],        "iOS",            "Mobile"),
    (["android"],                             "Android",        "Mobile"),
    (["windows phone", "windows mobile"],     "Windows Mobile", "Mobile"),
    (["mac os x", "macos", "apple mac os"],   "macOS",          "Computer"),
    (["windows"],                             "Windows",        "Computer"),
    (["linux"],                               "Linux",          "Computer"),
    (["freebsd", "openbsd", "netbsd"],        "BSD",            "Computer"),
]


def classify_device(vendor: str, os_raw: str, nmap_type: str):
    """Return (device_type_label, os_label) using nmap data + vendor heuristics."""
    v = vendor.lower()
    o = os_raw.lower()
    t = nmap_type.lower()

    # nmap explicit device type
    if "phone" in t or "pda" in t:
        dev_type = "Mobile"
    elif "general purpose" in t:
        dev_type = "Computer"
    elif "router" in t or "firewall" in t or "switch" in t:
        dev_type = "Router"
    elif "printer" in t:
        dev_type = "Printer"
    elif "media" in t or "game" in t:
        dev_type = "Media"
    elif "webcam" in t or "camera" in t:
        dev_type = "Camera"
    else:
        dev_type = ""

    # OS string → label + implied type
    os_label = ""
    for keywords, label, implied_type in _OS_RULES:
        if any(k in o for k in keywords):
            os_label = label
            if not dev_type:
                dev_type = implied_type
            break

    # Vendor heuristics when type still unknown
    if not dev_type:
        if any(k in v for k in _MOBILE_VENDOR_KEYWORDS):
            dev_type = "Mobile"
        elif "google" in v and not os_label:
            dev_type = "Mobile"   # Pixel / Nest devices

    return dev_type, os_label


def get_local_subnet():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        parts = local_ip.split(".")
        subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return subnet, local_ip
    except Exception:
        return "192.168.1.0/24", "unknown"


def parse_nmap_output(output):
    """Parse nmap output into device dicts, including OS and device-type fields."""
    devices = []
    # Split on each new host block so we can read multi-line OS info per host
    blocks = re.split(r"(?=Nmap scan report for )", output)

    for block in blocks:
        if not block.strip():
            continue

        ip = hostname = mac = vendor = os_info = nmap_type = ""

        m = re.search(r"Nmap scan report for (.+?) \((\d+\.\d+\.\d+\.\d+)\)", block)
        if m:
            hostname = m.group(1).strip()
            ip = m.group(2)
        else:
            m = re.search(r"Nmap scan report for (\d+\.\d+\.\d+\.\d+)", block)
            if m:
                ip = m.group(1)

        if not ip:
            continue

        m = re.search(r"MAC Address: ([0-9A-Fa-f:]{17}) \((.+?)\)", block)
        if not m:
            continue   # local machine — handled separately in merge_devices
        mac = m.group(1).upper()
        vendor = m.group(2)

        m = re.search(r"Device type:\s*(.+)", block)
        if m:
            nmap_type = m.group(1).strip()

        m = re.search(r"OS details:\s*(.+)", block)
        if m:
            os_info = m.group(1).strip()
        else:
            m = re.search(r"Running(?:\s+\(JUST GUESSING\))?:\s*(.+)", block)
            if m:
                os_info = m.group(1).strip()

        dev_type, os_label = classify_device(vendor, os_info, nmap_type)

        devices.append({
            "ip": ip,
            "mac": mac,
            "vendor": vendor,
            "hostname": hostname,
            "os": os_label,
            "type": dev_type,
        })

    return devices


def arp_table_devices():
    """Read Windows ARP cache as supplemental source."""
    devices = []
    try:
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10)
        for line in result.stdout.splitlines():
            m = re.match(r"\s+(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f]{2}(?:[:-][0-9a-f]{2}){5})\s+dynamic", line, re.I)
            if m:
                mac = m.group(2).replace("-", ":").upper()
                devices.append({"ip": m.group(1), "mac": mac, "vendor": "", "hostname": "", "os": "", "type": ""})
    except Exception:
        pass
    return devices


def get_local_mac(local_ip):
    """Find the MAC address of the adapter bound to local_ip via ipconfig /all."""
    try:
        result = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True, timeout=10)
        current_mac = None
        for line in result.stdout.splitlines():
            mac_m = re.search(r"Physical Address[.\s]+:\s+([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})", line)
            if mac_m:
                current_mac = mac_m.group(1).replace("-", ":").upper()
            ip_m = re.search(r"IPv4 Address[.\s]+:\s+(\d+\.\d+\.\d+\.\d+)", line)
            if ip_m and ip_m.group(1) == local_ip and current_mac:
                return current_mac
    except Exception:
        pass
    n = uuid.getnode()
    return ":".join(f"{(n >> (8 * i)) & 0xFF:02X}" for i in reversed(range(6)))


def get_local_hostname():
    try:
        return socket.gethostname()
    except Exception:
        return ""


def merge_devices(nmap_devs, arp_devs, local_ip):
    by_mac = {d["mac"]: d for d in nmap_devs}
    for d in arp_devs:
        if d["mac"] not in by_mac:
            by_mac[d["mac"]] = d

    if local_ip and local_ip != "unknown":
        local_mac = get_local_mac(local_ip)
        if local_mac and local_mac not in by_mac:
            by_mac[local_mac] = {
                "ip": local_ip,
                "mac": local_mac,
                "vendor": "This device",
                "hostname": get_local_hostname(),
                "os": "Windows",
                "type": "Computer",
            }

    return sorted(by_mac.values(), key=lambda x: list(map(int, x["ip"].split("."))))


def do_scan():
    subnet, local_ip = get_local_subnet()
    with _lock:
        _state["scanning"] = True
        _state["error"] = ""
        _state["subnet"] = subnet
        _state["local_ip"] = local_ip

    nmap_devs = []
    error_msg = ""
    try:
        result = subprocess.run(
            ["nmap", "-sn", subnet],
            capture_output=True, text=True, timeout=120,
        )
        nmap_devs = parse_nmap_output(result.stdout)
        if result.returncode != 0 and not nmap_devs:
            error_msg = result.stderr.strip() or "nmap returned an error."
    except FileNotFoundError:
        error_msg = "nmap not found. Install nmap and ensure it is on PATH."
    except subprocess.TimeoutExpired:
        error_msg = "nmap scan timed out."
    except Exception as e:
        error_msg = str(e)

    arp_devs = arp_table_devices()
    devices = merge_devices(nmap_devs, arp_devs, local_ip)

    with _lock:
        _state["devices"] = devices
        _state["last_scan"] = time.time()
        _state["scanning"] = False
        _state["error"] = error_msg


def background_loop():
    while True:
        do_scan()
        time.sleep(30)


@app.route("/")
def index():
    subnet, local_ip = get_local_subnet()
    return render_template("index.html", local_ip=local_ip, subnet=subnet)


@app.route("/api/status")
def api_status():
    with _lock:
        return jsonify({
            "devices": _state["devices"],
            "count": len(_state["devices"]),
            "last_scan": _state["last_scan"],
            "scanning": _state["scanning"],
            "subnet": _state["subnet"],
            "local_ip": _state["local_ip"],
            "error": _state["error"],
        })


@app.route("/api/scan", methods=["POST"])
def api_scan():
    with _lock:
        if _state["scanning"]:
            return jsonify({"status": "already_scanning"})
    t = threading.Thread(target=do_scan, daemon=True)
    t.start()
    return jsonify({"status": "started"})


if __name__ == "__main__":
    t = threading.Thread(target=background_loop, daemon=True)
    t.start()
    app.run(host="0.0.0.0", port=5000, debug=False)
