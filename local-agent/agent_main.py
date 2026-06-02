
import os
import time
import hashlib
import socket
import threading
from collections import defaultdict
from datetime import datetime, timezone

import psutil
import requests
from scapy.all import sniff, IP
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from ipwhois import IPWhois
import geoip2.database
from dotenv import load_dotenv

# ============================================================
# LOAD ENV VARIABLES
# ============================================================

from dotenv import load_dotenv

load_dotenv()

# ============================================================
# CONFIGURATION
# ============================================================

BACKEND_API = os.getenv(
    "BACKEND_API",
    "http://localhost:8000/telemetry/upload"
)

VIRUSTOTAL_API_KEY = os.getenv("VT_API_KEY")

GEOIP_DB = os.getenv(
    "GEOIP_DB",
    "GeoLite2-City.mmdb"
)

SCAN_INTERVAL = int(
    os.getenv("SCAN_INTERVAL", 3)
)

# ============================================================
# PROCESS MAPPINGS
# ============================================================

PROCESS_FRIENDLY_NAMES = {
    "code.exe": "Visual Studio Code",
    "chrome.exe": "Google Chrome",
    "msedge.exe": "Microsoft Edge",
    "firefox.exe": "Mozilla Firefox",
    "powershell.exe": "Windows PowerShell",
    "cmd.exe": "Windows Command Prompt",
    "wire.exe": "Wire Secure Messenger",
    "supportassistagent.exe": "Dell SupportAssist",
    "qhactivedefense.exe": "360 Total Security",
    "qhsafetray.exe": "360 Security Tray",
    "microsoftstartfeedprovider.exe": "Microsoft Start Feed",
    "python.exe": "Python",
    "discord.exe": "Discord",
    "steam.exe": "Steam",
    "spotify.exe": "Spotify"
}

# ============================================================
# SUSPICIOUS PROCESSES
# ============================================================

SUSPICIOUS_PROCESSES = {
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "certutil.exe",
    "mshta.exe",
    "regsvr32.exe",
    "bash",
    "sh",
    "python.exe"
}

# ============================================================
# WHITELIST
# ============================================================

WHITELIST_PROCESSES = {
    "chrome.exe",
    "firefox.exe",
    "msedge.exe",
    "brave.exe",
    "svchost.exe",
    "explorer.exe",
    "system",
    "code.exe",
    "wire.exe",
    "supportassistagent.exe",
    "qhactivedefense.exe",
    "qhsafetray.exe",
    "microsoftstartfeedprovider.exe"
}

# ============================================================
# GLOBAL TRACKING
# ============================================================

seen_connections = set()

connection_counter = defaultdict(int)

vt_cache = {}

geo_reader = geoip2.database.Reader(GEOIP_DB)

# ============================================================
# HELPERS
# ============================================================

def get_friendly_name(raw_name):

    return PROCESS_FRIENDLY_NAMES.get(
        raw_name.lower(),
        raw_name.replace(".exe", "").title()
    )

# ============================================================

def sha256_file(path):

    try:

        sha256 = hashlib.sha256()

        with open(path, "rb") as f:

            for chunk in iter(lambda: f.read(4096), b""):

                sha256.update(chunk)

        return sha256.hexdigest()

    except:

        return "unknown"

# ============================================================

def resolve_dns(ip):

    try:

        return socket.gethostbyaddr(ip)[0]

    except:

        return "Unknown Domain"

# ============================================================

def get_ip_owner(ip):

    try:

        obj = IPWhois(ip)

        result = obj.lookup_rdap()

        network = result.get("network", {})

        return network.get("name", "Unknown Organization")

    except:

        return "Unknown Organization"

# ============================================================

def get_geoip(ip):

    try:

        response = geo_reader.city(ip)

        return {
            "country": response.country.name,
            "city": response.city.name
        }

    except:

        return {
            "country": "Unknown",
            "city": "Unknown"
        }

# ============================================================

def virustotal_lookup(ip):

    if not VIRUSTOTAL_API_KEY:

        return 0

    if ip in vt_cache:

        return vt_cache[ip]

    try:

        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY
        }

        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

        response = requests.get(
            url,
            headers=headers,
            timeout=5
        )

        if response.status_code == 200:

            data = response.json()

            stats = data["data"]["attributes"]["last_analysis_stats"]

            malicious = stats.get("malicious", 0)

            vt_cache[ip] = malicious

            return malicious

    except:

        pass

    return 0

# ============================================================

def calculate_risk(proc_name, vt_score, conn_count):

    risk = 20

    if proc_name in SUSPICIOUS_PROCESSES:

        risk += 40

    if vt_score > 0:

        risk += 40

    if conn_count > 15:

        risk += 15

    return min(risk, 100)

# ============================================================

def send_telemetry(event):

    payload = {
        "events": [event]
    }

    try:

        requests.post(
            BACKEND_API,
            json=payload,
            timeout=3
        )

    except:

        pass

# ============================================================
# NETWORK MONITOR
# ============================================================

def monitor_network():

    print("=" * 70)
    print(" Probable-Octo-Palm-Tree Advanced Security Agent ")
    print("=" * 70)

    while True:

        try:

            connections = psutil.net_connections(kind="inet")

            for conn in connections:

                if conn.status != "ESTABLISHED":
                    continue

                if not conn.raddr:
                    continue

                pid = conn.pid

                if not pid:
                    continue

                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port

                if remote_ip.startswith("127.") or remote_ip == "::1":
                    continue

                try:

                    proc = psutil.Process(pid)

                    raw_proc_name = proc.name().lower()

                    proc_name = get_friendly_name(raw_proc_name)

                    exe_path = proc.exe()

                except:
                    continue

                conn_id = f"{pid}-{remote_ip}:{remote_port}"

                if conn_id in seen_connections:
                    continue

                seen_connections.add(conn_id)

                # ====================================================
                # DNS
                # ====================================================

                domain = resolve_dns(remote_ip)

                # ====================================================
                # ORGANIZATION
                # ====================================================

                organization = get_ip_owner(remote_ip)

                # ====================================================
                # GEOLOCATION
                # ====================================================

                geo = get_geoip(remote_ip)

                # ====================================================
                # PROCESS HASH
                # ====================================================

                file_hash = sha256_file(exe_path)

                # ====================================================
                # THREAT INTEL
                # ====================================================

                vt_score = virustotal_lookup(remote_ip)

                # ====================================================
                # CONNECTION RATE
                # ====================================================

                connection_counter[raw_proc_name] += 1

                conn_count = connection_counter[raw_proc_name]

                # ====================================================
                # RISK
                # ====================================================

                risk_score = calculate_risk(
                    raw_proc_name,
                    vt_score,
                    conn_count
                )

                severity = "low"

                if risk_score >= 80:
                    severity = "critical"

                elif risk_score >= 60:
                    severity = "high"

                elif risk_score >= 40:
                    severity = "medium"

                # ====================================================
                # THREAT TYPE
                # ====================================================

                threat_type = "Normal Network Activity"

                if raw_proc_name in SUSPICIOUS_PROCESSES:
                    threat_type = "Suspicious Process Activity"

                if vt_score > 0:
                    threat_type = "Known Malicious Communication"

                # ====================================================
                # PROFESSIONAL CONSOLE OUTPUT
                # ====================================================

                print("\n" + "=" * 70)

                print(f"[{severity.upper()}] {threat_type}")

                print("-" * 70)

                print(f"Application : {proc_name}")

                print(f"PID         : {pid}")

                print(f"Organization: {organization}")

                print(f"Domain      : {domain}")

                print(f"Remote IP   : {remote_ip}")

                print(f"Port        : {remote_port}")

                print(f"Location    : {geo['city']}, {geo['country']}")

                print(f"VT Detections: {vt_score}")

                print(f"Risk Score  : {risk_score}")

                print("=" * 70)

                # ====================================================
                # TELEMETRY
                # ====================================================

                event = {

                    "timestamp": datetime.now(
                        timezone.utc
                    ).isoformat().replace("+00:00", "Z"),

                    "threat_type": threat_type,

                    "details": (
                        f"{proc_name} connected to "
                        f"{organization}"
                    ),

                    "severity": severity,

                    "url": f"http://{remote_ip}:{remote_port}",

                    "risk_score": risk_score,

                    "process_name": proc_name,

                    "process_hash": file_hash,

                    "domain": domain,

                    "organization": organization,

                    "geo_country": geo["country"],

                    "geo_city": geo["city"],

                    "remote_ip": remote_ip,

                    "remote_port": remote_port,

                    "virustotal_hits": vt_score
                }

                send_telemetry(event)

        except Exception as e:

            print(f"[ERROR] {e}")

        time.sleep(SCAN_INTERVAL)

# ============================================================
# PACKET CAPTURE
# ============================================================

def packet_callback(packet):

    if IP in packet:

        src = packet[IP].src
        dst = packet[IP].dst

        print(f"[PACKET] {src} -> {dst}")

# ============================================================

def start_packet_capture():

    print("[+] Packet capture enabled")

    sniff(
        prn=packet_callback,
        store=False
    )

# ============================================================
# RANSOMWARE DETECTION
# ============================================================

class RansomwareHandler(FileSystemEventHandler):

    suspicious_extensions = {
        ".locked",
        ".encrypted",
        ".crypt",
        ".enc"
    }

    def on_modified(self, event):

        if event.is_directory:
            return

        file_path = event.src_path.lower()

        for ext in self.suspicious_extensions:

            if file_path.endswith(ext):

                print("\n" + "=" * 70)

                print("[CRITICAL] POSSIBLE RANSOMWARE DETECTED")

                print("-" * 70)

                print(f"Encrypted File: {file_path}")

                print("=" * 70)

                event_data = {

                    "timestamp": datetime.now(
                        timezone.utc
                    ).isoformat().replace("+00:00", "Z"),

                    "threat_type": "Possible Ransomware Activity",

                    "details": (
                        f"Encrypted file extension detected: "
                        f"{file_path}"
                    ),

                    "severity": "critical",

                    "risk_score": 95
                }

                send_telemetry(event_data)

# ============================================================

def start_ransomware_monitor():

    path = "C:\\Users"

    observer = Observer()

    observer.schedule(
        RansomwareHandler(),
        path,
        recursive=True
    )

    observer.start()

    print("[+] Ransomware monitor enabled")

# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    threading.Thread(
        target=monitor_network,
        daemon=True
    ).start()

    threading.Thread(
        target=start_packet_capture,
        daemon=True
    ).start()

    threading.Thread(
        target=start_ransomware_monitor,
        daemon=True
    ).start()

    while True:

        time.sleep(1)

