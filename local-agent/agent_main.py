import psutil
import time
import requests
from datetime import datetime

# Probable-Octo-Palm-Tree Local Security Agent
# Monitors active system network connections to detect unauthorized access outside the browser

BACKEND_API = "http://localhost:8000/telemetry/upload"

# Processes that shouldn't typically make arbitrary outgoing internet connections
SUSPICIOUS_PROCESSES = {
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", 
    "certutil.exe", "mshta.exe", "regsvr32.exe", "bash", "sh"
}

# Processes we expect to make lots of connections (ignore them to save CPU)
WHITELIST_PROCESSES = {
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe",
    "svchost.exe", "explorer.exe", "System"
}

def monitor_network():
    print("Probable-Octo-Palm-Tree Local Security Agent started.")
    print("Monitoring active network connections...")
    
    seen_connections = set()
    
    while True:
        try:
            # Check all network connections
            for conn in psutil.net_connections(kind='inet'):
                # Only care about established outbound connections
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    pid = conn.pid
                    if not pid:
                        continue
                    
                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port
                    
                    # Ignore loopback
                    if remote_ip == "127.0.0.1" or remote_ip == "::1":
                        continue
                        
                    try:
                        proc = psutil.Process(pid)
                        proc_name = proc.name().lower()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                        
                    if proc_name in WHITELIST_PROCESSES:
                        continue
                        
                    conn_id = f"{pid}-{remote_ip}:{remote_port}"
                    if conn_id not in seen_connections:
                        seen_connections.add(conn_id)
                        
                        severity = "medium"
                        threat_type = "Unusual Outbound Connection"
                        
                        if proc_name in SUSPICIOUS_PROCESSES:
                            severity = "critical"
                            threat_type = "Suspicious Process Network Activity"
                            
                        print(f"[{severity.upper()}] {proc_name} (PID {pid}) connected to {remote_ip}:{remote_port}")
                        
                        # Send telemetry to our backend
                        payload = {
                            "events": [{
                                "timestamp": datetime.utcnow().isoformat() + "Z",
                                "threat_type": threat_type,
                                "details": f"Process '{proc_name}' (PID {pid}) connected to {remote_ip}:{remote_port}",
                                "severity": severity,
                                "url": f"http://{remote_ip}:{remote_port}",
                                "risk_score": 75 if severity == "critical" else 40
                            }]
                        }
                        
                        try:
                            requests.post(BACKEND_API, json=payload, timeout=2)
                        except:
                            pass # Backend might be offline
                            
        except Exception as e:
            print(f"Monitor error: {e}")
            
        time.sleep(3) # Poll every 3 seconds

if __name__ == "__main__":
    monitor_network()
