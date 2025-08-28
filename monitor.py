# project/monitor.py
import csv, datetime, time, os
from utils import resolve, ping, check_port
from intrusion_detection import is_suspicious_email

# Add topology IPs and public hosts
HOSTS = [
    {"name":"Google","host":"google.com"},
    {"name":"DNS","host":"8.8.8.8"},
    # Example local PC in Packet Tracer:
    # {"name":"PC1","host":"192.168.10.10"},
]

LOG_FILE = "logs/network_log.csv"
ALERTS_FILE = "logs/alerts.log"

def ensure_dirs():
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

def write_header_if_needed():
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp","name","host","ip","status","extra"])

def log_row(row):
    ensure_dirs()
    write_header_if_needed()
    with open(LOG_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(row)

def alert(msg):
    ensure_dirs()
    with open(ALERTS_FILE, "a") as f:
        f.write(msg + "\n")
    print(msg)

def scan_once():
    timestamp = datetime.datetime.now().isoformat()
    for h in HOSTS:
        ip = resolve(h["host"])
        status = "DOWN"
        extra = ""
        if ip:
            reachable = ping(ip)
            if reachable:
                status = "UP"
                https_ok = check_port(ip, 443)
                extra = f"https:{https_ok}"
            else:
                status = "DOWN"
                extra = "ping_failed"
        else:
            extra = "dns_failed"
        log_row([timestamp, h["name"], h["host"], ip or "N/A", status, extra])
        if status == "DOWN":
            alert(f"{timestamp} ALERT: {h['name']} ({h['host']}) DOWN - {extra}")

def demo_phishing_check(sample_text):
    if is_suspicious_email(sample_text):
        alert(f"{datetime.datetime.now().isoformat()} PHISHING WARNING: suspicious content detected")

if __name__ == "__main__":
    print("Demo: running 3 quick scans (sleep 5s between scans)...")
    for i in range(3):
        print(f"--- Scan {i+1} ---")
        scan_once()
        time.sleep(5)
    # Example phishing demo (uncomment to use)
    # demo_phishing_check("Please verify your bank account password now. Click here.")
    print("Demo complete. Check logs/ for results.")
