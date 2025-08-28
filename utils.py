# project/utils.py
import socket
import platform
import subprocess

def resolve(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None

def ping(host, timeout=1):
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    # For linux/mac add timeout param after count if needed
    cmd = ['ping', param, '1', host]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return proc.returncode == 0
    except Exception:
        return False

def check_port(ip, port, timeout=2):
    import socket
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        s.close()
        return True
    except:
        return False
