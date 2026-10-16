import socket
import subprocess
import platform
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from app.database import SessionLocal, AccessPoint, get_setting

def check_ap_status(ip: str, port: int = 22, timeout: float = 2.0):
    """
    Cek apakah AP hidup/mati.
    Pertama coba TCP socket ke port SSH (port 22) untuk mengukur latency & SSH availability.
    Jika gagal, fallback ke ICMP ping.
    """
    # 1. Coba TCP socket ke SSH port
    t_start = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            latency = round((time.time() - t_start) * 1000, 1)
            return True, latency
    except Exception:
        pass

    # 2. Fallback ke ICMP ping
    try:
        t_start = time.time()
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        timeout_flag = '-w' if platform.system().lower() == 'windows' else '-W'
        cmd = ['ping', param, '1', timeout_flag, str(int(timeout * 1000 if platform.system().lower() == 'windows' else timeout)), ip]
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if res.returncode == 0:
            latency = round((time.time() - t_start) * 1000, 1)
            return True, latency
    except Exception:
        pass

    return False, None

def run_monitor_cycle():
    """
    Jalankan 1 siklus pengecekan status untuk semua AP yang aktif
    """
    db = SessionLocal()
    try:
        timeout = float(get_setting(db, "ping_timeout", "2"))
        aps = db.query(AccessPoint).filter(AccessPoint.is_active == True).all()
        if not aps:
            return

        def _check(ap_data):
            ap_id, ip, port = ap_data
            is_up, latency = check_ap_status(ip, port, timeout)
            return ap_id, is_up, latency

        ap_items = [(ap.id, ap.ip, ap.port or 22) for ap in aps]
        
        with ThreadPoolExecutor(max_workers=25) as executor:
            results = list(executor.map(_check, ap_items))

        # Update database
        now = datetime.utcnow()
        for ap_id, is_up, latency in results:
            ap_obj = db.query(AccessPoint).filter(AccessPoint.id == ap_id).first()
            if ap_obj:
                ap_obj.is_online = is_up
                ap_obj.latency_ms = latency
                ap_obj.last_checked = now
        db.commit()
    finally:
        db.close()
