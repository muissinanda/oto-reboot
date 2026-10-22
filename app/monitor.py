import socket
import subprocess
import platform
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from app.database import SessionLocal, AccessPoint, get_setting, now_wib

def check_ap_status(ip: str, port: int = 22, timeout: float = 1.5):
    """
    Cek apakah AP hidup/mati secara instan.
    Pertama coba TCP socket ke port SSH (port 22).
    Jika host merespons (baik SYN-ACK/port terbuka result=0, maupun TCP RST/connection refused result=111/10061),
    host terbukti 100% HIDUP tanpa perlu subprocess ping yang membebani CPU!
    Hanya fallback ke ICMP ping jika koneksi benar-benar timeout (tidak ada respon sama sekali).
    """
    t_start = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        # 0 = Connected, 111 / 10061 = Connection Refused (Host menjawab RST -> host aktif!)
        if result in (0, 111, 10061):
            latency = round((time.time() - t_start) * 1000, 1)
            return True, latency
    except Exception:
        pass

    # 2. Fallback ke ICMP ping cepat hanya jika TCP timeout total
    try:
        t_start = time.time()
        is_win = platform.system().lower() == 'windows'
        param = '-n' if is_win else '-c'
        timeout_flag = '-w' if is_win else '-W'
        # Batasi timeout ping max 1000ms agar worker tidak tertahan
        ping_timeout = str(int(min(timeout, 1.0) * 1000 if is_win else min(timeout, 1.0)))
        cmd = ['ping', param, '1', timeout_flag, ping_timeout, ip]
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
        timeout = float(get_setting(db, "ping_timeout", "1.5"))
        aps = db.query(AccessPoint).filter(AccessPoint.is_active == True).all()
        if not aps:
            return

        def _check(ap_data):
            ap_id, ip, port = ap_data
            is_up, latency = check_ap_status(ip, port, timeout)
            return ap_id, is_up, latency

        ap_items = [(ap.id, ap.ip, ap.port or 22) for ap in aps]
        
        with ThreadPoolExecutor(max_workers=30) as executor:
            results = list(executor.map(_check, ap_items))

        # Update database in-memory tanpa query berulang (hemat ratusan query SQL)
        now = now_wib()
        ap_dict = {ap.id: ap for ap in aps}
        for ap_id, is_up, latency in results:
            ap_obj = ap_dict.get(ap_id)
            if ap_obj:
                ap_obj.is_online = is_up
                ap_obj.latency_ms = latency
                ap_obj.last_checked = now
        db.commit()
    finally:
        db.close()
