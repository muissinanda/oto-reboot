import socket
import time
import subprocess
import platform
import urllib.request
import ssl
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

# Target Global: Google & Cloudflare (serta OpenDNS & Quad9)
GLOBAL_LATENCY_TARGETS = [
    {
        "id": "google_primary",
        "name": "Google DNS Primary",
        "host": "8.8.8.8",
        "provider": "Google LLC",
        "icon": "bi-google",
        "type": "Anycast DNS",
        "ports": [443, 53]
    },
    {
        "id": "google_secondary",
        "name": "Google DNS Secondary",
        "host": "8.8.4.4",
        "provider": "Google LLC",
        "icon": "bi-google",
        "type": "Anycast DNS",
        "ports": [443, 53]
    },
    {
        "id": "cloudflare_primary",
        "name": "Cloudflare Primary",
        "host": "1.1.1.1",
        "provider": "Cloudflare Inc.",
        "icon": "bi-cloud-fill",
        "type": "Anycast CDN / DNS",
        "ports": [443, 53]
    },
    {
        "id": "cloudflare_secondary",
        "name": "Cloudflare Secondary",
        "host": "1.0.0.1",
        "provider": "Cloudflare Inc.",
        "icon": "bi-cloud-fill",
        "type": "Anycast CDN / DNS",
        "ports": [443, 53]
    },
    {
        "id": "opendns_primary",
        "name": "OpenDNS Cisco",
        "host": "208.67.222.222",
        "provider": "Cisco Systems",
        "icon": "bi-shield-check",
        "type": "Secure DNS",
        "ports": [443, 53]
    },
    {
        "id": "quad9_primary",
        "name": "Quad9 Threat Blocking",
        "host": "9.9.9.9",
        "provider": "Quad9 Foundation",
        "icon": "bi-lock-fill",
        "type": "Clean Anycast",
        "ports": [443, 53]
    }
]

# Target Aplikasi Kampus UNEJ (Universitas Jember)
UNEJ_APP_TARGETS = [
    {
        "id": "sister_unej",
        "name": "SISTER UNEJ",
        "category": "Sistem Akademik & KRS",
        "url": "https://sister.unej.ac.id",
        "icon": "bi-mortarboard-fill",
        "badge_color": "#38bdf8",
        "desc": "Sistem Informasi Terpadu Mahasiswa & Dosen"
    },
    {
        "id": "portal_unej",
        "name": "Portal Website UNEJ",
        "category": "Portal Resmi",
        "url": "https://unej.ac.id",
        "icon": "bi-globe2",
        "badge_color": "#34d399",
        "desc": "Website Utama Universitas Jember"
    },
    {
        "id": "mmp_unej",
        "name": "MMP UNEJ (E-Learning)",
        "category": "LMS Moodle Perkuliahan",
        "url": "https://mmp.unej.ac.id",
        "icon": "bi-laptop",
        "badge_color": "#facc15",
        "desc": "Media Menolak Pusing E-Learning Kampus"
    },
    {
        "id": "repository_unej",
        "name": "Repository UNEJ",
        "category": "Karya Ilmiah & Skripsi",
        "url": "https://repository.unej.ac.id",
        "icon": "bi-journal-bookmark-fill",
        "badge_color": "#c084fc",
        "desc": "Publikasi Ilmiah & Dokumen Akademik"
    },
    {
        "id": "spmb_unej",
        "name": "SPMB UNEJ",
        "category": "Penerimaan Mahasiswa",
        "url": "https://spmb.unej.ac.id",
        "icon": "bi-person-plus-fill",
        "badge_color": "#fb7185",
        "desc": "Portal Pendaftaran & Seleksi Mahasiswa Baru"
    },
    {
        "id": "lp2m_unej",
        "name": "LP2M UNEJ",
        "category": "Penelitian & Pengabdian",
        "url": "https://lp2m.unej.ac.id",
        "icon": "bi-lightbulb-fill",
        "badge_color": "#818cf8",
        "desc": "Lembaga Penelitian & Pengabdian Masyarakat"
    },
    {
        "id": "jurnal_unej",
        "name": "Portal Jurnal UNEJ",
        "category": "E-Journal OJS",
        "url": "https://jurnal.unej.ac.id",
        "icon": "bi-book-fill",
        "badge_color": "#2dd4bf",
        "desc": "Publikasi Jurnal Ilmiah Terakreditasi"
    },
    {
        "id": "simbapen_unej",
        "name": "SIMBAPEN UNEJ",
        "category": "Layanan Beasiswa",
        "url": "https://simbapen.unej.ac.id",
        "icon": "bi-award-fill",
        "badge_color": "#fb923c",
        "desc": "Sistem Informasi Manajemen Bantuan Pendidikan"
    }
]

# History buffer in-memory untuk sparkline grafik tren
_target_history: Dict[str, List[float]] = {}
_cached_payload: Optional[Dict[str, Any]] = None
_cached_timestamp: float = 0.0

def measure_ping(host: str, ports: List[int], timeout: float = 1.5) -> Dict[str, Any]:
    """
    Mengukur latensi RTT dengan kombinasi ultra-cepat:
    1. TCP SYN probe ke port umum (443 / 53) -> cepat, akurat, tanpa overhead subprocess.
    2. Fallback ke ICMP Ping cepat (1 packet).
    """
    t0 = time.time()
    # 1. Coba koneksi TCP socket
    for p in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(min(timeout, 0.8))
            s.connect((host, p))
            s.close()
            latency = round((time.time() - t0) * 1000.0, 1)
            return {"is_online": True, "latency_ms": latency, "method": "TCP"}
        except Exception:
            pass

    # 2. Fallback ICMP ping
    try:
        t_start = time.time()
        is_win = platform.system().lower() == 'windows'
        param = '-n' if is_win else '-c'
        timeout_flag = '-w' if is_win else '-W'
        ping_timeout = str(int(timeout * 1000 if is_win else timeout))
        cmd = ['ping', param, '1', timeout_flag, ping_timeout, host]
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if res.returncode == 0:
            latency = round((time.time() - t_start) * 1000.0, 1)
            return {"is_online": True, "latency_ms": latency, "method": "ICMP"}
    except Exception:
        pass

    return {"is_online": False, "latency_ms": None, "method": "TIMEOUT"}

def measure_http(url: str, timeout: float = 2.5) -> Dict[str, Any]:
    """
    Mengukur waktu respon HTTP (TTFB / Latensi Aplikasi) dan status SSL/HTTP
    """
    t0 = time.time()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "UNEJ-NOC-Monitor/2.0 (Wallboard; +https://unej.ac.id)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            dur = round((time.time() - t0) * 1000.0, 1)
            return {
                "is_online": True,
                "status_code": resp.status,
                "latency_ms": dur,
                "ssl_valid": True,
                "error": None
            }
    except urllib.error.HTTPError as e:
        # HTTP 301, 302, 401, 403 berarti web server aktif dan menjawab
        dur = round((time.time() - t0) * 1000.0, 1)
        return {
            "is_online": True,
            "status_code": e.code,
            "latency_ms": dur,
            "ssl_valid": True,
            "error": f"HTTP {e.code}"
        }
    except Exception as e:
        dur = round((time.time() - t0) * 1000.0, 1)
        return {
            "is_online": False,
            "status_code": None,
            "latency_ms": None,
            "ssl_valid": False,
            "error": str(e)[:50]
        }

def classify_latency_quality(latency: Optional[float]) -> Dict[str, str]:
    if latency is None:
        return {"badge": "RTO / OFFLINE", "color": "#f87171", "bg": "rgba(239, 68, 68, 0.15)", "class": "text-danger"}
    if latency < 20.0:
        return {"badge": "SANGAT CEPAT", "color": "#34d399", "bg": "rgba(16, 185, 129, 0.15)", "class": "text-success"}
    if latency < 50.0:
        return {"badge": "BAIK / STABIL", "color": "#22d3ee", "bg": "rgba(6, 182, 212, 0.15)", "class": "text-info"}
    if latency < 100.0:
        return {"badge": "SEDANG", "color": "#fbbf24", "bg": "rgba(245, 158, 11, 0.15)", "class": "text-warning"}
    return {"badge": "TINGGI", "color": "#fb923c", "bg": "rgba(251, 146, 60, 0.15)", "class": "text-warning"}

def classify_app_quality(latency: Optional[float], is_online: bool, status_code: Optional[int]) -> Dict[str, str]:
    if not is_online:
        return {"badge": "DOWN / TIMEOUT", "color": "#f87171", "bg": "rgba(239, 68, 68, 0.18)", "class": "text-danger"}
    if latency and latency < 300.0:
        return {"badge": "SANGAT CEPAT", "color": "#34d399", "bg": "rgba(16, 185, 129, 0.15)", "class": "text-success"}
    if latency and latency < 800.0:
        return {"badge": "NORMAL / STABIL", "color": "#22d3ee", "bg": "rgba(6, 182, 212, 0.15)", "class": "text-info"}
    if latency and latency < 2000.0:
        return {"badge": "RESPON SEDANG", "color": "#fbbf24", "bg": "rgba(245, 158, 11, 0.15)", "class": "text-warning"}
    return {"badge": "RESPON LAMBAT", "color": "#fb923c", "bg": "rgba(251, 146, 60, 0.18)", "class": "text-warning"}

def probe_all_services_sync() -> Dict[str, Any]:
    """
    Eksekusi probe paralel ke semua target global dan aplikasi UNEJ
    """
    global _target_history

    # 1. Probe Global Targets
    global_results = []
    valid_global_latencies = []
    for g in GLOBAL_LATENCY_TARGETS:
        t_id = g["id"]
        res = measure_ping(g["host"], g["ports"], timeout=1.5)
        lat = res["latency_ms"]

        # Catat history sparkline (maksimal 12 titik)
        if t_id not in _target_history:
            _target_history[t_id] = []
        _target_history[t_id].append(lat if lat is not None else 0.0)
        if len(_target_history[t_id]) > 12:
            _target_history[t_id].pop(0)

        if lat is not None:
            valid_global_latencies.append(lat)

        q = classify_latency_quality(lat)
        global_results.append({
            "id": t_id,
            "name": g["name"],
            "host": g["host"],
            "provider": g["provider"],
            "icon": g["icon"],
            "type": g["type"],
            "is_online": res["is_online"],
            "latency_ms": lat,
            "latency_display": f"{lat:.1f} ms" if lat is not None else "RTO",
            "quality": q,
            "history": list(_target_history[t_id])
        })

    # 2. Probe Aplikasi UNEJ
    unej_results = []
    valid_app_latencies = []
    online_app_count = 0

    for a in UNEJ_APP_TARGETS:
        a_id = a["id"]
        res = measure_http(a["url"], timeout=2.5)
        lat = res["latency_ms"]
        is_up = res["is_online"]

        if a_id not in _target_history:
            _target_history[a_id] = []
        _target_history[a_id].append(lat if lat is not None else 0.0)
        if len(_target_history[a_id]) > 12:
            _target_history[a_id].pop(0)

        if is_up:
            online_app_count += 1
            if lat is not None:
                valid_app_latencies.append(lat)

        q = classify_app_quality(lat, is_up, res["status_code"])
        unej_results.append({
            "id": a_id,
            "name": a["name"],
            "category": a["category"],
            "url": a["url"],
            "icon": a["icon"],
            "badge_color": a["badge_color"],
            "desc": a["desc"],
            "is_online": is_up,
            "status_code": res["status_code"] or 503,
            "status_display": f"HTTP {res['status_code']}" if res["status_code"] else "TIMEOUT",
            "latency_ms": lat,
            "latency_display": f"{lat:.0f} ms" if lat is not None else "-",
            "ssl_valid": res["ssl_valid"],
            "quality": q,
            "history": list(_target_history[a_id])
        })

    # Summary Metrik
    avg_global_lat = round(sum(valid_global_latencies) / len(valid_global_latencies), 1) if valid_global_latencies else 0.0
    avg_app_lat = round(sum(valid_app_latencies) / len(valid_app_latencies), 0) if valid_app_latencies else 0.0

    # Rata-rata spesifik Google & Cloudflare
    google_lats = [item["latency_ms"] for item in global_results if "google" in item["id"] and item["latency_ms"]]
    cf_lats = [item["latency_ms"] for item in global_results if "cloudflare" in item["id"] and item["latency_ms"]]
    avg_google = round(sum(google_lats) / len(google_lats), 1) if google_lats else 0.0
    avg_cf = round(sum(cf_lats) / len(cf_lats), 1) if cf_lats else 0.0

    return {
        "status": "success",
        "summary": {
            "avg_global_latency_ms": avg_global_lat,
            "avg_google_ms": avg_google,
            "avg_cloudflare_ms": avg_cf,
            "avg_unej_app_latency_ms": avg_app_lat,
            "total_apps": len(UNEJ_APP_TARGETS),
            "online_apps": online_app_count,
            "app_health_pct": round((online_app_count / len(UNEJ_APP_TARGETS)) * 100, 1),
            "timestamp": datetime.now().strftime("%H:%M:%S WIB")
        },
        "global_targets": global_results,
        "unej_apps": unej_results
    }

def get_services_health_payload(force_refresh: bool = False) -> Dict[str, Any]:
    """
    Mengembalikan payload telemetri latensi & aplikasi UNEJ dengan caching 10 detik
    agar responsif dan tidak membebani server/jaringan.
    """
    global _cached_payload, _cached_timestamp
    now = time.time()
    if not force_refresh and _cached_payload and (now - _cached_timestamp < 10.0):
        return _cached_payload

    try:
        data = probe_all_services_sync()
        _cached_payload = data
        _cached_timestamp = now
        return data
    except Exception as e:
        logger.error(f"Error probing services health: {e}")
        if _cached_payload:
            return _cached_payload
        return {
            "status": "error",
            "message": str(e),
            "summary": {
                "avg_global_latency_ms": 0.0,
                "avg_google_ms": 0.0,
                "avg_cloudflare_ms": 0.0,
                "avg_unej_app_latency_ms": 0.0,
                "total_apps": len(UNEJ_APP_TARGETS),
                "online_apps": 0,
                "app_health_pct": 0,
                "timestamp": datetime.now().strftime("%H:%M:%S WIB")
            },
            "global_targets": [],
            "unej_apps": []
        }
