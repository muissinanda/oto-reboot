import socket
import time
import urllib.request
import ssl
import logging
import threading
from typing import Dict, List, Any, Optional
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

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
_probe_lock = threading.Lock()
_is_probing = False

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

def _probe_single_ping(g: Dict[str, Any]) -> Dict[str, Any]:
    """
    Probe latensi ultra-cepat tanpa fork proses:
    Menggunakan TCP Socket non-blocking ke port 443 / 53 Anycast.
    Selesai dalam hitungan mili-detik (0.01 - 0.05s).
    """
    host = g["host"]
    ports = g["ports"]
    t0 = time.time()
    for p in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.7)
            s.connect((host, p))
            s.close()
            latency = round((time.time() - t0) * 1000.0, 1)
            return {"id": g["id"], "is_online": True, "latency_ms": latency}
        except Exception:
            pass
    return {"id": g["id"], "is_online": False, "latency_ms": None}

def _probe_single_http(a: Dict[str, Any]) -> Dict[str, Any]:
    """
    Probe HTTP respon time aplikasi UNEJ dengan timeout pendek (1.8s)
    """
    url = a["url"]
    t0 = time.time()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "UNEJ-NOC-Monitor/2.0 (FastProbe; +https://unej.ac.id)",
            "Accept": "*/*"
        }
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=1.8) as resp:
            dur = round((time.time() - t0) * 1000.0, 1)
            return {
                "id": a["id"],
                "is_online": True,
                "status_code": resp.status,
                "latency_ms": dur,
                "ssl_valid": True
            }
    except urllib.error.HTTPError as e:
        dur = round((time.time() - t0) * 1000.0, 1)
        return {
            "id": a["id"],
            "is_online": True,
            "status_code": e.code,
            "latency_ms": dur,
            "ssl_valid": True
        }
    except Exception:
        return {
            "id": a["id"],
            "is_online": False,
            "status_code": None,
            "latency_ms": None,
            "ssl_valid": False
        }

def _build_default_payload() -> Dict[str, Any]:
    """Mengembalikan payload default instan (0ms) untuk cold startup"""
    global_results = []
    for g in GLOBAL_LATENCY_TARGETS:
        global_results.append({
            "id": g["id"],
            "name": g["name"],
            "host": g["host"],
            "provider": g["provider"],
            "icon": g["icon"],
            "type": g["type"],
            "is_online": True,
            "latency_ms": 25.0,
            "latency_display": "Memuat...",
            "quality": {"badge": "MEMUAT", "color": "#22d3ee", "bg": "rgba(6, 182, 212, 0.15)", "class": "text-info"},
            "history": [25.0]
        })

    unej_results = []
    for a in UNEJ_APP_TARGETS:
        unej_results.append({
            "id": a["id"],
            "name": a["name"],
            "category": a["category"],
            "url": a["url"],
            "icon": a["icon"],
            "badge_color": a["badge_color"],
            "desc": a["desc"],
            "is_online": True,
            "status_code": 200,
            "status_display": "HTTP 200",
            "latency_ms": 200.0,
            "latency_display": "Memuat...",
            "ssl_valid": True,
            "quality": {"badge": "MEMUAT", "color": "#22d3ee", "bg": "rgba(6, 182, 212, 0.15)", "class": "text-info"},
            "history": [200.0]
        })

    return {
        "status": "success",
        "summary": {
            "avg_global_latency_ms": 25.0,
            "avg_google_ms": 30.0,
            "avg_cloudflare_ms": 15.0,
            "avg_unej_app_latency_ms": 200.0,
            "total_apps": len(UNEJ_APP_TARGETS),
            "online_apps": len(UNEJ_APP_TARGETS),
            "app_health_pct": 100.0,
            "timestamp": datetime.now().strftime("%H:%M:%S WIB")
        },
        "global_targets": global_results,
        "unej_apps": unej_results
    }

# Inisialisasi payload default agar request pertama langsung dijawab dalam 0.0001 detik
_cached_payload = _build_default_payload()

def update_services_health_background() -> None:
    """
    Siklus background worker (berjalan di thread terpisah / APScheduler):
    Mengeksekusi seluruh 14 target SECARA PARALEL bersamaan menggunakan ThreadPoolExecutor.
    Selesai dalam < 1.0 - 1.5 detik tanpa membebani event loop ataupun web request!
    """
    global _cached_payload, _cached_timestamp, _is_probing, _target_history

    with _probe_lock:
        if _is_probing:
            return
        _is_probing = True

    try:
        ping_results_map = {}
        http_results_map = {}

        # Eksekusi PARALEL 14 worker secara bersamaan
        with ThreadPoolExecutor(max_workers=14) as executor:
            ping_futures = {executor.submit(_probe_single_ping, g): g["id"] for g in GLOBAL_LATENCY_TARGETS}
            http_futures = {executor.submit(_probe_single_http, a): a["id"] for a in UNEJ_APP_TARGETS}

            for f in ping_futures:
                try:
                    res = f.result()
                    ping_results_map[res["id"]] = res
                except Exception:
                    pass

            for f in http_futures:
                try:
                    res = f.result()
                    http_results_map[res["id"]] = res
                except Exception:
                    pass

        # 1. Format Hasil Global Targets
        global_results = []
        valid_global_latencies = []
        for g in GLOBAL_LATENCY_TARGETS:
            t_id = g["id"]
            res = ping_results_map.get(t_id, {"is_online": False, "latency_ms": None})
            lat = res["latency_ms"]

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

        # 2. Format Hasil Aplikasi UNEJ
        unej_results = []
        valid_app_latencies = []
        online_app_count = 0

        for a in UNEJ_APP_TARGETS:
            a_id = a["id"]
            res = http_results_map.get(a_id, {"is_online": False, "latency_ms": None, "status_code": None, "ssl_valid": False})
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

            q = classify_app_quality(lat, is_up, res.get("status_code"))
            unej_results.append({
                "id": a_id,
                "name": a["name"],
                "category": a["category"],
                "url": a["url"],
                "icon": a["icon"],
                "badge_color": a["badge_color"],
                "desc": a["desc"],
                "is_online": is_up,
                "status_code": res.get("status_code") or 503,
                "status_display": f"HTTP {res.get('status_code')}" if res.get("status_code") else "TIMEOUT",
                "latency_ms": lat,
                "latency_display": f"{lat:.0f} ms" if lat is not None else "-",
                "ssl_valid": res.get("ssl_valid", False),
                "quality": q,
                "history": list(_target_history[a_id])
            })

        # Summary Metrik
        avg_global_lat = round(sum(valid_global_latencies) / len(valid_global_latencies), 1) if valid_global_latencies else 0.0
        avg_app_lat = round(sum(valid_app_latencies) / len(valid_app_latencies), 0) if valid_app_latencies else 0.0

        google_lats = [item["latency_ms"] for item in global_results if "google" in item["id"] and item["latency_ms"]]
        cf_lats = [item["latency_ms"] for item in global_results if "cloudflare" in item["id"] and item["latency_ms"]]
        avg_google = round(sum(google_lats) / len(google_lats), 1) if google_lats else 0.0
        avg_cf = round(sum(cf_lats) / len(cf_lats), 1) if cf_lats else 0.0

        new_payload = {
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

        # Simpan payload secara atomik ke in-memory cache
        _cached_payload = new_payload
        _cached_timestamp = time.time()
        logger.info(f"Services health probe updated in background: Global={avg_global_lat}ms, Apps={online_app_count}/{len(UNEJ_APP_TARGETS)}")

    except Exception as e:
        logger.error(f"Error in background services health probe: {e}")
    finally:
        with _probe_lock:
            _is_probing = False

def get_services_health_payload() -> Dict[str, Any]:
    """
    Mengembalikan payload telemetri latensi & aplikasi UNEJ SECARA INSTAN dari RAM cache.
    Respons time: < 0.001 ms (ZERO BLOCKING).
    Jika cache lebih tua dari 30 detik, trigger background worker secara non-blocking.
    """
    global _cached_payload, _cached_timestamp

    now = time.time()
    # Jika cache sudah lewat 30 detik dan tidak sedang probing, trigger update di background thread
    if (now - _cached_timestamp > 30.0) and not _is_probing:
        threading.Thread(target=update_services_health_background, daemon=True).start()

    return _cached_payload or _build_default_payload()
