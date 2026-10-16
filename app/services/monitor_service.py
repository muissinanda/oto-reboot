import logging
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import ping3
from flask import current_app
from app.extensions import db, scheduler
from app.models import AccessPoint

logger = logging.getLogger(__name__)


def _tcp_check(ip, port=22, timeout=3):
    """Fallback TCP connect check on port 22."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        return True
    except (socket.timeout, socket.error, OSError):
        return False
    finally:
        sock.close()


def check_ap_status(ip, timeout=3):
    """
    Check if an Access Point IP is online using ping3.
    Falls back to TCP socket connection on port 22 upon permission/ping failures.

    :param ip: IP address of the access point
    :param timeout: timeout in seconds
    :return: 'online' or 'offline'
    """
    try:
        latency = ping3.ping(ip, timeout=timeout)
        if latency is not None and latency is not False:
            return 'online'
        # Ping failed or returned None/False, fallback to SSH port 22
        if _tcp_check(ip, port=22, timeout=timeout):
            return 'online'
        return 'offline'
    except (ping3.errors.PingError, PermissionError, OSError, Exception) as exc:
        logger.debug("ping3 check failed for %s (%s), trying fallback TCP port 22", ip, exc)
        if _tcp_check(ip, port=22, timeout=timeout):
            return 'online'
        return 'offline'


def _check_all_aps_internal():
    """Internal implementation of check_all_aps within an active app context."""
    aps = AccessPoint.query.all()
    if not aps:
        return []

    def _worker(ap_data):
        ap_id, ip = ap_data
        status = check_ap_status(ip)
        return ap_id, status

    items = [(ap.id, ap.ip_address) for ap in aps]
    max_workers = min(len(items), 20)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = list(executor.map(_worker, items))

    status_map = dict(results)
    now = datetime.utcnow()

    for ap in aps:
        if ap.id in status_map:
            ap.status = status_map[ap.id]
            ap.last_checked = now

    try:
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        logger.error("Failed to update AP statuses in database: %s", exc)

    return [
        {
            'id': ap.id,
            'name': ap.name,
            'ip_address': ap.ip_address,
            'status': ap.status,
            'last_checked': ap.last_checked.isoformat() if ap.last_checked else None
        }
        for ap in aps
    ]


def check_all_aps():
    """
    Checks all APs in the database in parallel, updating status and last_checked.
    Manages Flask app context automatically if called from background thread.
    """
    app = None
    try:
        app = current_app._get_current_object()
    except RuntimeError:
        if hasattr(scheduler, 'app') and scheduler.app:
            app = scheduler.app

    if app:
        with app.app_context():
            return _check_all_aps_internal()
    return _check_all_aps_internal()


def check_single_ap(ap_id):
    """
    Check the status of a single AP, updates its status and last_checked in database.

    :param ap_id: AccessPoint ID
    :return: status string ('online' or 'offline'), or None if AP not found
    """
    ap = AccessPoint.query.get(ap_id)
    if not ap:
        logger.warning("Access Point with ID %s not found for status check", ap_id)
        return None

    status = check_ap_status(ap.ip_address)
    ap.status = status
    ap.last_checked = datetime.utcnow()

    try:
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        logger.error("Failed to commit status update for AP %s: %s", ap_id, exc)

    return status
