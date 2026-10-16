"""
Dashboard Route Blueprint for OTO REBOOT application.
Manages dashboard views, real-time statistics API, and quick actions for APs.
"""

import logging
from datetime import datetime, date, time
from flask import Blueprint, render_template, jsonify, request

from app.extensions import db
from app.models import AccessPoint, Schedule, RebootLog, Controller
from app.services.monitor_service import check_ap_status, check_all_aps, check_single_ap
from app.services.ssh_service import manual_reboot

logger = logging.getLogger(__name__)

dashboard_bp = Blueprint('dashboard', __name__, url_prefix='/')


@dashboard_bp.route('/', methods=['GET'])
def index():
    """
    Dashboard main page.
    Queries total APs, online/offline count, recent 10 reboot logs,
    active schedules count, and list of APs with status.
    """
    try:
        total_aps = AccessPoint.query.count()
        online_count = AccessPoint.query.filter(db.func.lower(AccessPoint.status) == 'online').count()
        offline_count = AccessPoint.query.filter(db.func.lower(AccessPoint.status) == 'offline').count()
        active_schedules_count = Schedule.query.filter_by(is_active=True).count()

        # Query recent 10 reboot logs with AP information
        recent_logs = (
            RebootLog.query
            .order_by(RebootLog.executed_at.desc())
            .limit(10)
            .all()
        )

        # Attach AP reference safely if relationship is not already bound
        for log in recent_logs:
            if not getattr(log, 'access_point', None):
                ap_id = getattr(log, 'access_point_id', None) or getattr(log, 'ap_id', None)
                if ap_id:
                    ap = AccessPoint.query.get(ap_id)
                    log.access_point = ap
                    log.ap = ap

        # List all APs with status (order by name)
        aps = AccessPoint.query.order_by(AccessPoint.name.asc()).all()

        return render_template(
            'dashboard.html',
            total_aps=total_aps,
            online_count=online_count,
            offline_count=offline_count,
            active_schedules_count=active_schedules_count,
            recent_logs=recent_logs,
            aps=aps
        )
    except Exception as e:
        logger.error(f"Error loading dashboard: {str(e)}", exc_info=True)
        # Render page with default/empty values if database query fails
        return render_template(
            'dashboard.html',
            total_aps=0,
            online_count=0,
            offline_count=0,
            active_schedules_count=0,
            recent_logs=[],
            aps=[],
            error=str(e)
        )


@dashboard_bp.route('/api/stats', methods=['GET'])
def get_stats():
    """
    JSON API returning overall stats:
    {total_aps, online, offline, unknown, total_schedules, active_schedules, total_reboots_today}
    """
    try:
        total_aps = AccessPoint.query.count()
        online = AccessPoint.query.filter(db.func.lower(AccessPoint.status) == 'online').count()
        offline = AccessPoint.query.filter(db.func.lower(AccessPoint.status) == 'offline').count()
        unknown = AccessPoint.query.filter(
            (AccessPoint.status.is_(None)) |
            (~db.func.lower(AccessPoint.status).in_(['online', 'offline']))
        ).count()

        total_schedules = Schedule.query.count()
        active_schedules = Schedule.query.filter_by(is_active=True).count()

        # Count reboots executed today
        today_start = datetime.combine(date.today(), time.min)
        today_end = datetime.combine(date.today(), time.max)
        total_reboots_today = RebootLog.query.filter(
            RebootLog.executed_at >= today_start,
            RebootLog.executed_at <= today_end
        ).count()

        return jsonify({
            'success': True,
            'total_aps': total_aps,
            'online': online,
            'offline': offline,
            'unknown': unknown,
            'total_schedules': total_schedules,
            'active_schedules': active_schedules,
            'total_reboots_today': total_reboots_today
        }), 200

    except Exception as e:
        logger.error(f"Error fetching stats API: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e),
            'total_aps': 0,
            'online': 0,
            'offline': 0,
            'unknown': 0,
            'total_schedules': 0,
            'active_schedules': 0,
            'total_reboots_today': 0
        }), 500


@dashboard_bp.route('/api/check-all', methods=['POST'])
def api_check_all():
    """
    Trigger check_all_aps() to update status of all APs.
    Returns JSON success status.
    """
    try:
        results = check_all_aps()
        return jsonify({
            'success': True,
            'message': 'Pemeriksaan status seluruh Access Point berhasil dimulai/selesai.',
            'data': results
        }), 200
    except Exception as e:
        logger.error(f"Error in api_check_all: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'message': f'Gagal memeriksa status Access Point: {str(e)}'
        }), 500


@dashboard_bp.route('/api/reboot-ap/<int:ap_id>', methods=['POST'])
def api_reboot_ap(ap_id):
    """
    Trigger manual_reboot(ap_id) for a single AP.
    Returns JSON result.
    """
    try:
        ap = AccessPoint.query.get(ap_id)
        if not ap:
            return jsonify({
                'success': False,
                'message': f'Access Point dengan ID {ap_id} tidak ditemukan.'
            }), 404

        result = manual_reboot(ap_id)
        is_success = isinstance(result, dict) and result.get('success', False) if isinstance(result, dict) else bool(result)

        return jsonify({
            'success': is_success,
            'ap_id': ap_id,
            'ap_name': ap.name,
            'message': f'Reboot untuk "{ap.name}" telah dieksekusi.',
            'result': result
        }), 200 if is_success else 400

    except Exception as e:
        logger.error(f"Error in api_reboot_ap for ap_id={ap_id}: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'message': f'Gagal mengeksekusi reboot: {str(e)}'
        }), 500


@dashboard_bp.route('/api/check-ap/<int:ap_id>', methods=['POST'])
def api_check_ap(ap_id):
    """
    Trigger check_single_ap(ap_id).
    Returns JSON with updated status.
    """
    try:
        ap = AccessPoint.query.get(ap_id)
        if not ap:
            return jsonify({
                'success': False,
                'message': f'Access Point dengan ID {ap_id} tidak ditemukan.'
            }), 404

        result = check_single_ap(ap_id)
        # Refresh AP from database to retrieve latest status
        db.session.refresh(ap)

        status = getattr(ap, 'status', None)
        if status is None and isinstance(result, dict):
            status = result.get('status', 'unknown')

        return jsonify({
            'success': True,
            'ap_id': ap_id,
            'ap_name': ap.name,
            'status': status,
            'message': f'Status "{ap.name}" berhasil diperbarui: {status}',
            'result': result
        }), 200

    except Exception as e:
        logger.error(f"Error in api_check_ap for ap_id={ap_id}: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'message': f'Gagal memeriksa status Access Point: {str(e)}'
        }), 500
