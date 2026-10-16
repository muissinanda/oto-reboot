"""
Logs Route Blueprint for OTO REBOOT application.
Handles reboot logs viewing with pagination, multi-attribute filtering,
log deletion/cleanup, and CSV export.
"""

import csv
import io
import logging
from datetime import datetime, time, timedelta
from flask import Blueprint, render_template, request, flash, redirect, url_for, Response

from app.extensions import db
from app.models import RebootLog, AccessPoint

logger = logging.getLogger(__name__)

logs_bp = Blueprint('logs', __name__, url_prefix='/logs')


def _build_filtered_logs_query():
    """
    Helper function to build a RebootLog query based on request GET parameters:
    date_from, date_to, status, triggered_by, ap_id.
    """
    query = RebootLog.query

    date_from_str = request.args.get('date_from', '').strip()
    date_to_str = request.args.get('date_to', '').strip()
    status = request.args.get('status', '').strip()
    triggered_by = request.args.get('triggered_by', '').strip()
    ap_id = request.args.get('ap_id', type=int)

    # Filter date from
    if date_from_str:
        try:
            date_from = datetime.strptime(date_from_str, '%Y-%m-%d')
            query = query.filter(RebootLog.executed_at >= date_from)
        except ValueError:
            logger.warning(f"Invalid date_from format: {date_from_str}")

    # Filter date to
    if date_to_str:
        try:
            date_to = datetime.strptime(date_to_str, '%Y-%m-%d')
            date_to = datetime.combine(date_to.date(), time.max)
            query = query.filter(RebootLog.executed_at <= date_to)
        except ValueError:
            logger.warning(f"Invalid date_to format: {date_to_str}")

    # Filter status
    if status and status.lower() != 'all':
        query = query.filter(db.func.lower(RebootLog.status) == status.lower())

    # Filter triggered_by
    if triggered_by and triggered_by.lower() != 'all':
        query = query.filter(db.func.lower(RebootLog.triggered_by) == triggered_by.lower())

    # Filter AP ID
    if ap_id:
        if hasattr(RebootLog, 'access_point_id'):
            query = query.filter(RebootLog.access_point_id == ap_id)
        elif hasattr(RebootLog, 'ap_id'):
            query = query.filter(RebootLog.ap_id == ap_id)

    return query


@logs_bp.route('/', methods=['GET'])
def index():
    """
    List all reboot logs with pagination (25 per page).
    Shows AP name, IP, triggered_by, status, message, executed_at.
    Supports filters: date_from, date_to, status, triggered_by, ap_id.
    Renders logs.html.
    """
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 25

        query = _build_filtered_logs_query()
        query = query.order_by(RebootLog.executed_at.desc(), RebootLog.id.desc())

        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        logs = pagination.items

        # Ensure AP object is accessible on each log
        for log in logs:
            if not getattr(log, 'access_point', None):
                target_ap_id = getattr(log, 'access_point_id', None) or getattr(log, 'ap_id', None)
                if target_ap_id:
                    ap = AccessPoint.query.get(target_ap_id)
                    log.access_point = ap
                    log.ap = ap

        aps = AccessPoint.query.order_by(AccessPoint.name.asc()).all()

        filters = {
            'date_from': request.args.get('date_from', '').strip(),
            'date_to': request.args.get('date_to', '').strip(),
            'status': request.args.get('status', '').strip(),
            'triggered_by': request.args.get('triggered_by', '').strip(),
            'ap_id': request.args.get('ap_id', type=int) or ''
        }

        return render_template(
            'logs.html',
            logs=logs,
            pagination=pagination,
            aps=aps,
            filters=filters
        )

    except Exception as e:
        logger.error(f"Error fetching reboot logs: {str(e)}", exc_info=True)
        flash(f'Gagal memuat log reboot: {str(e)}', 'danger')
        return render_template(
            'logs.html',
            logs=[],
            pagination=None,
            aps=[],
            filters={}
        )


@logs_bp.route('/clear', methods=['POST'])
def clear():
    """
    Clear reboot logs.
    Supports clearing all logs or logs older than X days.
    """
    try:
        days = request.form.get('days', type=int)

        if days and days > 0:
            cutoff = datetime.utcnow() - timedelta(days=days)
            deleted = RebootLog.query.filter(RebootLog.executed_at < cutoff).delete(synchronize_session=False)
            db.session.commit()
            flash(f'Berhasil menghapus {deleted} log reboot yang lebih lama dari {days} hari.', 'success')
        else:
            deleted = RebootLog.query.delete(synchronize_session=False)
            db.session.commit()
            flash(f'Berhasil menghapus seluruh log reboot ({deleted} rekaman).', 'success')

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error clearing logs: {str(e)}", exc_info=True)
        flash(f'Terjadi kesalahan saat membersihkan log: {str(e)}', 'danger')

    return redirect(url_for('logs.index'))


@logs_bp.route('/export', methods=['GET'])
def export():
    """
    Export reboot logs as CSV download.
    Applies any active query filters.
    """
    try:
        query = _build_filtered_logs_query()
        query = query.order_by(RebootLog.executed_at.desc(), RebootLog.id.desc())
        logs = query.all()

        # Cache APs to minimize queries during export
        ap_cache = {ap.id: ap for ap in AccessPoint.query.all()}

        output = io.StringIO()
        writer = csv.writer(output)

        # Header row
        writer.writerow([
            'Log ID',
            'Access Point Name',
            'IP Address',
            'Triggered By',
            'Status',
            'Message',
            'Executed At'
        ])

        for log in logs:
            target_ap_id = getattr(log, 'access_point_id', None) or getattr(log, 'ap_id', None)
            ap = getattr(log, 'access_point', None) or ap_cache.get(target_ap_id)

            ap_name = ap.name if ap else (f"AP ID #{target_ap_id}" if target_ap_id else '-')
            ap_ip = ap.ip_address if ap else '-'
            exec_time = log.executed_at.strftime('%Y-%m-%d %H:%M:%S') if getattr(log, 'executed_at', None) else '-'

            writer.writerow([
                log.id,
                ap_name,
                ap_ip,
                log.triggered_by or '-',
                log.status or '-',
                log.message or '',
                exec_time
            ])

        csv_content = output.getvalue()
        filename = f"reboot_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

        return Response(
            csv_content,
            mimetype='text/csv',
            headers={
                'Content-Disposition': f'attachment; filename="{filename}"',
                'Content-Type': 'text/csv; charset=utf-8'
            }
        )

    except Exception as e:
        logger.error(f"Error exporting logs to CSV: {str(e)}", exc_info=True)
        flash(f'Gagal mengekspor log ke format CSV: {str(e)}', 'danger')
        return redirect(url_for('logs.index'))
