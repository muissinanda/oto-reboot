"""
Access Points Route Blueprint for OTO REBOOT application.
Handles CRUD operations, filtering, searching, and single/batch reboot triggers for UniFi Access Points.
"""

import logging
from flask import Blueprint, render_template, request, flash, redirect, url_for

from app.extensions import db
from app.models import AccessPoint, Controller, ScheduleAccessPoint, RebootLog
from app.services.ssh_service import manual_reboot, reboot_multiple

logger = logging.getLogger(__name__)

access_points_bp = Blueprint('access_points', __name__, url_prefix='/access-points')


@access_points_bp.route('/', methods=['GET'])
def index():
    """
    List all APs with their controller name and status.
    Supports filtering by controller_id and keyword searching.
    """
    try:
        controller_id = request.args.get('controller_id', type=int)
        search_query = request.args.get('search', '', type=str).strip()

        query = AccessPoint.query

        # Filter by Controller if specified
        if controller_id:
            query = query.filter(AccessPoint.controller_id == controller_id)

        # Filter by search keyword (name or IP)
        if search_query:
            search_pattern = f"%{search_query}%"
            query = query.filter(
                (AccessPoint.name.ilike(search_pattern)) |
                (AccessPoint.ip_address.ilike(search_pattern))
            )

        access_points = query.order_by(AccessPoint.name.asc()).all()
        controllers = Controller.query.order_by(Controller.name.asc()).all()

        return render_template(
            'access_points.html',
            access_points=access_points,
            controllers=controllers,
            selected_controller_id=controller_id,
            search_query=search_query
        )

    except Exception as e:
        logger.error(f"Error listing access points: {str(e)}", exc_info=True)
        flash(f'Gagal memuat data Access Point: {str(e)}', 'danger')
        return render_template(
            'access_points.html',
            access_points=[],
            controllers=[],
            selected_controller_id=None,
            search_query=''
        )


@access_points_bp.route('/add', methods=['POST'])
def add():
    """
    Add a new Access Point.
    Form fields: name, ip_address, controller_id.
    Validates IP uniqueness and field presence.
    """
    name = request.form.get('name', '').strip()
    ip_address = request.form.get('ip_address', '').strip()
    controller_id = request.form.get('controller_id', type=int)

    # Validation
    if not name or not ip_address or not controller_id:
        flash('Nama, Alamat IP, dan Controller wajib diisi.', 'danger')
        return redirect(request.referrer or url_for('access_points.index'))

    # Check Controller existence
    controller = Controller.query.get(controller_id)
    if not controller:
        flash('Controller yang dipilih tidak valid.', 'danger')
        return redirect(request.referrer or url_for('access_points.index'))

    # Validate IP address uniqueness
    existing_ap = AccessPoint.query.filter_by(ip_address=ip_address).first()
    if existing_ap:
        flash(f'Alamat IP {ip_address} sudah digunakan oleh "{existing_ap.name}".', 'danger')
        return redirect(request.referrer or url_for('access_points.index'))

    try:
        new_ap = AccessPoint(
            name=name,
            ip_address=ip_address,
            controller_id=controller_id,
            status='unknown'
        )
        db.session.add(new_ap)
        db.session.commit()
        flash(f'Access Point "{name}" berhasil ditambahkan.', 'success')

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error adding access point: {str(e)}", exc_info=True)
        flash(f'Terjadi kesalahan saat menambahkan Access Point: {str(e)}', 'danger')

    return redirect(request.referrer or url_for('access_points.index'))


@access_points_bp.route('/edit/<int:ap_id>', methods=['POST'])
def edit(ap_id):
    """
    Edit an existing Access Point.
    Form fields: name, ip_address, controller_id.
    Validates IP uniqueness (excluding self).
    """
    ap = AccessPoint.query.get_or_404(ap_id)

    name = request.form.get('name', '').strip()
    ip_address = request.form.get('ip_address', '').strip()
    controller_id = request.form.get('controller_id', type=int)

    if not name or not ip_address or not controller_id:
        flash('Nama, Alamat IP, dan Controller wajib diisi.', 'danger')
        return redirect(request.referrer or url_for('access_points.index'))

    # Check Controller existence
    controller = Controller.query.get(controller_id)
    if not controller:
        flash('Controller yang dipilih tidak valid.', 'danger')
        return redirect(request.referrer or url_for('access_points.index'))

    # Validate IP address uniqueness (exclude current AP)
    existing_ap = AccessPoint.query.filter(
        AccessPoint.ip_address == ip_address,
        AccessPoint.id != ap_id
    ).first()

    if existing_ap:
        flash(f'Alamat IP {ip_address} sudah digunakan oleh "{existing_ap.name}".', 'danger')
        return redirect(request.referrer or url_for('access_points.index'))

    try:
        ap.name = name
        ap.ip_address = ip_address
        ap.controller_id = controller_id

        db.session.commit()
        flash(f'Access Point "{ap.name}" berhasil diperbarui.', 'success')

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating access point {ap_id}: {str(e)}", exc_info=True)
        flash(f'Gagal memperbarui Access Point: {str(e)}', 'danger')

    return redirect(request.referrer or url_for('access_points.index'))


@access_points_bp.route('/delete/<int:ap_id>', methods=['POST'])
def delete(ap_id):
    """
    Delete an Access Point.
    Cleans up associated schedule relations before deletion.
    """
    ap = AccessPoint.query.get_or_404(ap_id)
    ap_name = ap.name

    try:
        # Clean up associated ScheduleAccessPoint records if any
        if hasattr(ScheduleAccessPoint, 'access_point_id'):
            ScheduleAccessPoint.query.filter_by(access_point_id=ap_id).delete()
        elif hasattr(ScheduleAccessPoint, 'ap_id'):
            ScheduleAccessPoint.query.filter_by(ap_id=ap_id).delete()

        db.session.delete(ap)
        db.session.commit()
        flash(f'Access Point "{ap_name}" berhasil dihapus.', 'success')

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting access point {ap_id}: {str(e)}", exc_info=True)
        flash(f'Gagal menghapus Access Point "{ap_name}": {str(e)}', 'danger')

    return redirect(request.referrer or url_for('access_points.index'))


@access_points_bp.route('/reboot/<int:ap_id>', methods=['POST'])
def reboot(ap_id):
    """
    Manual reboot single AP using manual_reboot service.
    """
    ap = AccessPoint.query.get_or_404(ap_id)

    try:
        result = manual_reboot(ap_id)
        is_success = result.get('success', False) if isinstance(result, dict) else bool(result)
        msg = result.get('message', '') if isinstance(result, dict) else ''

        if is_success:
            flash(f'Reboot berhasil dikirim ke AP "{ap.name}". {msg}'.strip(), 'success')
        else:
            flash(f'Gagal melakukan reboot pada AP "{ap.name}": {msg or "Terjadi kesalahan koneksi SSH."}', 'danger')

    except Exception as e:
        logger.error(f"Error triggering reboot for AP {ap_id}: {str(e)}", exc_info=True)
        flash(f'Gagal melakukan reboot pada AP "{ap.name}": {str(e)}', 'danger')

    return redirect(request.referrer or url_for('access_points.index'))


@access_points_bp.route('/reboot-selected', methods=['POST'])
def reboot_selected():
    """
    Reboot multiple selected APs.
    Form field: selected_aps[] (list of AP IDs).
    """
    # Accept selected_aps[] or selected_aps
    raw_ids = request.form.getlist('selected_aps[]') or request.form.getlist('selected_aps')

    selected_ids = []
    for item in raw_ids:
        if isinstance(item, str) and ',' in item:
            selected_ids.extend([int(x.strip()) for x in item.split(',') if x.strip().isdigit()])
        elif str(item).isdigit():
            selected_ids.append(int(item))

    if not selected_ids:
        flash('Silakan pilih minimal satu Access Point untuk direboot.', 'warning')
        return redirect(request.referrer or url_for('access_points.index'))

    try:
        results = reboot_multiple(selected_ids)

        # Parse results format defensively
        if isinstance(results, dict):
            success_count = results.get('success_count', 0)
            fail_count = results.get('failed_count', 0)
        elif isinstance(results, list):
            success_count = sum(1 for r in results if (isinstance(r, dict) and r.get('success')) or r is True)
            fail_count = len(results) - success_count
        else:
            success_count = len(selected_ids)
            fail_count = 0

        if fail_count == 0:
            flash(f'Semua {success_count} Access Point yang dipilih berhasil direboot.', 'success')
        elif success_count > 0:
            flash(f'{success_count} Access Point berhasil direboot, {fail_count} gagal.', 'warning')
        else:
            flash(f'Gagal mereboot {fail_count} Access Point yang dipilih.', 'danger')

    except Exception as e:
        logger.error(f"Error rebooting selected APs: {str(e)}", exc_info=True)
        flash(f'Terjadi kesalahan saat mengeksekusi reboot massal: {str(e)}', 'danger')

    return redirect(request.referrer or url_for('access_points.index'))
