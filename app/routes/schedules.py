"""
Schedules Route Blueprint for OTO REBOOT application.
Handles CRUD operations for reboot schedules, recurring job setup (cron/daily/weekly),
AP mapping, manual execution ('run now'), and toggle active status.
"""

import inspect
import logging
from flask import Blueprint, render_template, request, flash, redirect, url_for

from app.extensions import db
from app.models import Schedule, ScheduleAccessPoint, AccessPoint, Controller
from app.services.scheduler_service import add_schedule_job, remove_schedule_job

logger = logging.getLogger(__name__)

schedules_bp = Blueprint('schedules', __name__, url_prefix='/schedules')


def _safe_add_schedule_job(schedule):
    """
    Safely invoke add_schedule_job supporting either (schedule) or (schedule_id) signature.
    """
    try:
        sig = inspect.signature(add_schedule_job)
        params = list(sig.parameters.keys())
        if params and ('id' in params[0].lower() or 'schedule_id' in params):
            return add_schedule_job(schedule.id)
        else:
            try:
                return add_schedule_job(schedule)
            except TypeError:
                return add_schedule_job(schedule.id)
    except Exception as e:
        logger.error(f"Error adding schedule job for schedule_id={schedule.id}: {str(e)}", exc_info=True)
        return False


def _safe_remove_schedule_job(schedule_id):
    """
    Safely invoke remove_schedule_job without raising uncaught exceptions.
    """
    try:
        return remove_schedule_job(schedule_id)
    except Exception as e:
        logger.error(f"Error removing schedule job for schedule_id={schedule_id}: {str(e)}", exc_info=True)
        return False


def _safe_execute_scheduled_reboot(schedule):
    """
    Executes the scheduled reboot immediately.
    Attempts to import execute_scheduled_reboot from scheduler_service or ssh_service,
    or falls back to rebooting all assigned APs via reboot_multiple.
    """
    func = None
    try:
        from app.services.scheduler_service import execute_scheduled_reboot
        func = execute_scheduled_reboot
    except ImportError:
        try:
            from app.services.ssh_service import execute_scheduled_reboot
            func = execute_scheduled_reboot
        except ImportError:
            func = None

    if func:
        try:
            sig = inspect.signature(func)
            params = list(sig.parameters.keys())
            if params and ('id' in params[0].lower() or 'schedule_id' in params):
                return func(schedule.id)
            else:
                try:
                    return func(schedule)
                except TypeError:
                    return func(schedule.id)
        except Exception as e:
            logger.error(f"Error calling execute_scheduled_reboot: {str(e)}", exc_info=True)
            return {'success': False, 'message': str(e)}
    else:
        # Fallback: manually reboot all assigned APs
        try:
            from app.services.ssh_service import reboot_multiple
            items = ScheduleAccessPoint.query.filter_by(schedule_id=schedule.id).all()
            ap_ids = [
                getattr(item, 'access_point_id', None) or getattr(item, 'ap_id', None)
                for item in items
            ]
            ap_ids = [ap_id for ap_id in ap_ids if ap_id is not None]

            if not ap_ids:
                return {'success': False, 'message': 'Tidak ada Access Point yang terhubung ke jadwal ini.'}

            return reboot_multiple(ap_ids)
        except Exception as e:
            logger.error(f"Fallback reboot failed for schedule_id={schedule.id}: {str(e)}", exc_info=True)
            return {'success': False, 'message': str(e)}


@schedules_bp.route('/', methods=['GET'])
def index():
    """
    List all schedules with their associated AP count and active status.
    Renders schedules.html.
    """
    try:
        schedules = Schedule.query.order_by(Schedule.id.desc()).all()

        # Compute AP count for each schedule
        for schedule in schedules:
            if hasattr(schedule, 'schedule_access_points') and schedule.schedule_access_points is not None:
                schedule.ap_count = len(schedule.schedule_access_points)
            elif hasattr(schedule, 'access_points') and schedule.access_points is not None:
                schedule.ap_count = len(schedule.access_points)
            else:
                schedule.ap_count = ScheduleAccessPoint.query.filter_by(schedule_id=schedule.id).count()

        return render_template('schedules.html', schedules=schedules)

    except Exception as e:
        logger.error(f"Error listing schedules: {str(e)}", exc_info=True)
        flash(f'Gagal memuat daftar Jadwal: {str(e)}', 'danger')
        return render_template('schedules.html', schedules=[])


@schedules_bp.route('/add', methods=['GET'])
def add_form():
    """
    Show add schedule form with list of all APs and controllers.
    Renders schedule_form.html with mode='add'.
    """
    try:
        aps = AccessPoint.query.order_by(AccessPoint.name.asc()).all()
        controllers = Controller.query.order_by(Controller.name.asc()).all()

        return render_template(
            'schedule_form.html',
            mode='add',
            schedule=None,
            aps=aps,
            controllers=controllers,
            selected_ap_ids=[]
        )
    except Exception as e:
        logger.error(f"Error rendering schedule add form: {str(e)}", exc_info=True)
        flash(f'Gagal membuka formulir tambah jadwal: {str(e)}', 'danger')
        return redirect(url_for('schedules.index'))


@schedules_bp.route('/add', methods=['POST'])
def add():
    """
    Create a new schedule.
    Form fields: name, description, schedule_type (daily/weekly/cron),
    hour, minute, day_of_week (comma-separated), cron_expression, is_active,
    selected_aps[] (list of AP ids).
    """
    name = request.form.get('name', '').strip()
    description = request.form.get('description', '').strip()
    schedule_type = request.form.get('schedule_type', 'daily').strip()
    cron_expression = request.form.get('cron_expression', '').strip()

    # Parse hour & minute
    hour = request.form.get('hour', type=int)
    minute = request.form.get('minute', type=int)
    time_str = request.form.get('time', '').strip()
    if (hour is None or minute is None) and time_str and ':' in time_str:
        try:
            parts = time_str.split(':')
            hour = int(parts[0])
            minute = int(parts[1])
        except (ValueError, IndexError):
            pass
    if hour is None:
        hour = 0
    if minute is None:
        minute = 0

    # Parse day_of_week (could be multiple select or comma string)
    dows = request.form.getlist('day_of_week[]') or request.form.getlist('day_of_week')
    if dows:
        day_of_week = ','.join(dows)
    else:
        day_of_week = request.form.get('day_of_week', '').strip()

    # Parse is_active
    is_active = (
        'is_active' in request.form and
        request.form.get('is_active') in ['1', 'true', 'True', 'on', 'yes']
    )

    # Parse selected AP IDs
    raw_aps = request.form.getlist('selected_aps[]') or request.form.getlist('selected_aps')
    selected_ap_ids = []
    for item in raw_aps:
        if isinstance(item, str) and ',' in item:
            selected_ap_ids.extend([int(x.strip()) for x in item.split(',') if x.strip().isdigit()])
        elif str(item).isdigit():
            selected_ap_ids.append(int(item))

    if not name:
        flash('Nama Jadwal wajib diisi.', 'danger')
        return redirect(url_for('schedules.add_form'))

    try:
        new_schedule = Schedule(
            name=name,
            description=description,
            schedule_type=schedule_type,
            hour=hour,
            minute=minute,
            day_of_week=day_of_week,
            cron_expression=cron_expression,
            is_active=is_active
        )
        db.session.add(new_schedule)
        db.session.flush()  # Populate new_schedule.id

        # Insert ScheduleAccessPoint associations
        for ap_id in selected_ap_ids:
            sap_kwargs = {'schedule_id': new_schedule.id}
            if hasattr(ScheduleAccessPoint, 'access_point_id'):
                sap_kwargs['access_point_id'] = ap_id
            elif hasattr(ScheduleAccessPoint, 'ap_id'):
                sap_kwargs['ap_id'] = ap_id
            else:
                sap_kwargs['access_point_id'] = ap_id

            db.session.add(ScheduleAccessPoint(**sap_kwargs))

        db.session.commit()

        # If active, register into APScheduler
        if is_active:
            _safe_add_schedule_job(new_schedule)

        flash(f'Jadwal "{new_schedule.name}" berhasil dibuat.', 'success')
        return redirect(url_for('schedules.index'))

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating schedule: {str(e)}", exc_info=True)
        flash(f'Terjadi kesalahan saat membuat jadwal: {str(e)}', 'danger')
        return redirect(url_for('schedules.add_form'))


@schedules_bp.route('/edit/<int:schedule_id>', methods=['GET'])
def edit_form(schedule_id):
    """
    Show edit form pre-populated with current schedule and assigned APs.
    Renders schedule_form.html with mode='edit'.
    """
    schedule = Schedule.query.get_or_404(schedule_id)

    try:
        aps = AccessPoint.query.order_by(AccessPoint.name.asc()).all()
        controllers = Controller.query.order_by(Controller.name.asc()).all()

        # Retrieve selected AP IDs
        sap_items = ScheduleAccessPoint.query.filter_by(schedule_id=schedule.id).all()
        selected_ap_ids = [
            getattr(item, 'access_point_id', None) or getattr(item, 'ap_id', None)
            for item in sap_items
        ]
        selected_ap_ids = [ap_id for ap_id in selected_ap_ids if ap_id is not None]

        return render_template(
            'schedule_form.html',
            mode='edit',
            schedule=schedule,
            aps=aps,
            controllers=controllers,
            selected_ap_ids=selected_ap_ids
        )
    except Exception as e:
        logger.error(f"Error rendering schedule edit form for schedule_id={schedule_id}: {str(e)}", exc_info=True)
        flash(f'Gagal membuka formulir ubah jadwal: {str(e)}', 'danger')
        return redirect(url_for('schedules.index'))


@schedules_bp.route('/edit/<int:schedule_id>', methods=['POST'])
def edit(schedule_id):
    """
    Update schedule fields, replace associated AP records, and refresh the scheduler job.
    """
    schedule = Schedule.query.get_or_404(schedule_id)

    name = request.form.get('name', '').strip()
    description = request.form.get('description', '').strip()
    schedule_type = request.form.get('schedule_type', 'daily').strip()
    cron_expression = request.form.get('cron_expression', '').strip()

    # Parse hour & minute
    hour = request.form.get('hour', type=int)
    minute = request.form.get('minute', type=int)
    time_str = request.form.get('time', '').strip()
    if (hour is None or minute is None) and time_str and ':' in time_str:
        try:
            parts = time_str.split(':')
            hour = int(parts[0])
            minute = int(parts[1])
        except (ValueError, IndexError):
            pass
    if hour is None:
        hour = schedule.hour or 0
    if minute is None:
        minute = schedule.minute or 0

    # Parse day_of_week
    dows = request.form.getlist('day_of_week[]') or request.form.getlist('day_of_week')
    if dows:
        day_of_week = ','.join(dows)
    else:
        day_of_week = request.form.get('day_of_week', '').strip()

    # Parse is_active
    is_active = (
        'is_active' in request.form and
        request.form.get('is_active') in ['1', 'true', 'True', 'on', 'yes']
    )

    # Parse selected AP IDs
    raw_aps = request.form.getlist('selected_aps[]') or request.form.getlist('selected_aps')
    selected_ap_ids = []
    for item in raw_aps:
        if isinstance(item, str) and ',' in item:
            selected_ap_ids.extend([int(x.strip()) for x in item.split(',') if x.strip().isdigit()])
        elif str(item).isdigit():
            selected_ap_ids.append(int(item))

    if not name:
        flash('Nama Jadwal wajib diisi.', 'danger')
        return redirect(url_for('schedules.edit_form', schedule_id=schedule_id))

    try:
        # Update schedule attributes
        schedule.name = name
        schedule.description = description
        schedule.schedule_type = schedule_type
        schedule.hour = hour
        schedule.minute = minute
        schedule.day_of_week = day_of_week
        schedule.cron_expression = cron_expression
        schedule.is_active = is_active

        # Replace ScheduleAccessPoint items
        ScheduleAccessPoint.query.filter_by(schedule_id=schedule.id).delete()

        for ap_id in selected_ap_ids:
            sap_kwargs = {'schedule_id': schedule.id}
            if hasattr(ScheduleAccessPoint, 'access_point_id'):
                sap_kwargs['access_point_id'] = ap_id
            elif hasattr(ScheduleAccessPoint, 'ap_id'):
                sap_kwargs['ap_id'] = ap_id
            else:
                sap_kwargs['access_point_id'] = ap_id

            db.session.add(ScheduleAccessPoint(**sap_kwargs))

        db.session.commit()

        # Refresh scheduler job
        _safe_remove_schedule_job(schedule.id)
        if schedule.is_active:
            _safe_add_schedule_job(schedule)

        flash(f'Jadwal "{schedule.name}" berhasil diperbarui.', 'success')
        return redirect(url_for('schedules.index'))

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating schedule {schedule_id}: {str(e)}", exc_info=True)
        flash(f'Terjadi kesalahan saat memperbarui jadwal: {str(e)}', 'danger')
        return redirect(url_for('schedules.edit_form', schedule_id=schedule_id))


@schedules_bp.route('/delete/<int:schedule_id>', methods=['POST'])
def delete(schedule_id):
    """
    Delete a schedule and associated items, removing any active job from scheduler.
    """
    schedule = Schedule.query.get_or_404(schedule_id)
    sched_name = schedule.name

    try:
        # Remove from scheduler
        _safe_remove_schedule_job(schedule.id)

        # Remove mapping items
        ScheduleAccessPoint.query.filter_by(schedule_id=schedule.id).delete()

        # Delete schedule
        db.session.delete(schedule)
        db.session.commit()
        flash(f'Jadwal "{sched_name}" berhasil dihapus.', 'success')

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting schedule {schedule_id}: {str(e)}", exc_info=True)
        flash(f'Gagal menghapus jadwal: {str(e)}', 'danger')

    return redirect(url_for('schedules.index'))


@schedules_bp.route('/toggle/<int:schedule_id>', methods=['POST'])
def toggle(schedule_id):
    """
    Toggle is_active on schedule and add/remove job in scheduler accordingly.
    """
    schedule = Schedule.query.get_or_404(schedule_id)

    try:
        schedule.is_active = not schedule.is_active
        db.session.commit()

        if schedule.is_active:
            _safe_add_schedule_job(schedule)
            flash(f'Jadwal "{schedule.name}" berhasil diaktifkan.', 'success')
        else:
            _safe_remove_schedule_job(schedule.id)
            flash(f'Jadwal "{schedule.name}" berhasil dinonaktifkan.', 'warning')

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error toggling schedule {schedule_id}: {str(e)}", exc_info=True)
        flash(f'Gagal mengubah status jadwal: {str(e)}', 'danger')

    return redirect(request.referrer or url_for('schedules.index'))


@schedules_bp.route('/run-now/<int:schedule_id>', methods=['POST'])
def run_now(schedule_id):
    """
    Manually execute the scheduled reboot immediately.
    Calls execute_scheduled_reboot.
    """
    schedule = Schedule.query.get_or_404(schedule_id)

    try:
        result = _safe_execute_scheduled_reboot(schedule)
        is_success = result.get('success', False) if isinstance(result, dict) else bool(result)
        message = result.get('message', '') if isinstance(result, dict) else ''

        if is_success:
            flash(f'Jadwal "{schedule.name}" berhasil dieksekusi sekarang. {message}'.strip(), 'success')
        else:
            flash(f'Gagal mengeksekusi jadwal "{schedule.name}": {message or "Terjadi kesalahan saat reboot."}', 'danger')

    except Exception as e:
        logger.error(f"Error executing run-now for schedule {schedule_id}: {str(e)}", exc_info=True)
        flash(f'Terjadi kesalahan saat mengeksekusi reboot jadwal: {str(e)}', 'danger')

    return redirect(request.referrer or url_for('schedules.index'))
