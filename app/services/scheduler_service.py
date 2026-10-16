import logging
from collections import defaultdict
from apscheduler.triggers.cron import CronTrigger
from apscheduler.jobstores.base import JobLookupError
from app.extensions import db, scheduler
from app.models import Schedule, RebootLog
from app.services.ssh_service import reboot_multiple
from app.services.monitor_service import check_all_aps

logger = logging.getLogger(__name__)


def _monitor_job_runner():
    """Background runner for periodic AP monitoring."""
    app = getattr(scheduler, 'app', None)
    if app:
        with app.app_context():
            check_all_aps()
    else:
        check_all_aps()


def _execute_scheduled_reboot_internal(schedule_id):
    """Internal handler to execute scheduled reboots within app context."""
    schedule = Schedule.query.get(schedule_id)
    if not schedule:
        logger.warning("Scheduled job triggered for non-existent schedule %s", schedule_id)
        return

    if not schedule.is_active:
        logger.info("Schedule %s is inactive, skipping reboot", schedule_id)
        return

    logger.info("Executing scheduled reboot for Schedule ID %s (%s)", schedule.id, schedule.name)

    if not schedule.schedule_items:
        logger.info("Schedule %s has no access points assigned", schedule.id)
        return

    aps_by_controller = defaultdict(list)
    for item in schedule.schedule_items:
        ap = item.access_point
        if not ap:
            continue

        ctrl = schedule.controller or ap.controller
        if not ctrl:
            logger.error("No SSH controller found for AP %s (%s)", ap.id, ap.ip_address)
            fail_log = RebootLog(
                access_point_id=ap.id,
                schedule_id=schedule.id,
                triggered_by='scheduled',
                status='failed',
                message='No controller credentials configured for this Access Point'
            )
            db.session.add(fail_log)
        else:
            aps_by_controller[ctrl].append(ap)

    try:
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        logger.error("Error saving initial schedule logs: %s", exc)

    # Reboot access points grouped by controller
    for ctrl, ap_list in aps_by_controller.items():
        reboot_multiple(
            access_points=ap_list,
            controller=ctrl,
            schedule_id=schedule.id,
            triggered_by='scheduled'
        )


def execute_scheduled_reboot(schedule_id):
    """
    Executes a scheduled reboot for all APs associated with a schedule ID.
    Ensures an application context is present.
    """
    app = getattr(scheduler, 'app', None)
    if app:
        with app.app_context():
            _execute_scheduled_reboot_internal(schedule_id)
    else:
        _execute_scheduled_reboot_internal(schedule_id)


def add_schedule_job(schedule):
    """
    Creates and registers an APScheduler cron job from a Schedule model instance.

    :param schedule: Schedule model instance
    :return: True if successfully registered, False otherwise
    """
    job_id = f"schedule_{schedule.id}"
    trigger = None

    if schedule.schedule_type == 'cron' and schedule.cron_expression:
        try:
            trigger = CronTrigger.from_crontab(schedule.cron_expression)
        except Exception as exc:
            logger.error("Invalid crontab expression '%s' for schedule %s: %s",
                         schedule.cron_expression, schedule.id, exc)
            return False
    elif schedule.schedule_type == 'daily':
        trigger = CronTrigger(
            hour=schedule.hour if schedule.hour is not None else 3,
            minute=schedule.minute if schedule.minute is not None else 0
        )
    elif schedule.schedule_type == 'weekly':
        trigger = CronTrigger(
            day_of_week=schedule.day_of_week or 'mon',
            hour=schedule.hour if schedule.hour is not None else 3,
            minute=schedule.minute if schedule.minute is not None else 0
        )
    else:
        logger.warning("Unrecognized schedule configuration for schedule %s (type: %s)",
                       schedule.id, schedule.schedule_type)
        return False

    scheduler.add_job(
        id=job_id,
        func=execute_scheduled_reboot,
        args=[schedule.id],
        trigger=trigger,
        replace_existing=True
    )
    logger.info("Registered job %s with trigger: %s", job_id, trigger)
    return True


def remove_schedule_job(schedule_id):
    """
    Removes a scheduled job by its schedule ID. Handles missing job gracefully.

    :param schedule_id: Schedule ID
    :return: True if removed, False otherwise
    """
    job_id = f"schedule_{schedule_id}"
    try:
        scheduler.remove_job(job_id)
        logger.info("Successfully removed job %s", job_id)
        return True
    except JobLookupError:
        logger.info("Job %s not found in scheduler, skipping removal", job_id)
        return False
    except Exception as exc:
        logger.warning("Error removing job %s: %s", job_id, exc)
        return False


def init_scheduler(app):
    """
    Initializes Flask-APScheduler, registers periodic AP monitoring,
    and loads all active schedules from the database into the scheduler.
    """
    if not scheduler.running:
        scheduler.init_app(app)
        scheduler.start()
        logger.info("APScheduler initialized and started.")

    # Periodic background ping/monitor job
    monitor_interval = app.config.get('MONITOR_INTERVAL', 300)
    scheduler.add_job(
        id='monitor_all_aps',
        func=_monitor_job_runner,
        trigger='interval',
        seconds=monitor_interval,
        replace_existing=True
    )
    logger.info("Registered periodic AP monitoring job every %s seconds", monitor_interval)

    # Load active schedules from database
    with app.app_context():
        try:
            active_schedules = Schedule.query.filter_by(is_active=True).all()
            for schedule in active_schedules:
                try:
                    add_schedule_job(schedule)
                except Exception as exc:
                    logger.error("Failed to load schedule job %s: %s", schedule.id, exc)
            logger.info("Loaded %s active schedules into scheduler", len(active_schedules))
        except Exception as exc:
            logger.error("Error loading active schedules on startup: %s", exc)
