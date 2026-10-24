from datetime import datetime
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from app.database import SessionLocal, RebootSchedule, AccessPoint, get_setting, now_wib
from app.ssh_worker import reboot_aps_batch
from app.monitor import run_monitor_cycle
from app.snmp_service import run_nms_poll_cycle
from app.services.latency_service import update_services_health_background

scheduler = AsyncIOScheduler()

def execute_scheduled_reboot(schedule_id: int):
    """
    Eksekusi jadwal reboot otomatis yang dipicu oleh APScheduler
    """
    db = SessionLocal()
    try:
        schedule = db.query(RebootSchedule).filter(RebootSchedule.id == schedule_id).first()
        if not schedule or not schedule.is_enabled:
            return

        # Tentukan target APs
        target_aps = []
        if schedule.target_type == "all":
            target_aps = db.query(AccessPoint).filter(AccessPoint.is_active == True).all()
        elif schedule.target_type == "site":
            target_aps = db.query(AccessPoint).filter(
                AccessPoint.is_active == True,
                AccessPoint.site == schedule.target_payload
            ).all()
        elif schedule.target_type == "group":
            target_aps = db.query(AccessPoint).filter(
                AccessPoint.is_active == True,
                AccessPoint.group == schedule.target_payload
            ).all()
        elif schedule.target_type == "selected":
            try:
                ids = [int(x.strip()) for x in schedule.target_payload.split(",") if x.strip().isdigit()]
                target_aps = db.query(AccessPoint).filter(
                    AccessPoint.is_active == True,
                    AccessPoint.id.in_(ids)
                ).all()
            except Exception:
                target_aps = []

        ap_ids = [ap.id for ap in target_aps]
        if ap_ids:
            reboot_aps_batch(ap_ids, trigger_type="scheduled", schedule_name=schedule.name)

        schedule.last_run = now_wib()
        db.commit()
    finally:
        db.close()

def reload_scheduler_jobs():
    """
    Muat ulang semua jadwal aktif dari database ke APScheduler
    """
    # Bersihkan job jadwal reboot lama (kecuali monitor job)
    for job in scheduler.get_jobs():
        if job.id.startswith("schedule_"):
            scheduler.remove_job(job.id)

    db = SessionLocal()
    try:
        schedules = db.query(RebootSchedule).filter(RebootSchedule.is_enabled == True).all()
        for s in schedules:
            job_id = f"schedule_{s.id}"
            
            # Days of week parsing
            day_of_week = s.days_of_week if s.days_of_week and s.days_of_week != "*" else None
            
            trigger = CronTrigger(
                hour=s.hour,
                minute=s.minute,
                day_of_week=day_of_week
            )
            scheduler.add_job(
                execute_scheduled_reboot,
                trigger=trigger,
                id=job_id,
                name=s.name,
                args=[s.id],
                replace_existing=True
            )
    finally:
        db.close()

def update_monitor_interval(interval_sec: int):
    """
    Update interval waktu ping probe monitor secara dinamis saat setting diubah
    """
    if scheduler.running:
        try:
            scheduler.reschedule_job(
                "ap_monitor_job",
                trigger=IntervalTrigger(seconds=interval_sec)
            )
        except Exception:
            scheduler.add_job(
                run_monitor_cycle,
                trigger=IntervalTrigger(seconds=interval_sec),
                id="ap_monitor_job",
                name="AP Status Ping Monitor",
                replace_existing=True
            )

def setup_scheduler():
    """
    Inisialisasi background monitor & scheduler
    """
    if not scheduler.running:
        db = SessionLocal()
        interval_sec = int(get_setting(db, "ping_interval", "300"))
        db.close()

        # Job 1: Monitor Status AP (Default 300 detik = 5 menit)
        scheduler.add_job(
            run_monitor_cycle,
            trigger=IntervalTrigger(seconds=interval_sec),
            id="ap_monitor_job",
            name="AP Status Ping Monitor",
            replace_existing=True
        )

        # Job 2: Muat jadwal reboot
        reload_scheduler_jobs()

        # Job 3: NMS SNMP Traffic & Health Monitor (setiap 60 detik)
        scheduler.add_job(
            run_nms_poll_cycle,
            trigger=IntervalTrigger(seconds=60),
            id="nms_snmp_monitor_job",
            name="SNMP Traffic & Health Poller",
            replace_existing=True
        )

        # Job 4: Latensi Global & Health Layanan UNEJ (setiap 30 detik di background)
        scheduler.add_job(
            update_services_health_background,
            trigger=IntervalTrigger(seconds=30),
            id="services_health_job",
            name="Global Latency & UNEJ Services Poller",
            replace_existing=True
        )

        scheduler.start()
