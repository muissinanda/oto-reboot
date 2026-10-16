import os
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Float, Text
from sqlalchemy.orm import declarative_base, sessionmaker

# Menentukan lokasi database SQLite di folder data
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.environ.get("DATA_DIR", os.path.join(BASE_DIR, "data"))
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "oto_reboot.db")
DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(
    DATABASE_URL, 
    connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class AccessPoint(Base):
    __tablename__ = "access_points"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    ip = Column(String(50), unique=True, index=True, nullable=False)
    device_type = Column(String(50), default="unifi", nullable=False) # "unifi" (SSH exec) atau "ruckus" (rkscli shell)
    site = Column(String(100), default="Fasilkom", nullable=False) # Site / Fakultas (misal: Fasilkom, FT, FEB, Rektorat)
    group = Column(String(50), default="Default", nullable=True) # Sub-lokasi / Grup IP (misal: Lantai 2, 10.132.24.x)
    username = Column(String(50), nullable=True) # Custom SSH username
    password = Column(String(100), nullable=True) # Custom SSH password
    port = Column(Integer, default=22)
    is_online = Column(Boolean, default=False)
    latency_ms = Column(Float, nullable=True)
    last_checked = Column(DateTime, nullable=True)
    last_rebooted = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True) # Monitor & reboot enabled
    created_at = Column(DateTime, default=datetime.utcnow)

class RebootSchedule(Base):
    __tablename__ = "reboot_schedules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    # Cron fields
    hour = Column(Integer, default=3) # 0 - 23
    minute = Column(Integer, default=0) # 0 - 59
    days_of_week = Column(String(50), default="*") # * or 0,1,2,3,4,5,6 (0=Mon or Mon,Tue..)
    is_enabled = Column(Boolean, default=True)
    target_type = Column(String(20), default="all") # "all", "group", "selected"
    target_payload = Column(Text, nullable=True) # comma-separated IDs or group name
    last_run = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class RebootLog(Base):
    __tablename__ = "reboot_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    ap_id = Column(Integer, nullable=True)
    ap_name = Column(String(100), nullable=False)
    ap_ip = Column(String(50), nullable=False)
    trigger_type = Column(String(20), default="manual") # manual, scheduled
    schedule_name = Column(String(100), nullable=True)
    status = Column(String(20), nullable=False) # success, failed
    message = Column(Text, nullable=True)
    duration_ms = Column(Integer, default=0)

import hashlib
import secrets

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    hashed = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}:{hashed}"

def verify_password(password: str, stored_hash: str) -> bool:
    if not stored_hash or ":" not in stored_hash:
        return False
    salt, original_hash = stored_hash.split(":", 1)
    return hashlib.sha256((salt + password).encode()).hexdigest() == original_hash

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=True) # Email akun Google
    google_id = Column(String(100), unique=True, index=True, nullable=True) # Google OAuth Sub ID
    avatar_url = Column(String(300), nullable=True) # Foto profil Google
    full_name = Column(String(100), nullable=False)
    password_hash = Column(String(200), nullable=True) # Nullable jika login murni via Google
    role = Column(String(20), default="site_admin", nullable=False) # "superadmin" atau "site_admin"
    allowed_sites = Column(Text, default="*", nullable=False) # "*" untuk all, atau koma "Fasilkom,Fakultas Teknik"
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class AppSetting(Base):
    __tablename__ = "app_settings"

    key = Column(String(50), primary_key=True)
    value = Column(Text, nullable=False)

def init_db():
    Base.metadata.create_all(bind=engine)
    
    # SQLite schema migration untuk kolom baru
    with engine.connect() as conn:
        try:
            from sqlalchemy import text
            res_ap = conn.execute(text("PRAGMA table_info(access_points)")).fetchall()
            ap_cols = [row[1] for row in res_ap]
            if "site" not in ap_cols:
                conn.execute(text("ALTER TABLE access_points ADD COLUMN site VARCHAR(100) DEFAULT 'Fasilkom'"))
                conn.commit()
            if "device_type" not in ap_cols:
                conn.execute(text("ALTER TABLE access_points ADD COLUMN device_type VARCHAR(50) DEFAULT 'unifi'"))
                conn.commit()

            # Migrasi tabel users
            res_usr = conn.execute(text("PRAGMA table_info(users)")).fetchall()
            usr_cols = [row[1] for row in res_usr]
            if "email" not in usr_cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN email VARCHAR(100)"))
                conn.commit()
            if "google_id" not in usr_cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN google_id VARCHAR(100)"))
                conn.commit()
            if "avatar_url" not in usr_cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN avatar_url VARCHAR(300)"))
                conn.commit()
        except Exception:
            pass

    db = SessionLocal()
    try:
        db.query(AccessPoint).filter((AccessPoint.site == None) | (AccessPoint.site == "")).update({"site": "Fasilkom"})
        db.query(AccessPoint).filter((AccessPoint.device_type == None) | (AccessPoint.device_type == "")).update({"device_type": "unifi"})
        db.commit()
    except Exception:
        pass
    # Seed default superadmin jika belum ada user
    if db.query(User).count() == 0:
        admin_user = User(
            username="admin",
            full_name="Super Administrator",
            password_hash=hash_password("admin123"),
            role="superadmin",
            allowed_sites="*",
            is_active=True
        )
        db.add(admin_user)
        db.commit()

    # Default settings jika belum ada
    default_settings = {
        "ssh_username": "aproot",
        "ssh_password": "Asdf123#",
        "ssh_port": "22",
        "ssh_timeout": "5",
        "ruckus_ssh_username": "aproot",
        "ruckus_ssh_password": "Asdf123#",
        "ruckus_ssh_port": "22",
        "ruckus_ssh_timeout": "10",
        "google_oauth_enabled": "0",
        "google_client_id": "",
        "google_client_secret": "",
        "google_default_site": "Fasilkom",
        "ping_interval": "30", # detik
        "ping_timeout": "2", # detik
        "app_title": "OTO REBOOT - AP Manager"
    }
    for k, v in default_settings.items():
        if not db.query(AppSetting).filter(AppSetting.key == k).first():
            db.add(AppSetting(key=k, value=v))
    db.commit()
    db.close()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_setting(db, key: str, default: str = ""):
    row = db.query(AppSetting).filter(AppSetting.key == key).first()
    return row.value if row else default

def set_setting(db, key: str, value: str):
    row = db.query(AppSetting).filter(AppSetting.key == key).first()
    if row:
        row.value = value
    else:
        db.add(AppSetting(key=key, value=value))
    db.commit()
