import os
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Float, Text, ForeignKey, BigInteger, event
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

# Standarisasi Waktu ke Waktu Indonesia Barat (WIB / UTC+7)
WIB_TZ = timezone(timedelta(hours=7))

def now_wib():
    """Mengembalikan waktu saat ini dalam zona waktu WIB (UTC+7) naive datetime untuk SQLite"""
    return datetime.now(WIB_TZ).replace(tzinfo=None)

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

# -----------------------------------------------------------------
# OPTIMASI EKSTREM SQLITE WAL & MEMORY PRAGMAS (LIGHTWEIGHT & SAT-SET)
# - WAL Mode: Pembaca & penulis tidak saling mengunci (concurrency instan)
# - Synchronous NORMAL: Write I/O 5-10x lebih kencang tanpa stall
# - Cache 64MB & Memory Temp Store: Query dieksekusi di RAM
# - Memory-mapped I/O (mmap 256MB): Direct memory kernel access
# -----------------------------------------------------------------
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA cache_size=-64000")
        cursor.execute("PRAGMA temp_store=MEMORY")
        cursor.execute("PRAGMA mmap_size=268435456")
        cursor.execute("PRAGMA busy_timeout=5000")
    finally:
        cursor.close()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class AccessPoint(Base):
    __tablename__ = "access_points"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    ip = Column(String(50), unique=True, index=True, nullable=False)
    device_type = Column(String(50), default="unifi", nullable=False) # "unifi" (SSH exec) atau "ruckus" (rkscli shell)
    site = Column(String(100), default="Fasilkom", nullable=False, index=True) # Site / Fakultas (misal: Fasilkom, FT, FEB, Rektorat)
    group = Column(String(50), default="Default", nullable=True) # Sub-lokasi / Grup IP (misal: Lantai 2, 10.132.24.x)
    username = Column(String(50), nullable=True) # Custom SSH username
    password = Column(String(100), nullable=True) # Custom SSH password
    port = Column(Integer, default=22)
    is_online = Column(Boolean, default=False, index=True)
    latency_ms = Column(Float, nullable=True)
    last_checked = Column(DateTime, nullable=True)
    last_rebooted = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True, index=True) # Monitor & reboot enabled
    created_at = Column(DateTime, default=now_wib)

class RebootSchedule(Base):
    __tablename__ = "reboot_schedules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    # Cron fields
    hour = Column(Integer, default=3) # 0 - 23
    minute = Column(Integer, default=0) # 0 - 59
    days_of_week = Column(String(50), default="*") # * or 0,1,2,3,4,5,6 (0=Mon or Mon,Tue..)
    is_enabled = Column(Boolean, default=True, index=True)
    target_type = Column(String(20), default="all") # "all", "group", "selected"
    target_payload = Column(Text, nullable=True) # comma-separated IDs or group name
    last_run = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=now_wib)

class RebootLog(Base):
    __tablename__ = "reboot_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=now_wib, index=True)
    ap_id = Column(Integer, nullable=True)
    ap_name = Column(String(100), nullable=False)
    ap_ip = Column(String(50), nullable=False)
    trigger_type = Column(String(20), default="manual") # manual, scheduled
    schedule_name = Column(String(100), nullable=True)
    status = Column(String(20), nullable=False, index=True) # success, failed
    message = Column(Text, nullable=True)
    duration_ms = Column(Integer, default=0)

class NetworkDevice(Base):
    __tablename__ = "network_devices"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    ip = Column(String(50), unique=True, index=True, nullable=False)
    device_type = Column(String(50), default="mikrotik")  # mikrotik, switch, access_point, generic
    snmp_version = Column(String(10), default="2c")       # 1, 2c
    snmp_community = Column(String(50), default="public")
    snmp_port = Column(Integer, default=161)
    site = Column(String(100), default="Fasilkom", index=True)
    is_active = Column(Boolean, default=True, index=True)
    is_online = Column(Boolean, default=False, index=True)
    uptime = Column(String(50), nullable=True)
    cpu_usage = Column(Float, nullable=True)          # Persentase CPU (0-100%)
    memory_usage = Column(Float, nullable=True)       # Persentase RAM (0-100%)
    memory_total_mb = Column(Float, nullable=True)
    memory_used_mb = Column(Float, nullable=True)
    temperature = Column(Float, nullable=True)        # Derajat Celcius (°C)
    voltage = Column(Float, nullable=True)            # Volt (V)
    model_info = Column(String(255), nullable=True)
    last_polled = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=now_wib)

    # BGP Telemetry Summary
    bgp_peer_count = Column(Integer, default=0)
    bgp_established_count = Column(Integer, default=0)
    bgp_local_as = Column(Integer, nullable=True)
    bgp_router_id = Column(String(50), nullable=True)

    interfaces = relationship("DeviceInterface", back_populates="device", cascade="all, delete-orphan", lazy="joined")
    bgp_peers = relationship("DeviceBgpPeer", back_populates="device", cascade="all, delete-orphan", lazy="joined")

class DeviceBgpPeer(Base):
    __tablename__ = "device_bgp_peers"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("network_devices.id", ondelete="CASCADE"), index=True, nullable=False)
    peer_ip = Column(String(50), nullable=False)           # Peer Remote IP (e.g. 103.241.204.1)
    remote_as = Column(Integer, nullable=True)            # Remote AS (e.g. 13335, 7713)
    as_name = Column(String(100), nullable=True)          # Nama Provider / Organisasi AS
    state = Column(String(50), default="idle")             # established, active, idle, connect, etc.
    admin_status = Column(String(50), default="start")     # start, stop
    in_updates = Column(BigInteger, default=0)
    out_updates = Column(BigInteger, default=0)
    in_total_messages = Column(BigInteger, default=0)
    out_total_messages = Column(BigInteger, default=0)
    fsm_established_time = Column(Integer, default=0)      # Detik session berjalan
    uptime = Column(String(50), nullable=True)             # Human-readable uptime
    accepted_prefixes = Column(Integer, nullable=True)     # Jumlah route / prefix diterima
    interface_name = Column(String(100), nullable=True)    # Interface port (e.g. xe-0/1/0, xe-0/1/2)
    local_ip = Column(String(50), nullable=True)          # Local IP address peering
    description = Column(String(255), nullable=True)
    last_updated = Column(DateTime, nullable=True)

    device = relationship("NetworkDevice", back_populates="bgp_peers")

class DeviceInterface(Base):
    __tablename__ = "device_interfaces"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("network_devices.id", ondelete="CASCADE"), index=True, nullable=False)
    if_index = Column(Integer, nullable=False)
    name = Column(String(100), nullable=False)        # ether1, sfp-sfpplus1, vlan10
    alias = Column(String(255), nullable=True)       # Comment / deskripsi di MikroTik
    if_type = Column(String(50), default="ethernet")  # ethernet, vlan, bridge, backbone, other
    is_up = Column(Boolean, default=False)
    mac_address = Column(String(50), nullable=True)
    speed_mbps = Column(Float, nullable=True)         # Link speed (e.g. 1000 Mbps)
    
    # Counter bytes terakhir (64-bit HC octets)
    rx_bytes = Column(BigInteger, default=0)
    tx_bytes = Column(BigInteger, default=0)
    
    # Real-time traffic rate
    rx_rate_mbps = Column(Float, default=0.0)         # Kecepatan download saat ini (Mbps)
    tx_rate_mbps = Column(Float, default=0.0)         # Kecepatan upload saat ini (Mbps)
    total_rx_gb = Column(Float, default=0.0)
    total_tx_gb = Column(Float, default=0.0)
    last_updated = Column(DateTime, nullable=True)

    # Detail SFP & Optical Diagnostics (DDM)
    is_sfp = Column(Boolean, default=False)
    port_speed = Column(String(50), nullable=True)     # "1G SFP", "10G SFP+", "25G SFP28"
    sfp_vendor = Column(String(100), nullable=True)    # Merk SFP (MikroTik, OEM, Cisco, Finisar)
    sfp_part_number = Column(String(100), nullable=True) # Part number SFP (S+85DLC03D, dll)
    sfp_serial = Column(String(100), nullable=True)    # Serial number
    sfp_wavelength = Column(Integer, nullable=True)    # Panjang gelombang (nm: 1310, 850, 1550)
    sfp_temperature = Column(Float, nullable=True)     # Suhu SFP (°C)
    sfp_voltage = Column(Float, nullable=True)         # Voltase SFP (V)
    sfp_tx_power = Column(Float, nullable=True)        # TX Power (dBm)
    sfp_rx_power = Column(Float, nullable=True)        # Redaman / RX Power (dBm)
    sfp_rx_loss = Column(Boolean, default=False)       # True jika sinyal putus / Loss of Signal
    sfp_tx_fault = Column(Boolean, default=False)      # True jika laser fault

    device = relationship("NetworkDevice", back_populates="interfaces")

class NetworkTrafficHistory(Base):
    __tablename__ = "network_traffic_history"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("network_devices.id", ondelete="CASCADE"), index=True, nullable=True)
    site = Column(String(100), default="Fasilkom", index=True)
    timestamp = Column(DateTime, default=now_wib, index=True)
    rx_mbps = Column(Float, default=0.0)
    tx_mbps = Column(Float, default=0.0)
    total_mbps = Column(Float, default=0.0)
    cpu_usage = Column(Float, nullable=True)
    temperature = Column(Float, nullable=True)

    device = relationship("NetworkDevice")

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
    created_at = Column(DateTime, default=now_wib)

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

            # Migrasi tabel device_interfaces untuk kolom SFP
            res_iface = conn.execute(text("PRAGMA table_info(device_interfaces)")).fetchall()
            iface_cols = [row[1] for row in res_iface]
            sfp_cols = [
                ("is_sfp", "BOOLEAN DEFAULT 0"),
                ("port_speed", "VARCHAR(50)"),
                ("sfp_vendor", "VARCHAR(100)"),
                ("sfp_part_number", "VARCHAR(100)"),
                ("sfp_serial", "VARCHAR(100)"),
                ("sfp_wavelength", "INTEGER"),
                ("sfp_temperature", "FLOAT"),
                ("sfp_voltage", "FLOAT"),
                ("sfp_tx_power", "FLOAT"),
                ("sfp_rx_power", "FLOAT"),
                ("sfp_rx_loss", "BOOLEAN DEFAULT 0"),
                ("sfp_tx_fault", "BOOLEAN DEFAULT 0"),
            ]
            for col_name, col_type in sfp_cols:
                if col_name not in iface_cols:
                    try:
                        conn.execute(text(f"ALTER TABLE device_interfaces ADD COLUMN {col_name} {col_type}"))
                        conn.commit()
                    except Exception:
                        pass

            # Migrasi tabel network_devices untuk kolom BGP
            res_dev = conn.execute(text("PRAGMA table_info(network_devices)")).fetchall()
            dev_cols = [row[1] for row in res_dev]
            bgp_dev_cols = [
                ("bgp_peer_count", "INTEGER DEFAULT 0"),
                ("bgp_established_count", "INTEGER DEFAULT 0"),
                ("bgp_local_as", "INTEGER"),
                ("bgp_router_id", "VARCHAR(50)"),
            ]
            for col_name, col_type in bgp_dev_cols:
                if col_name not in dev_cols:
                    try:
                        conn.execute(text(f"ALTER TABLE network_devices ADD COLUMN {col_name} {col_type}"))
                        conn.commit()
                    except Exception:
                        pass

            # Migrasi tabel device_bgp_peers untuk interface & local_ip
            res_bgp_p = conn.execute(text("PRAGMA table_info(device_bgp_peers)")).fetchall()
            bgp_p_cols = [row[1] for row in res_bgp_p]
            bgp_p_new_cols = [
                ("interface_name", "VARCHAR(100)"),
                ("local_ip", "VARCHAR(50)"),
            ]
            for col_name, col_type in bgp_p_new_cols:
                if col_name not in bgp_p_cols:
                    try:
                        conn.execute(text(f"ALTER TABLE device_bgp_peers ADD COLUMN {col_name} {col_type}"))
                        conn.commit()
                    except Exception:
                        pass

            # Buat indeks pencarian penting di SQLite untuk performa query instan
            perf_indexes = [
                "CREATE INDEX IF NOT EXISTS idx_ap_site ON access_points(site)",
                "CREATE INDEX IF NOT EXISTS idx_ap_active ON access_points(is_active)",
                "CREATE INDEX IF NOT EXISTS idx_ap_online ON access_points(is_online)",
                "CREATE INDEX IF NOT EXISTS idx_netdev_site ON network_devices(site)",
                "CREATE INDEX IF NOT EXISTS idx_netdev_active ON network_devices(is_active)",
                "CREATE INDEX IF NOT EXISTS idx_netdev_online ON network_devices(is_online)",
                "CREATE INDEX IF NOT EXISTS idx_reboot_status ON reboot_logs(status)",
                "CREATE INDEX IF NOT EXISTS idx_sched_enabled ON reboot_schedules(is_enabled)",
                "CREATE INDEX IF NOT EXISTS idx_deviface_devid ON device_interfaces(device_id)",
            ]
            for idx_sql in perf_indexes:
                try:
                    conn.execute(text(idx_sql))
                    conn.commit()
                except Exception:
                    pass
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
        "ping_interval": "300", # detik (5 menit)
        "ping_timeout": "2", # detik
        "app_title": "OTO REBOOT - AP Manager"
    }
    for k, v in default_settings.items():
        if not db.query(AppSetting).filter(AppSetting.key == k).first():
            db.add(AppSetting(key=k, value=v))
    
    # Otomatis update setting lama jika masih 30 detik ke 300 detik (5 menit)
    pi_setting = db.query(AppSetting).filter(AppSetting.key == "ping_interval").first()
    if pi_setting and pi_setting.value == "30":
        pi_setting.value = "300"
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
