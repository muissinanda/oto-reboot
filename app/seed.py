"""
Seed data awal berdasarkan daftar IP Access Point pengguna (UniFi & Ruckus)
"""
from app.database import SessionLocal, AccessPoint

INITIAL_APS = [
    # 10.132.24.x
    {"ip": "10.132.24.95", "name": "AP Fasilkom 24.95", "group": "Fasilkom 24", "site": "Fasilkom", "device_type": "unifi"},
    {"ip": "10.132.24.98", "name": "AP Fasilkom 24.98", "group": "Fasilkom 24", "site": "Fasilkom", "device_type": "unifi"},
    {"ip": "10.132.24.99", "name": "AP Fasilkom 24.99", "group": "Fasilkom 24", "site": "Fasilkom", "device_type": "unifi"},
    {"ip": "10.132.24.102", "name": "AP Fasilkom 24.102", "group": "Fasilkom 24", "site": "Fasilkom", "device_type": "unifi"},
    {"ip": "10.132.24.103", "name": "AP Fasilkom 24.103", "group": "Fasilkom 24", "site": "Fasilkom", "device_type": "unifi"},
    {"ip": "10.132.24.104", "name": "AP Fasilkom 24.104", "group": "Fasilkom 24", "site": "Fasilkom", "device_type": "unifi"},
    {"ip": "10.132.24.105", "name": "AP Fasilkom 24.105", "group": "Fasilkom 24", "site": "Fasilkom", "device_type": "unifi"},
    {"ip": "10.132.24.106", "name": "AP Fasilkom 24.106", "group": "Fasilkom 24", "site": "Fasilkom", "device_type": "unifi"},
    {"ip": "10.132.24.108", "name": "AP Fasilkom 24.108", "group": "Fasilkom 24", "site": "Fasilkom", "device_type": "unifi"},
    {"ip": "10.132.24.109", "name": "AP Fasilkom 24.109", "group": "Fasilkom 24", "site": "Fasilkom", "device_type": "unifi"},
    {"ip": "10.132.24.110", "name": "AP Fasilkom 24.110", "group": "Fasilkom 24", "site": "Fasilkom", "device_type": "unifi"},
    {"ip": "10.132.24.111", "name": "AP Fasilkom 24.111", "group": "Fasilkom 24", "site": "Fasilkom", "device_type": "unifi"},
    {"ip": "10.132.24.112", "name": "AP Fasilkom 24.112", "group": "Fasilkom 24", "site": "Fasilkom", "device_type": "unifi"},
    {"ip": "10.132.24.113", "name": "AP Fasilkom 24.113", "group": "Fasilkom 24", "site": "Fasilkom", "device_type": "unifi"},
    {"ip": "10.132.24.115", "name": "AP Fasilkom 24.115", "group": "Fasilkom 24", "site": "Fasilkom", "device_type": "unifi"},
    {"ip": "10.132.24.116", "name": "AP Fasilkom 24.116", "group": "Fasilkom 24", "site": "Fasilkom", "device_type": "unifi"},
    {"ip": "10.132.24.117", "name": "AP Fasilkom 24.117", "group": "Fasilkom 24", "site": "Fasilkom", "device_type": "unifi"},
    {"ip": "10.132.24.118", "name": "AP Fasilkom 24.118", "group": "Fasilkom 24", "site": "Fasilkom", "device_type": "unifi"},
    {"ip": "10.132.24.120", "name": "AP Fasilkom 24.120", "group": "Fasilkom 24", "site": "Fasilkom", "device_type": "unifi"},
    {"ip": "10.132.24.121", "name": "AP Fasilkom 24.121", "group": "Fasilkom 24", "site": "Fasilkom", "device_type": "unifi"},
    {"ip": "10.132.24.122", "name": "AP Fasilkom 24.122", "group": "Fasilkom 24", "site": "Fasilkom", "device_type": "unifi"},
    {"ip": "10.132.24.126", "name": "AP Fasilkom 24.126", "group": "Fasilkom 24", "site": "Fasilkom", "device_type": "unifi"},

    # 10.132.25.x
    {"ip": "10.132.25.103", "name": "AP Fasilkom 25.103", "group": "Fasilkom 25", "site": "Fasilkom", "device_type": "unifi"},
    {"ip": "10.132.25.104", "name": "AP Fasilkom 25.104", "group": "Fasilkom 25", "site": "Fasilkom", "device_type": "unifi"},
    {"ip": "10.132.25.106", "name": "AP Fasilkom 25.106", "group": "Fasilkom 25", "site": "Fasilkom", "device_type": "unifi"},
    {"ip": "10.132.25.107", "name": "AP Fasilkom 25.107", "group": "Fasilkom 25", "site": "Fasilkom", "device_type": "unifi"},
    {"ip": "10.132.25.109", "name": "AP Fasilkom 25.109", "group": "Fasilkom 25", "site": "Fasilkom", "device_type": "unifi"},
    {"ip": "10.132.25.111", "name": "AP Fasilkom 25.111", "group": "Fasilkom 25", "site": "Fasilkom", "device_type": "unifi"},
    {"ip": "10.132.25.112", "name": "AP Fasilkom 25.112", "group": "Fasilkom 25", "site": "Fasilkom", "device_type": "unifi"},
    {"ip": "10.132.25.114", "name": "AP Fasilkom 25.114", "group": "Fasilkom 25", "site": "Fasilkom", "device_type": "unifi"},
    {"ip": "10.132.25.115", "name": "AP Fasilkom 25.115", "group": "Fasilkom 25", "site": "Fasilkom", "device_type": "unifi"},
    {"ip": "10.132.25.116", "name": "AP Fasilkom 25.116", "group": "Fasilkom 25", "site": "Fasilkom", "device_type": "unifi"},
    {"ip": "10.132.25.117", "name": "AP Fasilkom 25.117", "group": "Fasilkom 25", "site": "Fasilkom", "device_type": "unifi"},
    {"ip": "10.132.25.118", "name": "AP Fasilkom 25.118", "group": "Fasilkom 25", "site": "Fasilkom", "device_type": "unifi"},
    {"ip": "10.132.25.119", "name": "AP Fasilkom 25.119", "group": "Fasilkom 25", "site": "Fasilkom", "device_type": "unifi"},
    {"ip": "10.132.25.120", "name": "AP Fasilkom 25.120", "group": "Fasilkom 25", "site": "Fasilkom", "device_type": "unifi"},
    {"ip": "10.132.25.121", "name": "AP Fasilkom 25.121", "group": "Fasilkom 25", "site": "Fasilkom", "device_type": "unifi"},
    {"ip": "10.132.25.122", "name": "AP Fasilkom 25.122", "group": "Fasilkom 25", "site": "Fasilkom", "device_type": "unifi"},
    {"ip": "10.132.25.123", "name": "AP Fasilkom 25.123", "group": "Fasilkom 25", "site": "Fasilkom", "device_type": "unifi"},
    {"ip": "10.132.25.124", "name": "AP Fasilkom 25.124", "group": "Fasilkom 25", "site": "Fasilkom", "device_type": "unifi"},
    {"ip": "10.132.25.125", "name": "AP Fasilkom 25.125", "group": "Fasilkom 25", "site": "Fasilkom", "device_type": "unifi"},
]

RUCKUS_APS = [
    "10.154.10.4", "10.154.10.6", "10.154.10.17", "10.154.154.148",
    "10.154.10.19", "10.154.10.20", "10.154.10.5", "10.154.10.18",
    "10.154.10.14", "10.154.10.25", "10.154.10.78", "10.154.10.15",
    "10.154.10.27", "10.154.10.13", "10.154.10.26", "10.154.10.2",
    "10.154.10.29", "10.154.10.16", "10.154.10.31", "10.154.10.30",
    "10.154.10.40", "10.154.10.8", "10.133.100.28"
]

def seed_initial_aps():
    db = SessionLocal()
    try:
        # Seed UniFi APs
        for item in INITIAL_APS:
            if not db.query(AccessPoint).filter(AccessPoint.ip == item["ip"]).first():
                ap = AccessPoint(
                    name=item["name"],
                    ip=item["ip"],
                    site=item["site"],
                    group=item["group"],
                    device_type=item["device_type"]
                )
                db.add(ap)

        # Seed Ruckus APs (Site: Ruckus Zone)
        for ip in RUCKUS_APS:
            if not db.query(AccessPoint).filter(AccessPoint.ip == ip).first():
                ap = AccessPoint(
                    name=f"AP Ruckus {ip.split('.')[-1]}",
                    ip=ip,
                    site="Ruckus Zone",
                    group="Ruckus APs",
                    device_type="ruckus"
                )
                db.add(ap)

        db.commit()
    finally:
        db.close()
