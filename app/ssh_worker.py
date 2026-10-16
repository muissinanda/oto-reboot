import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import paramiko
from app.database import SessionLocal, AccessPoint, RebootLog, get_setting

MAX_WORKERS = 25

def reboot_ruckus_shell(ssh, username, password, timeout=10):
    """
    Eksekusi reboot AP Ruckus via interactive shell (rkscli)
    Sesuai script: kirim enter, user, password, tunggu prompt 'rkscli:', lalu kirim 'reboot'
    """
    shell = ssh.invoke_shell()
    time.sleep(1)
    shell.send("\n")
    time.sleep(1)
    shell.send(username + "\n")
    time.sleep(1)
    shell.send(password + "\n")
    time.sleep(2)

    buffer = ""
    for _ in range(10):
        time.sleep(1)
        if shell.recv_ready():
            buffer += shell.recv(1000).decode(errors='ignore')
        if "rkscli:" in buffer:
            break

    if "rkscli:" not in buffer:
        raise Exception(f"Gagal masuk prompt 'rkscli:'. Respon: {buffer.strip()[-150:]}")

    shell.send("reboot\n")
    time.sleep(2)
    output = ""
    if shell.recv_ready():
        output = shell.recv(5000).decode(errors='ignore')
    return output.strip()

def execute_ssh_reboot(ap_id: int, trigger_type: str = "manual", schedule_name: str = None):
    """
    Eksekusi SSH reboot ke 1 AP (UniFi atau Ruckus)
    """
    db = SessionLocal()
    start_time = time.time()
    try:
        ap = db.query(AccessPoint).filter(AccessPoint.id == ap_id).first()
        if not ap:
            return {"status": "error", "message": f"AP dengan ID {ap_id} tidak ditemukan"}

        device_type = getattr(ap, "device_type", "unifi") or "unifi"

        # Ambil konfigurasi SSH default sesuai vendor AP
        if device_type == "ruckus":
            global_user = get_setting(db, "ruckus_ssh_username", "aproot")
            global_pass = get_setting(db, "ruckus_ssh_password", "Asdf123#")
            global_port = int(get_setting(db, "ruckus_ssh_port", "22"))
            global_timeout = int(get_setting(db, "ruckus_ssh_timeout", "10"))
        else:
            global_user = get_setting(db, "ssh_username", "aproot")
            global_pass = get_setting(db, "ssh_password", "Asdf123#")
            global_port = int(get_setting(db, "ssh_port", "22"))
            global_timeout = int(get_setting(db, "ssh_timeout", "5"))

        username = ap.username if ap.username else global_user
        password = ap.password if ap.password else global_pass
        port = ap.port if ap.port else global_port

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            ssh.connect(
                hostname=ap.ip, 
                port=port, 
                username=username, 
                password=password, 
                timeout=global_timeout,
                banner_timeout=global_timeout,
                auth_timeout=global_timeout
            )

            # Eksekusi sesuai tipe perangkat
            if device_type == "ruckus":
                output = reboot_ruckus_shell(ssh, username, password, global_timeout)
                detail_msg = f"Ruckus rkscli reboot sent. Output: {output[:100]}"
            else:
                # Default UniFi / Linux generic
                stdin, stdout, stderr = ssh.exec_command("reboot")
                detail_msg = "Perintah 'reboot' berhasil dikirim via SSH (UniFi/Linux)"

            try:
                ssh.close()
            except Exception:
                pass

            duration_ms = int((time.time() - start_time) * 1000)
            
            # Update AP status & last_rebooted
            ap.last_rebooted = datetime.utcnow()
            
            # Catat log sukses
            log = RebootLog(
                ap_id=ap.id,
                ap_name=ap.name,
                ap_ip=ap.ip,
                trigger_type=trigger_type,
                schedule_name=schedule_name,
                status="success",
                message=detail_msg,
                duration_ms=duration_ms
            )
            db.add(log)
            db.commit()

            return {
                "ap_id": ap.id,
                "name": ap.name,
                "ip": ap.ip,
                "status": "success",
                "message": f"Berhasil reboot ({device_type.upper()})"
            }

        except Exception as e:
            duration_ms = int((time.time() - start_time) * 1000)
            err_msg = str(e)
            
            log = RebootLog(
                ap_id=ap.id,
                ap_name=ap.name,
                ap_ip=ap.ip,
                trigger_type=trigger_type,
                schedule_name=schedule_name,
                status="failed",
                message=f"SSH Error ({device_type.upper()}): {err_msg}",
                duration_ms=duration_ms
            )
            db.add(log)
            db.commit()

            return {
                "ap_id": ap.id,
                "name": ap.name,
                "ip": ap.ip,
                "status": "failed",
                "message": err_msg
            }

    finally:
        db.close()

def reboot_aps_batch(ap_ids: list, trigger_type: str = "manual", schedule_name: str = None):
    """
    Eksekusi reboot untuk banyak AP secara paralel multi-threading
    """
    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [
            executor.submit(execute_ssh_reboot, ap_id, trigger_type, schedule_name)
            for ap_id in ap_ids
        ]
        for f in futures:
            try:
                results.append(f.result())
            except Exception as e:
                results.append({"status": "failed", "message": str(e)})
    return results
