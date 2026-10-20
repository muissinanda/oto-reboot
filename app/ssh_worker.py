import time
import subprocess
import shutil
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import paramiko
from paramiko.transport import Transport
from app.database import SessionLocal, AccessPoint, RebootLog, get_setting

# Daftarkan KEX dan Host Key legacy hanya jika didukung oleh modul internal Paramiko (mencegah KeyError)
for kex_algo in ("diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha1"):
    if hasattr(Transport, "_kex_info") and kex_algo in Transport._kex_info and kex_algo not in Transport._preferred_kex:
        Transport._preferred_kex = (kex_algo,) + Transport._preferred_kex

for key_algo in ("ssh-rsa", "ssh-dss"):
    if hasattr(Transport, "_key_info") and key_algo in Transport._key_info and key_algo not in Transport._preferred_keys:
        Transport._preferred_keys = (key_algo,) + Transport._preferred_keys

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

def reboot_via_system_ssh(ip: str, port: int, username: str, password: str, device_type: str = "unifi", timeout: int = 10):
    """
    Fallback reboot menggunakan system OpenSSH client + sshpass.
    Sangat andal untuk Dropbear UniFi firmware lama yang menggunakan KEX diffie-hellman-group14-sha1 & ssh-rsa.
    """
    if not shutil.which("sshpass"):
        return False, "sshpass belum tersedia di sistem"

    if device_type == "ruckus":
        return False, "Ruckus menggunakan interactive rkscli shell"

    cmd = [
        "sshpass", "-p", password,
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group1-sha1,diffie-hellman-group-exchange-sha1",
        "-o", "HostKeyAlgorithms=+ssh-rsa,ssh-dss",
        "-o", "PubkeyAcceptedKeyTypes=+ssh-rsa",
        "-o", f"ConnectTimeout={timeout}",
        "-p", str(port),
        f"{username}@{ip}",
        "reboot"
    ]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 3)
        out = (proc.stdout + " " + proc.stderr).lower()
        if proc.returncode == 0 or "closed by remote host" in out or "connection reset" in out:
            return True, "Reboot terkirim via OpenSSH Fallback (Dropbear legacy compatible)"
        return False, proc.stderr.strip() or proc.stdout.strip() or f"Exit code {proc.returncode}"
    except subprocess.TimeoutExpired:
        return True, "Reboot terkirim (AP memutus koneksi saat reboot)"
    except Exception as ex:
        return False, str(ex)

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
            try:
                ssh.connect(
                    hostname=ap.ip, 
                    port=port, 
                    username=username, 
                    password=password, 
                    timeout=global_timeout,
                    banner_timeout=global_timeout,
                    auth_timeout=global_timeout,
                    look_for_keys=False,
                    allow_agent=False
                )
            except Exception as conn_err:
                err_str = str(conn_err).lower()
                # Jika error cipher / algorithm mismatch (Dropbear pada UniFi lama), coba fallback disabled_algorithms
                if "incompatible" in err_str or "algorithm" in err_str or "key" in err_str:
                    ssh.connect(
                        hostname=ap.ip, 
                        port=port, 
                        username=username, 
                        password=password, 
                        timeout=global_timeout,
                        banner_timeout=global_timeout,
                        auth_timeout=global_timeout,
                        look_for_keys=False,
                        allow_agent=False,
                        disabled_algorithms={"pubkeys": ["rsa-sha2-512", "rsa-sha2-256"]}
                    )
                else:
                    raise conn_err

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
            # Jika paramiko mengalami kendala KEX/cipher mismatch pada Dropbear, gunakan fallback OpenSSH + sshpass
            fb_ok, fb_msg = reboot_via_system_ssh(ap.ip, port, username, password, device_type, global_timeout)
            duration_ms = int((time.time() - start_time) * 1000)

            if fb_ok:
                ap.last_rebooted = datetime.utcnow()
                log = RebootLog(
                    ap_id=ap.id,
                    ap_name=ap.name,
                    ap_ip=ap.ip,
                    trigger_type=trigger_type,
                    schedule_name=schedule_name,
                    status="success",
                    message=f"Reboot berhasil ({device_type.upper()} via OpenSSH Fallback: {fb_msg})",
                    duration_ms=duration_ms
                )
                db.add(log)
                db.commit()

                return {
                    "ap_id": ap.id,
                    "name": ap.name,
                    "ip": ap.ip,
                    "status": "success",
                    "message": f"Berhasil reboot ({device_type.upper()} via OpenSSH)"
                }

            err_msg = str(e)
            log = RebootLog(
                ap_id=ap.id,
                ap_name=ap.name,
                ap_ip=ap.ip,
                trigger_type=trigger_type,
                schedule_name=schedule_name,
                status="failed",
                message=f"SSH Error ({device_type.upper()}): {err_msg} | Fallback: {fb_msg}",
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
