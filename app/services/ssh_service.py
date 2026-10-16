import logging
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import paramiko
from app.extensions import db
from app.models import AccessPoint, RebootLog

logger = logging.getLogger(__name__)


def reboot_ap(ip, username, password, timeout=10):
    """
    Connect to an Access Point via SSH and execute the 'reboot' command.

    :param ip: IP address of the access point
    :param username: SSH username
    :param password: SSH password
    :param timeout: Connection and command timeout in seconds
    :return: dict with 'status' ('success' or 'failed') and 'message'
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        logger.info("Membuka koneksi SSH ke %s...", ip)
        client.connect(
            hostname=ip,
            username=username,
            password=password,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
            look_for_keys=False,
            allow_agent=False
        )

        try:
            stdin, stdout, stderr = client.exec_command('reboot', timeout=timeout)
            # Many APs terminate connection immediately when reboot begins
            try:
                exit_status = stdout.channel.recv_exit_status()
                err_msg = stderr.read().decode('utf-8', errors='ignore').strip()
                if exit_status == 0 or not err_msg:
                    return {
                        'status': 'success',
                        'message': f'Reboot command executed successfully on {ip}'
                    }
                else:
                    return {
                        'status': 'failed',
                        'message': f'Reboot command returned error on {ip}: {err_msg}'
                    }
            except Exception:
                # Connection dropped by remote host as reboot initiates
                return {
                    'status': 'success',
                    'message': f'Reboot command sent to {ip} (connection closed by device)'
                }
        except Exception as exec_err:
            return {
                'status': 'failed',
                'message': f'Failed to execute reboot command on {ip}: {str(exec_err)}'
            }

    except paramiko.AuthenticationException:
        logger.warning("SSH authentication failed for %s", ip)
        return {
            'status': 'failed',
            'message': f'Authentication failed for {ip} with username {username}'
        }
    except (paramiko.SSHException, socket.timeout, socket.error, OSError) as exc:
        logger.error("SSH connection error for %s: %s", ip, exc)
        return {
            'status': 'failed',
            'message': f'SSH connection error for {ip}: {str(exc)}'
        }
    except Exception as exc:
        logger.error("Unexpected error rebooting AP %s: %s", ip, exc)
        return {
            'status': 'failed',
            'message': f'Unexpected error rebooting {ip}: {str(exc)}'
        }
    finally:
        try:
            client.close()
        except Exception:
            pass


def reboot_multiple(access_points, controller, schedule_id=None, triggered_by='scheduled'):
    """
    Reboot multiple Access Points in parallel using ThreadPoolExecutor.
    Creates a RebootLog entry for each AP.

    :param access_points: list of AccessPoint model objects
    :param controller: Controller model object providing SSH credentials
    :param schedule_id: optional schedule ID if triggered by scheduler
    :param triggered_by: 'scheduled' or 'manual'
    :return: list of result dicts
    """
    if not access_points:
        return []

    username = controller.ssh_username
    password = controller.ssh_password

    def _worker(ap_data):
        ap_id, ip, name = ap_data
        result = reboot_ap(ip, username, password)
        return ap_id, ip, name, result

    ap_items = [(ap.id, ap.ip_address, ap.name) for ap in access_points]
    max_workers = min(len(ap_items), 10)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        execution_results = list(executor.map(_worker, ap_items))

    results = []
    for ap_id, ip, name, res in execution_results:
        status = res.get('status', 'failed')
        message = res.get('message', '')

        log = RebootLog(
            access_point_id=ap_id,
            schedule_id=schedule_id,
            triggered_by=triggered_by,
            status=status,
            message=message,
            executed_at=datetime.utcnow()
        )
        db.session.add(log)

        results.append({
            'access_point_id': ap_id,
            'access_point_name': name,
            'ip_address': ip,
            'status': status,
            'message': message
        })

    try:
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        logger.error("Failed to commit reboot logs: %s", exc)

    return results


def manual_reboot(ap_id):
    """
    Perform a manual reboot for a single Access Point by ID.
    Looks up AP and controller credentials, sends reboot, logs result.

    :param ap_id: AccessPoint ID
    :return: result dict with status and message
    """
    ap = AccessPoint.query.get(ap_id)
    if not ap:
        return {
            'status': 'failed',
            'message': f'Access Point with ID {ap_id} not found'
        }

    controller = ap.controller
    if not controller:
        return {
            'status': 'failed',
            'message': f'No Controller assigned to Access Point {ap.name} ({ap.ip_address})'
        }

    result = reboot_ap(
        ip=ap.ip_address,
        username=controller.ssh_username,
        password=controller.ssh_password
    )

    log = RebootLog(
        access_point_id=ap.id,
        schedule_id=None,
        triggered_by='manual',
        status=result.get('status', 'failed'),
        message=result.get('message', ''),
        executed_at=datetime.utcnow()
    )
    db.session.add(log)

    try:
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        logger.error("Failed to commit manual reboot log for AP %s: %s", ap_id, exc)

    return {
        'access_point_id': ap.id,
        'access_point_name': ap.name,
        'ip_address': ap.ip_address,
        'status': result.get('status', 'failed'),
        'message': result.get('message', '')
    }
