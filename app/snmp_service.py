import time
import asyncio
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, List, Optional, Tuple

from pysnmp.hlapi.asyncio import (
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    get_cmd,
    bulk_walk_cmd
)

from app.database import SessionLocal, NetworkDevice, DeviceInterface, now_wib

# Standard System OIDs (RFC 1213)
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"

# Host Resources MIB (Standard RFC 2790 for Linux, AP, MikroTik)
OID_HR_PROCESSOR_LOAD = "1.3.6.1.2.1.25.3.3.1.2"      # CPU Cores load table
OID_HR_STORAGE_DESCR = "1.3.6.1.2.1.25.2.3.1.3"       # Storage Descr (RAM)
OID_HR_STORAGE_ALLOC_UNITS = "1.3.6.1.2.1.25.2.3.1.4" # Storage Allocation Units
OID_HR_STORAGE_SIZE = "1.3.6.1.2.1.25.2.3.1.5"        # Storage Total Units
OID_HR_STORAGE_USED = "1.3.6.1.2.1.25.2.3.1.6"        # Storage Used Units

# MikroTik Health (RouterOS 7 Table)
OID_MT_HEALTH_NAME = "1.3.6.1.4.1.14988.1.1.3.100.1.2"   # Health sensor names
OID_MT_HEALTH_VALUE = "1.3.6.1.4.1.14988.1.1.3.100.1.3"  # Health sensor values

# MikroTik Health (RouterOS 6 / Legacy Scalars)
OID_MT_TEMP_BOARD = "1.3.6.1.4.1.14988.1.1.3.10.0"   # Suhu Board (°C)
OID_MT_TEMP_CPU = "1.3.6.1.4.1.14988.1.1.3.11.0"     # Suhu CPU (°C)
OID_MT_VOLTAGE = "1.3.6.1.4.1.14988.1.1.3.8.0"       # Tegangan (decivolt -> volt / 10)

# MikroTik Legacy CPU & Memory
OID_MT_ACTIVE_CPU = "1.3.6.1.4.1.14988.1.1.1.3.1.0"  # CPU Load %
OID_MT_TOTAL_MEM = "1.3.6.1.4.1.14988.1.1.1.1.1.0"   # Total RAM bytes
OID_MT_FREE_MEM = "1.3.6.1.4.1.14988.1.1.1.2.1.0"    # Free RAM bytes

# Interface MIBs
OID_IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"                # ifName (ether1, vlan10, dsb)
OID_IF_DESCR = "1.3.6.1.2.1.2.2.1.2"                  # ifDescr fallback
OID_IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"              # ifAlias (MikroTik Comment)
OID_IF_TYPE = "1.3.6.1.2.1.2.2.1.3"                   # ifType (6=ethernet, 135=vlan, etc)
OID_IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"            # 1 = UP, 2 = DOWN
OID_IF_HC_IN_OCTETS = "1.3.6.1.2.1.31.1.1.1.6"       # 64-bit Rx bytes
OID_IF_HC_OUT_OCTETS = "1.3.6.1.2.1.31.1.1.1.10"     # 64-bit Tx bytes
OID_IF_IN_OCTETS_32 = "1.3.6.1.2.1.2.2.1.10"          # 32-bit Rx fallback
OID_IF_OUT_OCTETS_32 = "1.3.6.1.2.1.2.2.1.16"        # 32-bit Tx fallback

def format_uptime(timeticks: Optional[int]) -> str:
    """Format timeticks (1/100 s) menjadi format human readable misal: 12d 4h 32m"""
    if not timeticks or timeticks < 0:
        return "Unknown"
    seconds = int(timeticks / 100)
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, _ = divmod(remainder, 60)
    
    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts) if parts else "0m"

def classify_interface_type(name: str, if_type_num: int = 0) -> str:
    """Klasifikasi tipe interface: ethernet, vlan, backbone, bridge, wireless, other"""
    n = name.lower()
    if "vlan" in n or if_type_num == 135:
        return "vlan"
    if "bridge" in n:
        return "bridge"
    if any(k in n for k in ["eoip", "gre", "tunnel", "wg", "wireguard", "ovpn", "sstp", "l2tp", "pppoe", "backbone", "bb_"]):
        return "backbone"
    if any(k in n for k in ["wlan", "wifi", "ath"]):
        return "wireless"
    if any(k in n for k in ["ether", "sfp", "ge", "fa", "port"]) or if_type_num == 6:
        return "ethernet"
    return "other"

async def test_snmp_connection(ip: str, community: str = "public", port: int = 161, version: str = "2c") -> Dict[str, Any]:
    """Test koneksi SNMP ke perangkat target secara cepat (timeout 2.5s)"""
    snmp_engine = SnmpEngine()
    try:
        mp_model = 0 if version == "1" else 1
        auth_data = CommunityData(community, mpModel=mp_model)
        transport = await UdpTransportTarget.create((ip, port), timeout=2.5, retries=1)
        
        errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
            snmp_engine,
            auth_data,
            transport,
            ContextData(),
            ObjectType(ObjectIdentity(OID_SYS_DESCR)),
            ObjectType(ObjectIdentity(OID_SYS_UPTIME)),
            ObjectType(ObjectIdentity(OID_SYS_NAME))
        )

        if errorIndication:
            return {"status": "error", "message": f"Koneksi SNMP Gagal: {errorIndication}"}
        if errorStatus:
            return {"status": "error", "message": f"SNMP Error: {errorStatus.prettyPrint()}"}

        model_info = "Generic SNMP Device"
        uptime_str = "-"
        device_name = ip

        for varBind in varBinds:
            oid_str = str(varBind[0])
            val = varBind[1]
            if oid_str.startswith(OID_SYS_DESCR[:-2]):
                model_info = str(val)
            elif oid_str.startswith(OID_SYS_UPTIME[:-2]):
                try:
                    uptime_str = format_uptime(int(val))
                except Exception:
                    pass
            elif oid_str.startswith(OID_SYS_NAME[:-2]):
                device_name = str(val)

        return {
            "status": "success",
            "message": f"Tersambung! Respon dari: {device_name}",
            "device_name": device_name,
            "model_info": model_info,
            "uptime": uptime_str
        }
    except Exception as e:
        return {"status": "error", "message": f"Gagal menghubungi target: {str(e)}"}

async def walk_oid_column(snmp_engine: SnmpEngine, auth_data: CommunityData, transport: Any, base_oid: str, max_reps: int = 25) -> Dict[int, Any]:
    """
    Melakukan bulk walk pada satu kolom OID dengan pengecekan prefix ketat.
    Pasti berhenti begitu melewati kolom base_oid sehingga tidak runaway dan sangat cepat.
    """
    result = {}
    prefix = base_oid if base_oid.endswith(".") else (base_oid + ".")
    try:
        async for err_ind, err_stat, err_idx, v_binds in bulk_walk_cmd(
            snmp_engine,
            auth_data,
            transport,
            ContextData(),
            0, max_reps,
            ObjectType(ObjectIdentity(base_oid))
        ):
            if err_ind or err_stat:
                break
            stopped = False
            for vb in v_binds:
                oid_str = str(vb[0])
                if not oid_str.startswith(prefix):
                    stopped = True
                    break
                idx_part = oid_str[len(prefix):]
                try:
                    idx = int(idx_part)
                except ValueError:
                    idx = idx_part
                result[idx] = vb[1]
            if stopped:
                break
    except Exception:
        pass
    return result

async def poll_single_device(device_id: int) -> Tuple[bool, str]:
    """
    Eksekusi pengambilan metrik SNMP lengkap (CPU, RAM, Suhu, Voltase, dan Traffic Interface).
    Mengembalikan (True, "OK") atau (False, "Deskripsi error").
    """
    db = SessionLocal()
    try:
        dev = db.query(NetworkDevice).filter(NetworkDevice.id == device_id).first()
        if not dev:
            return False, "Perangkat tidak ditemukan di database"
        if not dev.is_active:
            return False, "Perangkat dalam status non-aktif"

        ip = dev.ip
        community = dev.snmp_community or "public"
        port = dev.snmp_port or 161
        version = dev.snmp_version or "2c"

        snmp_engine = SnmpEngine()
        mp_model = 0 if version == "1" else 1
        auth_data = CommunityData(community, mpModel=mp_model)
        transport = await UdpTransportTarget.create((ip, port), timeout=3.0, retries=1)

        # -----------------------------------------------------------------
        # LANGKAH 1: QUERY DASAR SISTEM (sysDescr, sysUptime, sysName)
        # Query ini WAJIB berhasil untuk menentukan status ONLINE perangkat.
        # -----------------------------------------------------------------
        try:
            errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
                snmp_engine,
                auth_data,
                transport,
                ContextData(),
                ObjectType(ObjectIdentity(OID_SYS_DESCR)),
                ObjectType(ObjectIdentity(OID_SYS_UPTIME)),
                ObjectType(ObjectIdentity(OID_SYS_NAME))
            )

            if errorIndication:
                dev.is_online = False
                dev.last_polled = now_wib()
                db.commit()
                return False, f"SNMP Timeout/Gagal: {errorIndication}"

            if errorStatus:
                dev.is_online = False
                dev.last_polled = now_wib()
                db.commit()
                return False, f"SNMP Error: {errorStatus.prettyPrint()}"

            # Berhasil menjawab! Perangkat terkonfirmasi ONLINE
            dev.is_online = True
            dev.last_polled = now_wib()

            for varBind in varBinds:
                oid_str = str(varBind[0])
                val = varBind[1]
                if oid_str.startswith(OID_SYS_DESCR[:-2]):
                    raw_descr = str(val)
                    if any(k in raw_descr for k in ["RouterOS", "MikroTik", "RB"]):
                        dev.device_type = "mikrotik"
                    dev.model_info = raw_descr[:250]
                elif oid_str.startswith(OID_SYS_UPTIME[:-2]):
                    try:
                        dev.uptime = format_uptime(int(val))
                    except Exception:
                        pass
                elif oid_str.startswith(OID_SYS_NAME[:-2]):
                    dev_sys_name = str(val).strip()
                    if dev_sys_name and dev.name == dev.ip:
                        dev.name = dev_sys_name

        except Exception as e:
            dev.is_online = False
            dev.last_polled = now_wib()
            db.commit()
            return False, f"Exception saat get dasar: {str(e)}"

        # -----------------------------------------------------------------
        # LANGKAH 2: SUHU & TEGANGAN (ROUTEROS 7 TABLE & ROS 6 LEGACY)
        # Dibungkus try-except agar kegagalan OID proprietary tidak merusak poll
        # -----------------------------------------------------------------
        try:
            # 2a. Coba RouterOS 7 Health Item Table
            h_names = await walk_oid_column(snmp_engine, auth_data, transport, OID_MT_HEALTH_NAME, 20)
            if h_names:
                h_vals = await walk_oid_column(snmp_engine, auth_data, transport, OID_MT_HEALTH_VALUE, 20)
                for idx, name_raw in h_names.items():
                    name_str = str(name_raw).lower()
                    val_raw = h_vals.get(idx)
                    if val_raw is not None:
                        try:
                            num_val = float(val_raw)
                            # Suhu (CPU atau Board)
                            if "temp" in name_str and num_val > 0:
                                parsed_t = round(num_val / 10.0 if num_val > 150 else num_val, 1)
                                if "cpu" in name_str or dev.temperature is None:
                                    dev.temperature = parsed_t
                            # Voltase
                            elif "volt" in name_str and num_val > 0:
                                parsed_v = round(num_val / 10.0 if num_val > 50 else num_val, 1)
                                dev.voltage = parsed_v
                        except Exception:
                            pass

            # 2b. Fallback legacy RouterOS 6 OIDs jika suhu/voltase masih kosong
            if dev.temperature is None or dev.voltage is None:
                err_ind, err_stat, _, vbs = await get_cmd(
                    snmp_engine,
                    auth_data,
                    transport,
                    ContextData(),
                    ObjectType(ObjectIdentity(OID_MT_TEMP_BOARD)),
                    ObjectType(ObjectIdentity(OID_MT_TEMP_CPU)),
                    ObjectType(ObjectIdentity(OID_MT_VOLTAGE))
                )
                if not err_ind and not err_stat:
                    for vb in vbs:
                        oid_s = str(vb[0])
                        val = vb[1]
                        try:
                            f_val = float(val)
                            if oid_s.startswith(OID_MT_TEMP_BOARD[:-2]) and f_val > 0 and dev.temperature is None:
                                dev.temperature = round(f_val if f_val < 200 else f_val / 10.0, 1)
                            elif oid_s.startswith(OID_MT_TEMP_CPU[:-2]) and f_val > 0 and dev.temperature is None:
                                dev.temperature = round(f_val if f_val < 200 else f_val / 10.0, 1)
                            elif oid_s.startswith(OID_MT_VOLTAGE[:-2]) and f_val > 0 and dev.voltage is None:
                                dev.voltage = round(f_val / 10.0 if f_val > 50 else f_val, 1)
                        except Exception:
                            pass
        except Exception:
            pass

        # -----------------------------------------------------------------
        # LANGKAH 3: CPU & MEMORY USAGE
        # -----------------------------------------------------------------
        try:
            # 3a. CPU Load via Host Resources MIB (hrProcessorLoad - multi-core support)
            cpu_cores = await walk_oid_column(snmp_engine, auth_data, transport, OID_HR_PROCESSOR_LOAD, 16)
            if cpu_cores:
                loads = []
                for _, core_load in cpu_cores.items():
                    try:
                        loads.append(float(core_load))
                    except Exception:
                        pass
                if loads:
                    dev.cpu_usage = round(sum(loads) / len(loads), 1)

            # Fallback legacy MikroTik CPU scalar jika belum dapat
            if dev.cpu_usage is None:
                err_ind, err_stat, _, vbs = await get_cmd(
                    snmp_engine, auth_data, transport, ContextData(),
                    ObjectType(ObjectIdentity(OID_MT_ACTIVE_CPU))
                )
                if not err_ind and not err_stat and vbs:
                    try:
                        dev.cpu_usage = float(vbs[0][1])
                    except Exception:
                        pass

            # 3b. RAM Memory via Host Resources Storage MIB
            stor_descrs = await walk_oid_column(snmp_engine, auth_data, transport, OID_HR_STORAGE_DESCR, 20)
            ram_idx = None
            for idx, descr_val in stor_descrs.items():
                d_str = str(descr_val).lower()
                if any(k in d_str for k in ["main memory", "ram", "physical memory", "system memory"]):
                    ram_idx = idx
                    break

            if ram_idx is not None:
                err_ind, err_stat, _, vbs = await get_cmd(
                    snmp_engine, auth_data, transport, ContextData(),
                    ObjectType(ObjectIdentity(f"{OID_HR_STORAGE_ALLOC_UNITS}.{ram_idx}")),
                    ObjectType(ObjectIdentity(f"{OID_HR_STORAGE_SIZE}.{ram_idx}")),
                    ObjectType(ObjectIdentity(f"{OID_HR_STORAGE_USED}.{ram_idx}"))
                )
                if not err_ind and not err_stat and len(vbs) == 3:
                    units = float(vbs[0][1])
                    total_units = float(vbs[1][1])
                    used_units = float(vbs[2][1])
                    if total_units > 0 and units > 0:
                        total_bytes = total_units * units
                        used_bytes = used_units * units
                        dev.memory_total_mb = round(total_bytes / (1024 * 1024), 1)
                        dev.memory_used_mb = round(used_bytes / (1024 * 1024), 1)
                        dev.memory_usage = round((used_bytes / total_bytes) * 100, 1)

            # Fallback legacy MikroTik RAM scalar jika belum dapat
            if dev.memory_usage is None:
                err_ind, err_stat, _, vbs = await get_cmd(
                    snmp_engine, auth_data, transport, ContextData(),
                    ObjectType(ObjectIdentity(OID_MT_TOTAL_MEM)),
                    ObjectType(ObjectIdentity(OID_MT_FREE_MEM))
                )
                if not err_ind and not err_stat and len(vbs) == 2:
                    t_mem = float(vbs[0][1])
                    f_mem = float(vbs[1][1])
                    if t_mem > 0:
                        u_mem = max(0, t_mem - f_mem)
                        dev.memory_total_mb = round(t_mem / (1024 * 1024), 1)
                        dev.memory_used_mb = round(u_mem / (1024 * 1024), 1)
                        dev.memory_usage = round((u_mem / t_mem) * 100, 1)

        except Exception:
            pass

        # -----------------------------------------------------------------
        # LANGKAH 4: INTERFACES & TRAFFIC RATE
        # -----------------------------------------------------------------
        try:
            # Ambil nama interface (ifName, fallback ifDescr)
            if_names = await walk_oid_column(snmp_engine, auth_data, transport, OID_IF_NAME, 25)
            if not if_names:
                if_names = await walk_oid_column(snmp_engine, auth_data, transport, OID_IF_DESCR, 25)

            if if_names:
                # Ambil paralel: alias (komentar), operStatus, ifType, 64-bit HC Octets
                if_aliases, if_status, if_types, if_rx_64, if_tx_64 = await asyncio.gather(
                    walk_oid_column(snmp_engine, auth_data, transport, OID_IF_ALIAS, 25),
                    walk_oid_column(snmp_engine, auth_data, transport, OID_IF_OPER_STATUS, 25),
                    walk_oid_column(snmp_engine, auth_data, transport, OID_IF_TYPE, 25),
                    walk_oid_column(snmp_engine, auth_data, transport, OID_IF_HC_IN_OCTETS, 25),
                    walk_oid_column(snmp_engine, auth_data, transport, OID_IF_HC_OUT_OCTETS, 25),
                    return_exceptions=True
                )

                # Cek jika 64-bit tidak tersedia, ambil 32-bit fallback
                has_hc = isinstance(if_rx_64, dict) and len(if_rx_64) > 0
                if_rx_32 = {}
                if_tx_32 = {}
                if not has_hc:
                    if_rx_32 = await walk_oid_column(snmp_engine, auth_data, transport, OID_IF_IN_OCTETS_32, 25)
                    if_tx_32 = await walk_oid_column(snmp_engine, auth_data, transport, OID_IF_OUT_OCTETS_32, 25)

                aliases_dict = if_aliases if isinstance(if_aliases, dict) else {}
                status_dict = if_status if isinstance(if_status, dict) else {}
                types_dict = if_types if isinstance(if_types, dict) else {}
                rx_dict = if_rx_64 if has_hc else if_rx_32
                tx_dict = if_tx_64 if (isinstance(if_tx_64, dict) and len(if_tx_64) > 0) else if_tx_32

                now_dt = now_wib()
                existing_interfaces = {
                    iface.if_index: iface
                    for iface in db.query(DeviceInterface).filter(DeviceInterface.device_id == dev.id).all()
                }

                for if_idx, name_raw in if_names.items():
                    if_name = str(name_raw).strip()
                    if if_name.lower() in ["lo", "loopback"]:
                        continue

                    alias = str(aliases_dict.get(if_idx, "")).strip()
                    is_up = (int(status_dict.get(if_idx, 2)) == 1)
                    type_num = int(types_dict.get(if_idx, 0))
                    if_type_cat = classify_interface_type(if_name, type_num)

                    new_rx = int(rx_dict.get(if_idx, 0))
                    new_tx = int(tx_dict.get(if_idx, 0))

                    if if_idx in existing_interfaces:
                        iface_obj = existing_interfaces[if_idx]
                        prev_rx = iface_obj.rx_bytes or 0
                        prev_tx = iface_obj.tx_bytes or 0
                        prev_time = iface_obj.last_updated

                        rx_rate = 0.0
                        tx_rate = 0.0

                        if prev_time and new_rx >= prev_rx and new_tx >= prev_tx:
                            delta_sec = (now_dt - prev_time).total_seconds()
                            if 0 < delta_sec < 600:
                                rx_rate = round(((new_rx - prev_rx) * 8) / (delta_sec * 1_000_000), 2)
                                tx_rate = round(((new_tx - prev_tx) * 8) / (delta_sec * 1_000_000), 2)

                        iface_obj.name = if_name
                        iface_obj.alias = alias
                        iface_obj.if_type = if_type_cat
                        iface_obj.is_up = is_up
                        iface_obj.rx_bytes = new_rx
                        iface_obj.tx_bytes = new_tx
                        iface_obj.rx_rate_mbps = rx_rate
                        iface_obj.tx_rate_mbps = tx_rate
                        iface_obj.total_rx_gb = round(new_rx / (1024 ** 3), 2)
                        iface_obj.total_tx_gb = round(new_tx / (1024 ** 3), 2)
                        iface_obj.last_updated = now_dt
                    else:
                        new_iface = DeviceInterface(
                            device_id=dev.id,
                            if_index=if_idx,
                            name=if_name,
                            alias=alias,
                            if_type=if_type_cat,
                            is_up=is_up,
                            rx_bytes=new_rx,
                            tx_bytes=new_tx,
                            rx_rate_mbps=0.0,
                            tx_rate_mbps=0.0,
                            total_rx_gb=round(new_rx / (1024 ** 3), 2),
                            total_tx_gb=round(new_tx / (1024 ** 3), 2),
                            last_updated=now_dt
                        )
                        db.add(new_iface)

        except Exception as e:
            # Jangan batalkan seluruh transaksi hanya jika pembacaan antarmuka mengalami kendala
            pass

        db.commit()
        return True, "Polling berhasil"

    except Exception as e:
        db.rollback()
        return False, f"Terjadi kesalahan polling: {str(e)}"
    finally:
        db.close()

def run_nms_poll_cycle():
    """
    Siklus background worker untuk mengumpulkan metrik dari semua perangkat aktif
    """
    db = SessionLocal()
    try:
        active_devices = db.query(NetworkDevice).filter(NetworkDevice.is_active == True).all()
        dev_ids = [d.id for d in active_devices]
    finally:
        db.close()

    if not dev_ids:
        return

    async def _poll_all():
        tasks = [poll_single_device(d_id) for d_id in dev_ids]
        await asyncio.gather(*tasks, return_exceptions=True)

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(_poll_all())
        loop.close()
    except Exception:
        pass
