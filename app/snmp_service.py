import time
import asyncio
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, List, Optional

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

# Standard & Enterprise OIDs
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"

# MikroTik Health (Temperature & Voltage)
OID_MT_TEMP_BOARD = "1.3.6.1.4.1.14988.1.1.3.10.0"   # Suhu Board (°C)
OID_MT_TEMP_CPU = "1.3.6.1.4.1.14988.1.1.3.11.0"     # Suhu CPU (°C)
OID_MT_VOLTAGE = "1.3.6.1.4.1.14988.1.1.3.8.0"       # Tegangan (decivolt -> volt / 10)

# MikroTik CPU & Memory
OID_MT_ACTIVE_CPU = "1.3.6.1.4.1.14988.1.1.1.3.1.0" # CPU Load %
OID_MT_TOTAL_MEM = "1.3.6.1.4.1.14988.1.1.1.1.1.0"  # Total RAM bytes
OID_MT_FREE_MEM = "1.3.6.1.4.1.14988.1.1.1.2.1.0"   # Free RAM bytes

# Standard Host Resources (Universal for Linux/AP/MikroTik)
OID_HR_PROCESSOR_LOAD = "1.3.6.1.2.1.25.3.3.1.2"    # Walk table CPU cores
OID_HR_STORAGE_TYPE = "1.3.6.1.2.1.25.2.3.1.2"
OID_HR_STORAGE_DESCR = "1.3.6.1.2.1.25.2.3.1.3"
OID_HR_STORAGE_ALLOC_UNITS = "1.3.6.1.2.1.25.2.3.1.4"
OID_HR_STORAGE_SIZE = "1.3.6.1.2.1.25.2.3.1.5"
OID_HR_STORAGE_USED = "1.3.6.1.2.1.25.2.3.1.6"

# Interface MIBs
OID_IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"               # ifName (ether1, vlan10, dsb)
OID_IF_DESCR = "1.3.6.1.2.1.2.2.1.2"                 # ifDescr fallback
OID_IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"             # ifAlias (MikroTik Comment / Keterangan)
OID_IF_TYPE = "1.3.6.1.2.1.2.2.1.3"                  # ifType (6=ethernet, 135=vlan, etc)
OID_IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"           # 1 = UP, 2 = DOWN
OID_IF_HC_IN_OCTETS = "1.3.6.1.2.1.31.1.1.1.6"      # 64-bit Rx bytes
OID_IF_HC_OUT_OCTETS = "1.3.6.1.2.1.31.1.1.1.10"    # 64-bit Tx bytes
OID_IF_IN_OCTETS_32 = "1.3.6.1.2.1.2.2.1.10"         # 32-bit Rx fallback
OID_IF_OUT_OCTETS_32 = "1.3.6.1.2.1.2.2.1.16"       # 32-bit Tx fallback

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
        transport = await UdpTransportTarget.create((ip, port), timeout=2.5, retries=1)
        errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
            snmp_engine,
            CommunityData(community),
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

async def poll_single_device(device_id: int) -> bool:
    """
    Eksekusi pengambilan metrik SNMP lengkap (CPU, RAM, Suhu, Voltase, dan Traffic Interface)
    """
    db = SessionLocal()
    try:
        dev = db.query(NetworkDevice).filter(NetworkDevice.id == device_id).first()
        if not dev or not dev.is_active:
            return False

        ip = dev.ip
        community = dev.snmp_community or "public"
        port = dev.snmp_port or 161

        snmp_engine = SnmpEngine()
        transport = await UdpTransportTarget.create((ip, port), timeout=3.0, retries=1)

        # 1. Query Dasar & Health (CPU, RAM, Suhu, Voltase)
        query_oids = [
            ObjectType(ObjectIdentity(OID_SYS_DESCR)),
            ObjectType(ObjectIdentity(OID_SYS_UPTIME)),
            ObjectType(ObjectIdentity(OID_SYS_NAME)),
            ObjectType(ObjectIdentity(OID_MT_TEMP_BOARD)),
            ObjectType(ObjectIdentity(OID_MT_TEMP_CPU)),
            ObjectType(ObjectIdentity(OID_MT_VOLTAGE)),
            ObjectType(ObjectIdentity(OID_MT_ACTIVE_CPU)),
            ObjectType(ObjectIdentity(OID_MT_TOTAL_MEM)),
            ObjectType(ObjectIdentity(OID_MT_FREE_MEM)),
        ]

        errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
            snmp_engine,
            CommunityData(community),
            transport,
            ContextData(),
            *query_oids
        )

        if errorIndication or errorStatus:
            dev.is_online = False
            dev.last_polled = now_wib()
            db.commit()
            return False

        dev.is_online = True
        dev.last_polled = now_wib()

        mt_total_mem = None
        mt_free_mem = None

        for varBind in varBinds:
            oid_str = str(varBind[0])
            val = varBind[1]
            try:
                # SysDescr
                if oid_str.startswith(OID_SYS_DESCR[:-2]):
                    raw_descr = str(val)
                    if "RouterOS" in raw_descr or "MikroTik" in raw_descr:
                        dev.device_type = "mikrotik"
                    dev.model_info = raw_descr[:250]

                # Uptime
                elif oid_str.startswith(OID_SYS_UPTIME[:-2]):
                    dev.uptime = format_uptime(int(val))

                # Suhu Board
                elif oid_str.startswith(OID_MT_TEMP_BOARD[:-2]):
                    t_val = float(val)
                    if t_val > 0:
                        dev.temperature = round(t_val if t_val < 200 else t_val / 10.0, 1)

                # Suhu CPU (jika suhu board belum terisi)
                elif oid_str.startswith(OID_MT_TEMP_CPU[:-2]):
                    t_val = float(val)
                    if t_val > 0 and not dev.temperature:
                        dev.temperature = round(t_val if t_val < 200 else t_val / 10.0, 1)

                # Voltase
                elif oid_str.startswith(OID_MT_VOLTAGE[:-2]):
                    v_val = float(val)
                    if v_val > 0:
                        dev.voltage = round(v_val / 10.0 if v_val > 50 else v_val, 1)

                # CPU Active Load
                elif oid_str.startswith(OID_MT_ACTIVE_CPU[:-2]):
                    dev.cpu_usage = float(val)

                # Memory
                elif oid_str.startswith(OID_MT_TOTAL_MEM[:-2]):
                    mt_total_mem = float(val)
                elif oid_str.startswith(OID_MT_FREE_MEM[:-2]):
                    mt_free_mem = float(val)

            except Exception:
                pass

        if mt_total_mem and mt_free_mem is not None:
            dev.memory_total_mb = round(mt_total_mem / (1024 * 1024), 1)
            used_bytes = max(0, mt_total_mem - mt_free_mem)
            dev.memory_used_mb = round(used_bytes / (1024 * 1024), 1)
            dev.memory_usage = round((used_bytes / mt_total_mem) * 100, 1)

        # 2. Walk Host Resources CPU jika CPU belum terdeteksi dari MIB MikroTik
        if dev.cpu_usage is None:
            cpu_loads = []
            try:
                async for err_ind, err_stat, err_idx, v_binds in bulk_walk_cmd(
                    snmp_engine,
                    CommunityData(community),
                    transport,
                    ContextData(),
                    0, 10,
                    ObjectType(ObjectIdentity(OID_HR_PROCESSOR_LOAD))
                ):
                    if err_ind or err_stat:
                        break
                    for vb in v_binds:
                        if str(vb[0]).startswith(OID_HR_PROCESSOR_LOAD):
                            cpu_loads.append(float(vb[1]))
                if cpu_loads:
                    dev.cpu_usage = round(sum(cpu_loads) / len(cpu_loads), 1)
            except Exception:
                pass

        # 3. Walk Interfaces (Name, Alias, OperStatus, HCIn, HCOut)
        if_data: Dict[int, Dict[str, Any]] = {}

        # Walk ifName
        async for err_ind, err_stat, err_idx, v_binds in bulk_walk_cmd(
            snmp_engine,
            CommunityData(community),
            transport,
            ContextData(),
            0, 20,
            ObjectType(ObjectIdentity(OID_IF_NAME))
        ):
            if err_ind or err_stat:
                break
            for vb in v_binds:
                oid_parts = str(vb[0]).split(".")
                if_idx = int(oid_parts[-1])
                name = str(vb[1])
                if if_idx not in if_data:
                    if_data[if_idx] = {"name": name, "alias": "", "is_up": False, "rx": 0, "tx": 0, "if_type_num": 0}
                else:
                    if_data[if_idx]["name"] = name

        # Walk ifAlias (Comment / Description)
        async for err_ind, err_stat, err_idx, v_binds in bulk_walk_cmd(
            snmp_engine,
            CommunityData(community),
            transport,
            ContextData(),
            0, 20,
            ObjectType(ObjectIdentity(OID_IF_ALIAS))
        ):
            if err_ind or err_stat:
                break
            for vb in v_binds:
                oid_parts = str(vb[0]).split(".")
                if_idx = int(oid_parts[-1])
                alias = str(vb[1])
                if if_idx in if_data:
                    if_data[if_idx]["alias"] = alias

        # Walk ifOperStatus (1=up, 2=down)
        async for err_ind, err_stat, err_idx, v_binds in bulk_walk_cmd(
            snmp_engine,
            CommunityData(community),
            transport,
            ContextData(),
            0, 20,
            ObjectType(ObjectIdentity(OID_IF_OPER_STATUS))
        ):
            if err_ind or err_stat:
                break
            for vb in v_binds:
                oid_parts = str(vb[0]).split(".")
                if_idx = int(oid_parts[-1])
                val = int(vb[1])
                if if_idx in if_data:
                    if_data[if_idx]["is_up"] = (val == 1)

        # Walk ifType
        async for err_ind, err_stat, err_idx, v_binds in bulk_walk_cmd(
            snmp_engine,
            CommunityData(community),
            transport,
            ContextData(),
            0, 20,
            ObjectType(ObjectIdentity(OID_IF_TYPE))
        ):
            if err_ind or err_stat:
                break
            for vb in v_binds:
                oid_parts = str(vb[0]).split(".")
                if_idx = int(oid_parts[-1])
                try:
                    val = int(vb[1])
                    if if_idx in if_data:
                        if_data[if_idx]["if_type_num"] = val
                except Exception:
                    pass

        # Walk 64-bit HC In Octets (Download bytes)
        has_hc = False
        async for err_ind, err_stat, err_idx, v_binds in bulk_walk_cmd(
            snmp_engine,
            CommunityData(community),
            transport,
            ContextData(),
            0, 20,
            ObjectType(ObjectIdentity(OID_IF_HC_IN_OCTETS))
        ):
            if err_ind or err_stat:
                break
            for vb in v_binds:
                oid_parts = str(vb[0]).split(".")
                if_idx = int(oid_parts[-1])
                val = int(vb[1])
                if if_idx in if_data:
                    if_data[if_idx]["rx"] = val
                    has_hc = True

        # Walk 64-bit HC Out Octets (Upload bytes)
        async for err_ind, err_stat, err_idx, v_binds in bulk_walk_cmd(
            snmp_engine,
            CommunityData(community),
            transport,
            ContextData(),
            0, 20,
            ObjectType(ObjectIdentity(OID_IF_HC_OUT_OCTETS))
        ):
            if err_ind or err_stat:
                break
            for vb in v_binds:
                oid_parts = str(vb[0]).split(".")
                if_idx = int(oid_parts[-1])
                val = int(vb[1])
                if if_idx in if_data:
                    if_data[if_idx]["tx"] = val

        # Fallback 32-bit counters jika 64-bit HC Octets tidak didukung
        if not has_hc:
            async for err_ind, err_stat, err_idx, v_binds in bulk_walk_cmd(
                snmp_engine,
                CommunityData(community),
                transport,
                ContextData(),
                0, 20,
                ObjectType(ObjectIdentity(OID_IF_IN_OCTETS_32))
            ):
                if err_ind or err_stat:
                    break
                for vb in v_binds:
                    oid_parts = str(vb[0]).split(".")
                    if_idx = int(oid_parts[-1])
                    if if_idx in if_data:
                        if_data[if_idx]["rx"] = int(vb[1])

            async for err_ind, err_stat, err_idx, v_binds in bulk_walk_cmd(
                snmp_engine,
                CommunityData(community),
                transport,
                ContextData(),
                0, 20,
                ObjectType(ObjectIdentity(OID_IF_OUT_OCTETS_32))
            ):
                if err_ind or err_stat:
                    break
                for vb in v_binds:
                    oid_parts = str(vb[0]).split(".")
                    if_idx = int(oid_parts[-1])
                    if if_idx in if_data:
                        if_data[if_idx]["tx"] = int(vb[1])

        # 4. Sinkronisasi Data Interface ke Database & Hitung Rate Mbps
        now_dt = now_wib()
        existing_interfaces = {
            iface.if_index: iface
            for iface in db.query(DeviceInterface).filter(DeviceInterface.device_id == dev.id).all()
        }

        for if_idx, item in if_data.items():
            if_name = item.get("name") or f"if-{if_idx}"
            # Abaikan interface loopback lo jika tidak diperlukan
            if if_name.lower() in ["lo", "loopback"]:
                continue

            alias = item.get("alias") or ""
            is_up = item.get("is_up", False)
            if_type_cat = classify_interface_type(if_name, item.get("if_type_num", 0))
            new_rx = item.get("rx", 0)
            new_tx = item.get("tx", 0)

            if if_idx in existing_interfaces:
                iface_obj = existing_interfaces[if_idx]
                prev_rx = iface_obj.rx_bytes or 0
                prev_tx = iface_obj.tx_bytes or 0
                prev_time = iface_obj.last_updated

                rx_rate = 0.0
                tx_rate = 0.0

                if prev_time and new_rx >= prev_rx and new_tx >= prev_tx:
                    delta_sec = (now_dt - prev_time).total_seconds()
                    if 0 < delta_sec < 600:  # Validasi interval wajar (di bawah 10 menit)
                        # Hitung Megabit per detik (Mbps) = (bytes * 8) / (sec * 1,000,000)
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

        db.commit()
        return True
    except Exception as e:
        db.rollback()
        return False
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
