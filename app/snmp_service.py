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

from app.database import SessionLocal, NetworkDevice, DeviceInterface, NetworkTrafficHistory, now_wib

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
OID_IF_HIGH_SPEED = "1.3.6.1.2.1.31.1.1.1.15"         # ifHighSpeed (Mbps: 1000=1G, 10000=10G, 25000=25G)
OID_IF_HC_IN_OCTETS = "1.3.6.1.2.1.31.1.1.1.6"       # 64-bit Rx bytes
OID_IF_HC_OUT_OCTETS = "1.3.6.1.2.1.31.1.1.1.10"     # 64-bit Tx bytes
OID_IF_IN_OCTETS_32 = "1.3.6.1.2.1.2.2.1.10"          # 32-bit Rx fallback
OID_IF_OUT_OCTETS_32 = "1.3.6.1.2.1.2.2.1.16"        # 32-bit Tx fallback

# MikroTik Optical Table (SFP / DDM Telemetry)
OID_MT_OPT_NAME = "1.3.6.1.4.1.14988.1.1.19.1.1.2"        # Nama interface (e.g. sfp-sfpplus1)
OID_MT_OPT_RX_LOSS = "1.3.6.1.4.1.14988.1.1.19.1.1.3"     # 0 = Normal, 1 = Loss of Signal
OID_MT_OPT_TX_FAULT = "1.3.6.1.4.1.14988.1.1.19.1.1.4"    # 0 = Normal, 1 = Laser Fault
OID_MT_OPT_WAVELENGTH = "1.3.6.1.4.1.14988.1.1.19.1.1.5"  # Wavelength (nm, e.g. 1310, 850)
OID_MT_OPT_TEMP = "1.3.6.1.4.1.14988.1.1.19.1.1.6"        # Suhu SFP (°C)
OID_MT_OPT_VOLTAGE = "1.3.6.1.4.1.14988.1.1.19.1.1.7"     # Supply Voltage (mV / V)
OID_MT_OPT_TX_POWER = "1.3.6.1.4.1.14988.1.1.19.1.1.9"    # TX Power (0.001 dBm)
OID_MT_OPT_RX_POWER = "1.3.6.1.4.1.14988.1.1.19.1.1.10"   # RX Power / Redaman (0.001 dBm)
OID_MT_OPT_VENDOR = "1.3.6.1.4.1.14988.1.1.19.1.1.11"     # Merk / Vendor SFP
OID_MT_OPT_SERIAL = "1.3.6.1.4.1.14988.1.1.19.1.1.12"     # Serial Number SFP
OID_MT_OPT_REVISION = "1.3.6.1.4.1.14988.1.1.19.1.1.13"   # Revision SFP (A0)
OID_MT_OPT_PART = "1.3.6.1.4.1.14988.1.1.19.1.1.14"       # Part Number SFP (SFP-10G-LH-SM)

def parse_optical_power(val: Any) -> Optional[float]:
    """Konversi nilai optical power ke format dBm standar (di MikroTik 0.001 dBm)"""
    if val is None:
        return None
    try:
        f = float(val)
        if f == 0:
            return 0.0
        # Di MikroTik SNMP, optical power dilaporkan dalam satuan milli-dBm (0.001 dBm)
        # Contoh: -2557 -> -2.557 dBm, -1782 -> -1.782 dBm, -15400 -> -15.400 dBm
        if abs(f) >= 40:
            return round(f / 1000.0, 3)
        return round(f, 3)
    except Exception:
        return None

def parse_wavelength(val: Any) -> Optional[int]:
    """Konversi panjang gelombang ke nm (MikroTik mengirim 131000 untuk 1310.00 nm)"""
    if val is None:
        return None
    try:
        f = float(val)
        if f >= 10000:
            return int(round(f / 100.0))
        return int(round(f))
    except Exception:
        return None

def parse_optical_temp(val: Any) -> Optional[float]:
    """Konversi suhu SFP ke format Celcius (°C)"""
    if val is None:
        return None
    try:
        f = float(val)
        if f > 150:
            return round(f / 10.0 if f < 1500 else f / 100.0, 1)
        return round(f, 1)
    except Exception:
        return None

def parse_optical_voltage(val: Any) -> Optional[float]:
    """Konversi tegangan SFP ke Volt (V)"""
    if val is None:
        return None
    try:
        f = float(val)
        if f > 100:
            return round(f / 1000.0, 2)
        return round(f, 2)
    except Exception:
        return None

def determine_port_speed(if_name: str, high_speed: Optional[int]) -> str:
    """Tentukan label kecepatan port SFP / Ethernet: 1G, 10G, 25G, 40G, 100G"""
    n = if_name.lower()
    if high_speed and high_speed > 0:
        if high_speed >= 100000:
            return "100G QSFP28"
        if high_speed >= 40000:
            return "40G QSFP+"
        if high_speed >= 25000:
            return "25G SFP28"
        if high_speed >= 10000:
            return "10G SFP+"
        if high_speed >= 1000:
            if "sfpplus" in n or "sfp+" in n:
                return "10G SFP+"
            return "1G SFP" if "sfp" in n else "1 Gbps"
        if high_speed >= 100:
            return "100 Mbps"
    
    # Deteksi berbasis nama port router (CCR2004, CRS, dll)
    if "sfp28" in n or "25g" in n:
        return "25G SFP28"
    if "sfpplus" in n or "sfp+" in n or "10g" in n:
        return "10G SFP+"
    if "qsfp28" in n or "100g" in n:
        return "100G QSFP28"
    if "qsfp" in n or "40g" in n:
        return "40G QSFP+"
    if "sfp" in n:
        return "1G SFP"
    if "ether" in n:
        return "1 Gbps"
    return "-"

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
        # LANGKAH 4: INTERFACES, TRAFFIC RATE & DETAIL SFP / OPTIK
        # -----------------------------------------------------------------
        try:
            # Ambil nama interface (ifName, fallback ifDescr)
            if_names = await walk_oid_column(snmp_engine, auth_data, transport, OID_IF_NAME, 25)
            if not if_names:
                if_names = await walk_oid_column(snmp_engine, auth_data, transport, OID_IF_DESCR, 25)

            if if_names:
                # Ambil paralel: alias (komentar), operStatus, ifType, ifHighSpeed, 64-bit HC Octets
                if_aliases, if_status, if_types, if_speeds, if_rx_64, if_tx_64 = await asyncio.gather(
                    walk_oid_column(snmp_engine, auth_data, transport, OID_IF_ALIAS, 25),
                    walk_oid_column(snmp_engine, auth_data, transport, OID_IF_OPER_STATUS, 25),
                    walk_oid_column(snmp_engine, auth_data, transport, OID_IF_TYPE, 25),
                    walk_oid_column(snmp_engine, auth_data, transport, OID_IF_HIGH_SPEED, 25),
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
                speeds_dict = if_speeds if isinstance(if_speeds, dict) else {}
                rx_dict = if_rx_64 if has_hc else if_rx_32
                tx_dict = if_tx_64 if (isinstance(if_tx_64, dict) and len(if_tx_64) > 0) else if_tx_32

                # Ambil data tabel Optical SFP MikroTik (DDM)
                optical_by_name = {}
                try:
                    opt_names = await walk_oid_column(snmp_engine, auth_data, transport, OID_MT_OPT_NAME, 25)
                    if opt_names:
                        res_opt = await asyncio.gather(
                            walk_oid_column(snmp_engine, auth_data, transport, OID_MT_OPT_RX_LOSS, 25),
                            walk_oid_column(snmp_engine, auth_data, transport, OID_MT_OPT_TX_FAULT, 25),
                            walk_oid_column(snmp_engine, auth_data, transport, OID_MT_OPT_WAVELENGTH, 25),
                            walk_oid_column(snmp_engine, auth_data, transport, OID_MT_OPT_TEMP, 25),
                            walk_oid_column(snmp_engine, auth_data, transport, OID_MT_OPT_VOLTAGE, 25),
                            walk_oid_column(snmp_engine, auth_data, transport, OID_MT_OPT_TX_POWER, 25),
                            walk_oid_column(snmp_engine, auth_data, transport, OID_MT_OPT_RX_POWER, 25),
                            walk_oid_column(snmp_engine, auth_data, transport, OID_MT_OPT_VENDOR, 25),
                            walk_oid_column(snmp_engine, auth_data, transport, OID_MT_OPT_SERIAL, 25),
                            walk_oid_column(snmp_engine, auth_data, transport, OID_MT_OPT_REVISION, 25),
                            walk_oid_column(snmp_engine, auth_data, transport, OID_MT_OPT_PART, 25),
                            return_exceptions=True
                        )
                        opt_rx_loss = res_opt[0] if isinstance(res_opt[0], dict) else {}
                        opt_tx_fault = res_opt[1] if isinstance(res_opt[1], dict) else {}
                        opt_wave = res_opt[2] if isinstance(res_opt[2], dict) else {}
                        opt_temp = res_opt[3] if isinstance(res_opt[3], dict) else {}
                        opt_volt = res_opt[4] if isinstance(res_opt[4], dict) else {}
                        opt_tx_pow = res_opt[5] if isinstance(res_opt[5], dict) else {}
                        opt_rx_pow = res_opt[6] if isinstance(res_opt[6], dict) else {}
                        opt_vendor = res_opt[7] if isinstance(res_opt[7], dict) else {}
                        opt_serial = res_opt[8] if isinstance(res_opt[8], dict) else {}
                        opt_rev = res_opt[9] if isinstance(res_opt[9], dict) else {}
                        opt_part = res_opt[10] if isinstance(res_opt[10], dict) else {}

                        for o_idx, o_name_val in opt_names.items():
                            k_name = str(o_name_val).strip().lower()
                            # Part number bisa di .14, atau fallback ke .13
                            part_num = str(opt_part.get(o_idx, "")).strip() or str(opt_rev.get(o_idx, "")).strip() or None
                            serial_num = str(opt_serial.get(o_idx, "")).strip() or None

                            optical_by_name[k_name] = {
                                "rx_loss": bool(int(opt_rx_loss.get(o_idx, 0)) == 1),
                                "tx_fault": bool(int(opt_tx_fault.get(o_idx, 0)) == 1),
                                "wavelength": parse_wavelength(opt_wave.get(o_idx)),
                                "temperature": parse_optical_temp(opt_temp.get(o_idx)),
                                "voltage": parse_optical_voltage(opt_volt.get(o_idx)),
                                "tx_power": parse_optical_power(opt_tx_pow.get(o_idx)),
                                "rx_power": parse_optical_power(opt_rx_pow.get(o_idx)),
                                "vendor": str(opt_vendor.get(o_idx, "")).strip() or None,
                                "serial": serial_num,
                                "part": part_num,
                            }
                except Exception:
                    pass

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

                    # Deteksi port speed & SFP DDM
                    speed_mbps_val = int(speeds_dict.get(if_idx, 0)) if speeds_dict.get(if_idx) else None
                    port_speed_label = determine_port_speed(if_name, speed_mbps_val)
                    is_sfp_port = ("sfp" in if_name.lower()) or (if_name.lower() in optical_by_name)

                    opt_data = optical_by_name.get(if_name.lower(), {})

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

                        # SFP & Optical telemetry
                        iface_obj.is_sfp = is_sfp_port
                        iface_obj.port_speed = port_speed_label
                        iface_obj.sfp_vendor = opt_data.get("vendor")
                        iface_obj.sfp_part_number = opt_data.get("part")
                        iface_obj.sfp_serial = opt_data.get("serial")
                        iface_obj.sfp_wavelength = opt_data.get("wavelength")
                        iface_obj.sfp_temperature = opt_data.get("temperature")
                        iface_obj.sfp_voltage = opt_data.get("voltage")
                        iface_obj.sfp_tx_power = opt_data.get("tx_power")
                        iface_obj.sfp_rx_power = opt_data.get("rx_power")
                        iface_obj.sfp_rx_loss = opt_data.get("rx_loss", False)
                        iface_obj.sfp_tx_fault = opt_data.get("tx_fault", False)

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
                            last_updated=now_dt,
                            is_sfp=is_sfp_port,
                            port_speed=port_speed_label,
                            sfp_vendor=opt_data.get("vendor"),
                            sfp_part_number=opt_data.get("part"),
                            sfp_serial=opt_data.get("serial"),
                            sfp_wavelength=opt_data.get("wavelength"),
                            sfp_temperature=opt_data.get("temperature"),
                            sfp_voltage=opt_data.get("voltage"),
                            sfp_tx_power=opt_data.get("tx_power"),
                            sfp_rx_power=opt_data.get("rx_power"),
                            sfp_rx_loss=opt_data.get("rx_loss", False),
                            sfp_tx_fault=opt_data.get("tx_fault", False)
                        )
                        db.add(new_iface)

        except Exception as e:
            # Jangan batalkan seluruh transaksi hanya jika pembacaan antarmuka mengalami kendala
            pass

        # Rekam snapshot traffic ke tabel histori (NetworkTrafficHistory)
        try:
            total_rx = sum((iface.rx_rate_mbps or 0.0) for iface in dev.interfaces)
            total_tx = sum((iface.tx_rate_mbps or 0.0) for iface in dev.interfaces)
            hist = NetworkTrafficHistory(
                device_id=dev.id,
                site=dev.site or "Fasilkom",
                timestamp=now_wib(),
                rx_mbps=round(total_rx, 2),
                tx_mbps=round(total_tx, 2),
                total_mbps=round(total_rx + total_tx, 2),
                cpu_usage=dev.cpu_usage,
                temperature=dev.temperature
            )
            db.add(hist)
        except Exception:
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
