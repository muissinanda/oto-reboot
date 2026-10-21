import time
import asyncio
import re
import urllib.request
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

from app.database import SessionLocal, NetworkDevice, DeviceInterface, DeviceBgpPeer, NetworkTrafficHistory, now_wib

# Standard System OIDs (RFC 1213)
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"

# Host Resources MIB (Standard RFC 2790 for Linux, AP, MikroTik, Juniper)
OID_HR_PROCESSOR_LOAD = "1.3.6.1.2.1.25.3.3.1.2"      # CPU Cores load table
OID_HR_STORAGE_DESCR = "1.3.6.1.2.1.25.2.3.1.3"       # Storage Descr (RAM)
OID_HR_STORAGE_ALLOC_UNITS = "1.3.6.1.2.1.25.2.3.1.4" # Storage Allocation Units
OID_HR_STORAGE_SIZE = "1.3.6.1.2.1.25.2.3.1.5"        # Storage Total Units
OID_HR_STORAGE_USED = "1.3.6.1.2.1.25.2.3.1.6"        # Storage Used Units

# BGP4-MIB (RFC 4273 / RFC 1657 - Universal Standard for Juniper, MikroTik, Cisco, Linux)
OID_BGP_LOCAL_AS = "1.3.6.1.2.1.15.2.0"                  # Local Autonomous System
OID_BGP_IDENTIFIER = "1.3.6.1.2.1.15.4.0"                # BGP Router-ID (IPv4)
OID_BGP_PEER_STATE = "1.3.6.1.2.1.15.3.1.2"              # 1:idle, 2:connect, 3:active, 4:opensent, 5:openconfirm, 6:established
OID_BGP_PEER_ADMIN_STATUS = "1.3.6.1.2.1.15.3.1.3"       # 1:stop, 2:start
OID_BGP_PEER_REMOTE_AS = "1.3.6.1.2.1.15.3.1.9"          # Remote ASN
OID_BGP_PEER_IN_UPDATES = "1.3.6.1.2.1.15.3.1.10"        # In Updates
OID_BGP_PEER_OUT_UPDATES = "1.3.6.1.2.1.15.3.1.11"       # Out Updates
OID_BGP_PEER_IN_MSGS = "1.3.6.1.2.1.15.3.1.12"           # In Total Messages
OID_BGP_PEER_OUT_MSGS = "1.3.6.1.2.1.15.3.1.13"          # Out Total Messages
OID_BGP_PEER_EST_TIME = "1.3.6.1.2.1.15.3.1.16"          # Elapsed Time in Established (seconds)

# Juniper BGP Prefix MIB (BGP4-V2-MIB-JUNIPER)
OID_JNX_BGP_PREFIX_ACCEPTED = "1.3.6.1.4.1.2636.5.1.1.2.6.2.1.8" # Accepted Prefixes
OID_JNX_BGP_PREFIX_TOTAL = "1.3.6.1.4.1.2636.5.1.1.2.6.2.1.7"    # Total In-Prefixes
OID_JNX_BGP_PEER_REMOTE_ADDR = "1.3.6.1.4.1.2636.5.1.1.2.1.1.1.11" # Peer Remote IP address
OID_CISCO_BGP_PREFIX_ACCEPTED = "1.3.6.1.4.1.9.9.187.1.2.4.1.1" # Cisco BGP Accepted Prefixes
OID_BGP_PEER_LOCAL_ADDR = "1.3.6.1.2.1.15.3.1.5"                 # BGP Local IP Address for peering
OID_IP_AD_ENT_IF_INDEX = "1.3.6.1.2.1.4.20.1.2"                  # IP Address to ifIndex mapping
OID_IP_ROUTE_IF_INDEX = "1.3.6.1.2.1.4.21.1.7"                   # Route to ifIndex mapping

# Juniper Operating Sensors (JUNIPER-MIB - Routing Engine, FPC, Chassis)
OID_JNX_OPERATING_CPU = "1.3.6.1.4.1.2636.3.1.13.1.8"     # CPU % (Routing Engine 0 index .9.1.0.0 dll)
OID_JNX_OPERATING_TEMP = "1.3.6.1.4.1.2636.3.1.13.1.7"    # Temperature (°C)
OID_JNX_OPERATING_BUFFER = "1.3.6.1.4.1.2636.3.1.13.1.11" # Buffer / Memory pool %
OID_JNX_OPERATING_DRAM = "1.3.6.1.4.1.2636.3.1.13.1.12"   # Installed DRAM bytes

# Juniper Digital Optical Monitoring (JUNIPER-DOM-MIB - SFP/XFP/QSFP Transceivers)
OID_JNX_DOM_TEMP = "1.3.6.1.4.1.2636.3.60.1.1.1.1.2"      # Transceiver Temp (°C)
OID_JNX_DOM_VOLT = "1.3.6.1.4.1.2636.3.60.1.1.1.1.3"      # Transceiver Voltage (mV)
OID_JNX_DOM_TX_PWR = "1.3.6.1.4.1.2636.3.60.1.1.1.1.4"    # Tx Power (0.01 dBm)
OID_JNX_DOM_RX_PWR = "1.3.6.1.4.1.2636.3.60.1.1.1.1.5"    # Rx Power / Redaman (0.01 dBm)
OID_JNX_DOM_TX_LOS = "1.3.6.1.4.1.2636.3.60.1.1.1.1.6"    # Tx Loss of Signal (1=True)
OID_JNX_DOM_RX_LOS = "1.3.6.1.4.1.2636.3.60.1.1.1.1.7"    # Rx Loss of Signal (1=True, 2=False)

# Cisco Hardware Sensors
OID_CISCO_CPU_5MIN = "1.3.6.1.4.1.9.9.109.1.1.1.1.5"      # 5-min CPU %
OID_CISCO_CPU_OLD = "1.3.6.1.4.1.9.2.1.56.0"              # Legacy avgBusy5
OID_CISCO_TEMP = "1.3.6.1.4.1.9.9.13.1.3.1.3"             # ciscoEnvMonTemperature (°C)
OID_CISCO_MEM_USED = "1.3.6.1.4.1.9.9.48.1.1.1.5"         # Memory Pool Used bytes
OID_CISCO_MEM_FREE = "1.3.6.1.4.1.9.9.48.1.1.1.6"         # Memory Pool Free bytes

# Entity Sensor MIB (RFC 3433)
OID_ENT_PHY_SENSOR_VALUE = "1.3.6.1.2.1.99.1.1.1.4"        # Temperature / Fan / Power values

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

# Well-Known AS Numbers Directory
KNOWN_ASNS = {
    13335: "Cloudflare",
    15169: "Google",
    7713: "Telkom Indonesia",
    9905: "PT Link Net Tbk",
    64302: "IDREN - Indonesia Research & Education Network",
    132678: "Universitas Jember",
    24203: "Telkomsel",
    17995: "Indosat Ooredoo",
    23947: "Moratelindo (Oxygen)",
    4761: "Indonet",
    55688: "APJII / IIX",
    131755: "OpenIXP",
    24522: "Biznet Networks",
    9341: "Cyberindo Aditama (CBN)",
    136052: "Cyber Network Indonesia",
    38781: "Link Net / First Media",
    45727: "XL Axiata",
    20940: "Akamai",
    32934: "Meta (Facebook)",
    8075: "Microsoft",
    16509: "Amazon (AWS)",
    13414: "Twitter / X",
    2635: "APNIC",
    4637: "Telstra",
    6939: "Hurricane Electric (bgp.he.net)",
    3356: "Lumen / Level3",
    2914: "NTT Communications",
    6453: "Tata Communications",
    174: "Cogent",
    9002: "RETN",
    1299: "Arelion / Telia",
    37963: "Alibaba Cloud",
    45102: "Alibaba Cloud",
    132203: "Tencent Cloud",
    24086: "CBN Nusantara",
}

# Cache in-memory untuk ASN lookup dari Hurricane Electric (bgp.he.net)
ASN_CACHE: Dict[int, str] = dict(KNOWN_ASNS)

def parse_ip_address(val: Any) -> str:
    """Format PySNMP IpAddress / OctetString secara konsisten menjadi format IPv4 dotted-quad"""
    if val is None:
        return ""
    try:
        if hasattr(val, "prettyPrint"):
            s = str(val.prettyPrint()).strip()
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", s):
                return s
        if hasattr(val, "asNumbers"):
            nums = list(val.asNumbers())
            if len(nums) == 4:
                return ".".join(str(b) for b in nums)
        raw_b = bytes(val)
        if len(raw_b) == 4:
            return ".".join(str(b) for b in raw_b)
    except Exception:
        pass
    return str(val).strip()

def fetch_asn_from_he(asn: int, timeout: float = 3.5) -> Optional[str]:
    """Mengambil nama organisasi/provider resmi dari Hurricane Electric (https://bgp.he.net/AS{asn})"""
    if not asn or asn <= 0:
        return None
    
    url = f"https://bgp.he.net/AS{asn}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            html = resp.read().decode("utf-8", errors="ignore")
            
            m_h1 = re.search(r'<h1><a[^>]*>(?:AS\d+\s+)?([^<]+)</a>', html)
            if m_h1:
                name = m_h1.group(1).strip()
                if name:
                    return name
            
            m_title = re.search(r'<title>(?:AS\d+\s+)?(.*?)(?:\s+-\s+bgp\.he\.net)?</title>', html, re.IGNORECASE)
            if m_title:
                name = m_title.group(1).strip()
                if name and "bgp.he.net" not in name.lower():
                    return name
    except Exception:
        pass
    return None

def resolve_asn_name(asn: Optional[int], fetch_remote: bool = True) -> Optional[str]:
    """Mengembalikan nama provider AS dengan prioritas in-memory cache -> Hurricane Electric (bgp.he.net)"""
    if not asn or asn <= 0:
        return None
    if asn in ASN_CACHE:
        return ASN_CACHE[asn]
    if fetch_remote:
        he_name = fetch_asn_from_he(asn)
        if he_name:
            ASN_CACHE[asn] = he_name
            return he_name
    return f"AS{asn}"

async def resolve_asn_name_async(asn: Optional[int]) -> Optional[str]:
    """Versi asinkron non-blocking untuk resolving ASN dari bgp.he.net tanpa menghambat event loop"""
    if not asn or asn <= 0:
        return None
    if asn in ASN_CACHE:
        return ASN_CACHE[asn]
    loop = asyncio.get_event_loop()
    name = await loop.run_in_executor(None, fetch_asn_from_he, asn)
    if name:
        ASN_CACHE[asn] = name
        return name
    return f"AS{asn}"

def lookup_asn_name(asn: Optional[int]) -> Optional[str]:
    """Alias kompatibel lookup nama ASN"""
    return resolve_asn_name(asn, fetch_remote=False)

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
            if "sfpplus" in n or "sfp+" in n or n.startswith("xe-"):
                return "10G SFP+"
            return "1G SFP" if ("sfp" in n or n.startswith("ge-")) else "1 Gbps"
        if high_speed >= 100:
            return "100 Mbps"
    
    # Deteksi berbasis nama port router (Juniper xe/ge/et, MikroTik CCR2004, CRS, Cisco Te/Gi/Hu)
    if n.startswith("et-") or "qsfp28" in n or "100g" in n or n.startswith("hu") or n.startswith("fo"):
        return "100G QSFP28"
    if "sfp28" in n or "25g" in n or n.startswith("tf") or n.startswith("twentyfive"):
        return "25G SFP28"
    if n.startswith("xe-") or "sfpplus" in n or "sfp+" in n or "10g" in n or n.startswith("te") or n.startswith("ten"):
        return "10G SFP+"
    if "qsfp" in n or "40g" in n or n.startswith("fo"):
        return "40G QSFP+"
    if n.startswith("ge-") or "sfp" in n or n.startswith("gi") or n.startswith("gig"):
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
    if any(k in n for k in ["ether", "sfp", "ge-", "xe-", "et-", "ge", "xe", "fa", "gi", "te", "port"]) or if_type_num == 6:
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
                    raw_lower = raw_descr.lower()
                    if any(k in raw_lower for k in ["routeros", "mikrotik", "rb"]):
                        dev.device_type = "mikrotik"
                    elif any(k in raw_lower for k in ["juniper", "junos", "jnp"]):
                        dev.device_type = "juniper"
                    elif any(k in raw_lower for k in ["cisco", "ios"]):
                        dev.device_type = "cisco"
                    elif any(k in raw_lower for k in ["huawei", "vrp"]):
                        dev.device_type = "huawei"
                    elif any(k in raw_lower for k in ["linux", "ubuntu", "debian", "alpine"]):
                        dev.device_type = "linux"
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
        # LANGKAH 2: SUHU & TEGANGAN (ROUTEROS, JUNIPER, CISCO, ENTITY MIB)
        # -----------------------------------------------------------------
        try:
            # 2a. RouterOS 7 Health Item Table
            h_names = await walk_oid_column(snmp_engine, auth_data, transport, OID_MT_HEALTH_NAME, 20)
            if h_names:
                h_vals = await walk_oid_column(snmp_engine, auth_data, transport, OID_MT_HEALTH_VALUE, 20)
                for idx, name_raw in h_names.items():
                    name_str = str(name_raw).lower()
                    val_raw = h_vals.get(idx)
                    if val_raw is not None:
                        try:
                            num_val = float(val_raw)
                            if "temp" in name_str and num_val > 0:
                                parsed_t = round(num_val / 10.0 if num_val > 150 else num_val, 1)
                                if "cpu" in name_str or dev.temperature is None:
                                    dev.temperature = parsed_t
                            elif "volt" in name_str and num_val > 0:
                                parsed_v = round(num_val / 10.0 if num_val > 50 else num_val, 1)
                                dev.voltage = parsed_v
                        except Exception:
                            pass

            # 2b. RouterOS 6 Legacy OIDs
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

            # 2c. Juniper Operating Temperature (JUNIPER-MIB: jnxOperatingTemp)
            if dev.temperature is None:
                jnx_temps = await walk_oid_column(snmp_engine, auth_data, transport, OID_JNX_OPERATING_TEMP, 20)
                if jnx_temps:
                    valid_temps = []
                    for t_idx, t_val in jnx_temps.items():
                        try:
                            f_t = float(t_val)
                            if 15.0 <= f_t <= 115.0:
                                valid_temps.append((str(t_idx), f_t))
                        except Exception:
                            pass
                    if valid_temps:
                        re_temps = [t for idx_s, t in valid_temps if any(x in idx_s for x in ["9.1", "7.1", "1.1"])]
                        chosen_t = re_temps[0] if re_temps else max(t for _, t in valid_temps)
                        dev.temperature = round(chosen_t, 1)

            # 2d. Cisco Temperature Sensor
            if dev.temperature is None:
                err_ind, err_stat, _, c_vbs = await get_cmd(
                    snmp_engine, auth_data, transport, ContextData(),
                    ObjectType(ObjectIdentity(OID_CISCO_TEMP))
                )
                if not err_ind and not err_stat and c_vbs:
                    try:
                        c_t = float(c_vbs[0][1])
                        if 15.0 <= c_t <= 115.0:
                            dev.temperature = round(c_t, 1)
                    except Exception:
                        pass
        except Exception:
            pass

        # -----------------------------------------------------------------
        # LANGKAH 3: CPU & MEMORY USAGE (JUNIPER, MIKROTIK, CISCO, HOST-RESOURCES)
        # -----------------------------------------------------------------
        try:
            # 3a. CPU Load: Prioritaskan Juniper jnxOperatingCPU jika perangkat Juniper
            if dev.device_type == "juniper" or dev.cpu_usage is None or dev.cpu_usage == 0.0:
                jnx_cpus = await walk_oid_column(snmp_engine, auth_data, transport, OID_JNX_OPERATING_CPU, 20)
                if jnx_cpus:
                    valid_cpus = []
                    for c_idx, c_val in jnx_cpus.items():
                        try:
                            f_c = float(c_val)
                            if 0.0 <= f_c <= 100.0:
                                valid_cpus.append((str(c_idx), f_c))
                        except Exception:
                            pass
                    if valid_cpus:
                        re_cpus = [c for idx_s, c in valid_cpus if any(x in idx_s for x in ["9.1", "7.1", "1.1"])]
                        chosen_cpu = re_cpus[0] if re_cpus else max(c for _, c in valid_cpus)
                        dev.cpu_usage = round(chosen_cpu, 1)

            # CPU Load via Host Resources MIB (hrProcessorLoad - multi-core support)
            if dev.cpu_usage is None:
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

            # Cisco CPU Fallback (5-min average)
            if dev.cpu_usage is None:
                err_ind, err_stat, _, c_vbs = await get_cmd(
                    snmp_engine, auth_data, transport, ContextData(),
                    ObjectType(ObjectIdentity(OID_CISCO_CPU_5MIN)),
                    ObjectType(ObjectIdentity(OID_CISCO_CPU_OLD))
                )
                if not err_ind and not err_stat and c_vbs:
                    for vb in c_vbs:
                        try:
                            f_c = float(vb[1])
                            if 0.0 <= f_c <= 100.0:
                                dev.cpu_usage = round(f_c, 1)
                                break
                        except Exception:
                            pass

            # Fallback legacy MikroTik CPU scalar
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

            # 3b. RAM Memory: Juniper Buffer & DRAM MIB
            if dev.device_type == "juniper" or dev.memory_usage is None:
                jnx_bufs = await walk_oid_column(snmp_engine, auth_data, transport, OID_JNX_OPERATING_BUFFER, 15)
                if jnx_bufs:
                    for b_idx, b_val in jnx_bufs.items():
                        try:
                            f_b = float(b_val)
                            if 0.0 < f_b <= 100.0:
                                dev.memory_usage = round(f_b, 1)
                                break
                        except Exception:
                            pass
                
                jnx_drams = await walk_oid_column(snmp_engine, auth_data, transport, OID_JNX_OPERATING_DRAM, 15)
                if jnx_drams:
                    for d_idx, d_val in jnx_drams.items():
                        try:
                            dram_bytes = float(d_val)
                            if dram_bytes > (64 * 1024 * 1024):
                                dev.memory_total_mb = round(dram_bytes / (1024 * 1024), 1)
                                if dev.memory_usage is not None:
                                    dev.memory_used_mb = round(dev.memory_total_mb * (dev.memory_usage / 100.0), 1)
                                break
                        except Exception:
                            pass

            # Host Resources Storage MIB (RAM)
            if dev.memory_usage is None:
                stor_descrs = await walk_oid_column(snmp_engine, auth_data, transport, OID_HR_STORAGE_DESCR, 25)
                ram_idx = None
                for idx, descr_val in stor_descrs.items():
                    d_str = str(descr_val).lower()
                    if any(k in d_str for k in ["main memory", "ram", "physical memory", "system memory", "routing engine", "dram", "kernel memory", "system storage"]):
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

            # Fallback legacy MikroTik RAM scalar
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
        # LANGKAH 4: INTERFACES, TRAFFIC RATE & DETAIL SFP / OPTIK (MIKROTIK & JUNIPER DOM)
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

                # 4a. Ambil data tabel Optical SFP MikroTik (DDM)
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

                # 4b. Ambil data Juniper Optical DOM (JUNIPER-DOM-MIB: jnxDomCurrentTable)
                jnx_optical_by_idx = {}
                try:
                    jnx_rx_pwr = await walk_oid_column(snmp_engine, auth_data, transport, OID_JNX_DOM_RX_PWR, 25)
                    if jnx_rx_pwr:
                        res_jnx_dom = await asyncio.gather(
                            walk_oid_column(snmp_engine, auth_data, transport, OID_JNX_DOM_TX_PWR, 25),
                            walk_oid_column(snmp_engine, auth_data, transport, OID_JNX_DOM_TEMP, 25),
                            walk_oid_column(snmp_engine, auth_data, transport, OID_JNX_DOM_VOLT, 25),
                            walk_oid_column(snmp_engine, auth_data, transport, OID_JNX_DOM_RX_LOS, 25),
                            return_exceptions=True
                        )
                        jnx_tx_pwr = res_jnx_dom[0] if isinstance(res_jnx_dom[0], dict) else {}
                        jnx_dom_temp = res_jnx_dom[1] if isinstance(res_jnx_dom[1], dict) else {}
                        jnx_dom_volt = res_jnx_dom[2] if isinstance(res_jnx_dom[2], dict) else {}
                        jnx_dom_los = res_jnx_dom[3] if isinstance(res_jnx_dom[3], dict) else {}

                        for j_idx, raw_rx in jnx_rx_pwr.items():
                            try:
                                f_rx = float(raw_rx)
                                is_loss = (f_rx <= -3500) or (int(jnx_dom_los.get(j_idx, 2)) == 1)
                                parsed_rx = round(f_rx / 100.0, 2)
                                
                                raw_tx = jnx_tx_pwr.get(j_idx)
                                parsed_tx = round(float(raw_tx) / 100.0, 2) if raw_tx is not None else None
                                
                                raw_t = jnx_dom_temp.get(j_idx)
                                parsed_t = round(float(raw_t), 1) if raw_t is not None else None
                                
                                raw_v = jnx_dom_volt.get(j_idx)
                                parsed_v = round(float(raw_v) / 1000.0, 2) if (raw_v is not None and float(raw_v) > 100) else (float(raw_v) if raw_v is not None else None)

                                jnx_optical_by_idx[j_idx] = {
                                    "rx_loss": is_loss,
                                    "tx_fault": False,
                                    "temperature": parsed_t,
                                    "voltage": parsed_v,
                                    "tx_power": parsed_tx,
                                    "rx_power": parsed_rx,
                                    "vendor": "Juniper / Optical",
                                }
                            except Exception:
                                pass
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
                    
                    is_sfp_port = (
                        ("sfp" in if_name.lower()) or 
                        if_name.lower().startswith("xe-") or 
                        if_name.lower().startswith("et-") or 
                        ("10g" in if_name.lower()) or
                        (speed_mbps_val is not None and speed_mbps_val >= 10000) or
                        (if_name.lower() in optical_by_name) or
                        (if_idx in jnx_optical_by_idx)
                    )

                    opt_data = optical_by_name.get(if_name.lower()) or jnx_optical_by_idx.get(if_idx, {})

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
                        iface_obj.sfp_vendor = opt_data.get("vendor") or iface_obj.sfp_vendor
                        iface_obj.sfp_part_number = opt_data.get("part") or iface_obj.sfp_part_number
                        iface_obj.sfp_serial = opt_data.get("serial") or iface_obj.sfp_serial
                        iface_obj.sfp_wavelength = opt_data.get("wavelength") or iface_obj.sfp_wavelength
                        iface_obj.sfp_temperature = opt_data.get("temperature") or iface_obj.sfp_temperature
                        iface_obj.sfp_voltage = opt_data.get("voltage") or iface_obj.sfp_voltage
                        iface_obj.sfp_tx_power = opt_data.get("tx_power") if opt_data.get("tx_power") is not None else iface_obj.sfp_tx_power
                        iface_obj.sfp_rx_power = opt_data.get("rx_power") if opt_data.get("rx_power") is not None else iface_obj.sfp_rx_power
                        iface_obj.sfp_rx_loss = opt_data.get("rx_loss", iface_obj.sfp_rx_loss)
                        iface_obj.sfp_tx_fault = opt_data.get("tx_fault", iface_obj.sfp_tx_fault)

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
            pass

        # -----------------------------------------------------------------
        # LANGKAH 5: SENSOR PROTOKOL BGP (BORDER GATEWAY PROTOCOL - RFC 4273 / 1657)
        # -----------------------------------------------------------------
        try:
            # Query Router-ID dan Local AS
            err_ind, err_stat, _, bgp_basics = await get_cmd(
                snmp_engine, auth_data, transport, ContextData(),
                ObjectType(ObjectIdentity(OID_BGP_LOCAL_AS)),
                ObjectType(ObjectIdentity(OID_BGP_IDENTIFIER))
            )
            if not err_ind and not err_stat and bgp_basics:
                for vb in bgp_basics:
                    o_str = str(vb[0])
                    if o_str.startswith(OID_BGP_LOCAL_AS[:-2]):
                        try:
                            dev.bgp_local_as = int(vb[1])
                        except Exception:
                            pass
                    elif o_str.startswith(OID_BGP_IDENTIFIER[:-2]):
                        dev.bgp_router_id = parse_ip_address(vb[1])

            # Query tabel BGP Peer State
            peer_states = await walk_oid_column(snmp_engine, auth_data, transport, OID_BGP_PEER_STATE, 50)
            if peer_states:
                res_bgp = await asyncio.gather(
                    walk_oid_column(snmp_engine, auth_data, transport, OID_BGP_PEER_REMOTE_AS, 50),
                    walk_oid_column(snmp_engine, auth_data, transport, OID_BGP_PEER_ADMIN_STATUS, 50),
                    walk_oid_column(snmp_engine, auth_data, transport, OID_BGP_PEER_IN_UPDATES, 50),
                    walk_oid_column(snmp_engine, auth_data, transport, OID_BGP_PEER_OUT_UPDATES, 50),
                    walk_oid_column(snmp_engine, auth_data, transport, OID_BGP_PEER_IN_MSGS, 50),
                    walk_oid_column(snmp_engine, auth_data, transport, OID_BGP_PEER_OUT_MSGS, 50),
                    walk_oid_column(snmp_engine, auth_data, transport, OID_BGP_PEER_EST_TIME, 50),
                    walk_oid_column(snmp_engine, auth_data, transport, OID_JNX_BGP_PREFIX_ACCEPTED, 50),
                    walk_oid_column(snmp_engine, auth_data, transport, OID_JNX_BGP_PEER_REMOTE_ADDR, 50),
                    walk_oid_column(snmp_engine, auth_data, transport, OID_CISCO_BGP_PREFIX_ACCEPTED, 50),
                    walk_oid_column(snmp_engine, auth_data, transport, OID_BGP_PEER_LOCAL_ADDR, 50),
                    walk_oid_column(snmp_engine, auth_data, transport, OID_IP_AD_ENT_IF_INDEX, 50),
                    walk_oid_column(snmp_engine, auth_data, transport, OID_IP_ROUTE_IF_INDEX, 50),
                    return_exceptions=True
                )
                bgp_rem_as = res_bgp[0] if isinstance(res_bgp[0], dict) else {}
                bgp_admin = res_bgp[1] if isinstance(res_bgp[1], dict) else {}
                bgp_in_up = res_bgp[2] if isinstance(res_bgp[2], dict) else {}
                bgp_out_up = res_bgp[3] if isinstance(res_bgp[3], dict) else {}
                bgp_in_msg = res_bgp[4] if isinstance(res_bgp[4], dict) else {}
                bgp_out_msg = res_bgp[5] if isinstance(res_bgp[5], dict) else {}
                bgp_est_time = res_bgp[6] if isinstance(res_bgp[6], dict) else {}
                bgp_prefixes = res_bgp[7] if isinstance(res_bgp[7], dict) else {}
                bgp_jnx_addrs = res_bgp[8] if isinstance(res_bgp[8], dict) else {}
                bgp_cisco_prefs = res_bgp[9] if isinstance(res_bgp[9], dict) else {}
                bgp_loc_addrs = res_bgp[10] if len(res_bgp) > 10 and isinstance(res_bgp[10], dict) else {}
                ip_if_indices = res_bgp[11] if len(res_bgp) > 11 and isinstance(res_bgp[11], dict) else {}
                ip_route_indices = res_bgp[12] if len(res_bgp) > 12 and isinstance(res_bgp[12], dict) else {}

                # Buat mapping Juniper peer index ke IP address
                jnx_ip_to_idx = {}
                for j_idx, j_addr_raw in bgp_jnx_addrs.items():
                    addr_s = parse_ip_address(j_addr_raw)
                    if addr_s:
                        jnx_ip_to_idx[addr_s] = str(j_idx)

                BGP_STATE_MAP = {
                    1: "idle",
                    2: "connect",
                    3: "active",
                    4: "opensent",
                    5: "openconfirm",
                    6: "established"
                }

                existing_peers = {
                    p.peer_ip: p
                    for p in db.query(DeviceBgpPeer).filter(DeviceBgpPeer.device_id == dev.id).all()
                }

                active_peer_ips = set()
                est_count = 0

                for p_ip_raw, state_raw in peer_states.items():
                    peer_ip = str(p_ip_raw).strip()
                    active_peer_ips.add(peer_ip)
                    
                    st_num = int(state_raw) if state_raw is not None else 1
                    st_str = BGP_STATE_MAP.get(st_num, "idle")
                    if st_num == 6:
                        est_count += 1

                    r_as = int(bgp_rem_as.get(p_ip_raw, 0)) if bgp_rem_as.get(p_ip_raw) else None
                    as_org = await resolve_asn_name_async(r_as)

                    admin_val = int(bgp_admin.get(p_ip_raw, 2)) if bgp_admin.get(p_ip_raw) else 2
                    admin_str = "start" if admin_val == 2 else "stop"

                    in_u = int(bgp_in_up.get(p_ip_raw, 0)) if bgp_in_up.get(p_ip_raw) else 0
                    out_u = int(bgp_out_up.get(p_ip_raw, 0)) if bgp_out_up.get(p_ip_raw) else 0
                    in_m = int(bgp_in_msg.get(p_ip_raw, 0)) if bgp_in_msg.get(p_ip_raw) else 0
                    out_m = int(bgp_out_msg.get(p_ip_raw, 0)) if bgp_out_msg.get(p_ip_raw) else 0
                    est_sec = int(bgp_est_time.get(p_ip_raw, 0)) if bgp_est_time.get(p_ip_raw) else 0
                    uptime_str = format_uptime(est_sec * 100) if est_sec > 0 else "-"

                    # Prefix count matching: Juniper / Cisco / Standard
                    pref_count = None
                    if p_ip_raw in bgp_prefixes:
                        try:
                            pref_count = int(bgp_prefixes[p_ip_raw])
                        except Exception:
                            pass
                    
                    if pref_count is None and peer_ip in jnx_ip_to_idx:
                        j_p_idx = jnx_ip_to_idx[peer_ip]
                        for k_p, v_p in bgp_prefixes.items():
                            if str(k_p).startswith(j_p_idx):
                                try:
                                    pref_count = int(v_p)
                                    break
                                except Exception:
                                    pass

                    if pref_count is None:
                        for k_pref, v_pref in bgp_prefixes.items():
                            if str(p_ip_raw) in str(k_pref):
                                try:
                                    pref_count = int(v_pref)
                                    break
                                except Exception:
                                    pass

                    if pref_count is None and p_ip_raw in bgp_cisco_prefs:
                        try:
                            pref_count = int(bgp_cisco_prefs[p_ip_raw])
                        except Exception:
                            pass

                    # Deteksi Interface Port untuk BGP Peer
                    loc_ip_raw = bgp_loc_addrs.get(p_ip_raw)
                    loc_ip_str = parse_ip_address(loc_ip_raw) if loc_ip_raw else None
                    detected_iface_name = None

                    # 1. Cek via ipAdEntIfIndex (mapping IP lokal ke ifIndex)
                    if loc_ip_str:
                        for ip_k, if_v in ip_if_indices.items():
                            if loc_ip_str in str(ip_k):
                                try:
                                    t_idx = int(if_v)
                                    if t_idx in existing_interfaces:
                                        detected_iface_name = existing_interfaces[t_idx].name
                                        break
                                except Exception:
                                    pass

                    # 2. Cek via ipRouteIfIndex (route next-hop ke peer_ip)
                    if not detected_iface_name:
                        for route_k, if_v in ip_route_indices.items():
                            if peer_ip in str(route_k):
                                try:
                                    t_idx = int(if_v)
                                    if t_idx in existing_interfaces:
                                        detected_iface_name = existing_interfaces[t_idx].name
                                        break
                                except Exception:
                                    pass

                    # 3. Cek via keyword provider pada alias atau nama interface
                    if not detected_iface_name and r_as:
                        kw = None
                        if r_as == 7713 or "telkom" in (as_org or "").lower():
                            kw = "telkom"
                        elif r_as == 9905 or "linknet" in (as_org or "").lower() or "link net" in (as_org or "").lower():
                            kw = "linknet"
                        elif r_as == 64302 or "idren" in (as_org or "").lower():
                            kw = "idren"

                        if kw:
                            for _idx, _iface in existing_interfaces.items():
                                if kw in (_iface.alias or "").lower() or kw in _iface.name.lower():
                                    detected_iface_name = _iface.name
                                    break

                    now_p_dt = now_wib()
                    if peer_ip in existing_peers:
                        p_obj = existing_peers[peer_ip]
                        p_obj.remote_as = r_as
                        p_obj.as_name = as_org
                        p_obj.state = st_str
                        p_obj.admin_status = admin_str
                        p_obj.in_updates = in_u
                        p_obj.out_updates = out_u
                        p_obj.in_total_messages = in_m
                        p_obj.out_total_messages = out_m
                        p_obj.fsm_established_time = est_sec
                        p_obj.uptime = uptime_str
                        if pref_count is not None:
                            p_obj.accepted_prefixes = pref_count
                        if detected_iface_name:
                            p_obj.interface_name = detected_iface_name
                        if loc_ip_str:
                            p_obj.local_ip = loc_ip_str
                        p_obj.last_updated = now_p_dt
                    else:
                        p_obj = DeviceBgpPeer(
                            device_id=dev.id,
                            peer_ip=peer_ip,
                            remote_as=r_as,
                            as_name=as_org,
                            interface_name=detected_iface_name,
                            local_ip=loc_ip_str,
                            state=st_str,
                            admin_status=admin_str,
                            in_updates=in_u,
                            out_updates=out_u,
                            in_total_messages=in_m,
                            out_total_messages=out_m,
                            fsm_established_time=est_sec,
                            uptime=uptime_str,
                            accepted_prefixes=pref_count,
                            last_updated=now_p_dt
                        )
                        db.add(p_obj)

                # Hapus peer yang sudah tidak ada
                for old_ip, old_obj in existing_peers.items():
                    if old_ip not in active_peer_ips:
                        db.delete(old_obj)

                dev.bgp_peer_count = len(active_peer_ips)
                dev.bgp_established_count = est_count
        except Exception:
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
