# Author: ud3v0id
import argparse
import hashlib
import logging
import struct
import time
import sys
from typing import Iterable, Optional

import serial
import serial.tools.list_ports

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] : %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("mtktool")

MAGIC = 0xFEEEEEEF
DATA_PROTOCOL = 1
CMD_BOOT_TO = 0x010008
CMD_SYNC_SIGNAL = 0x434E5953

# --- Helpers: parameter parsing/validation ---
# Split helper reused by streaming validators/flows
def _split_stream_tokens(tokens):
    data_files = []
    out_file = None
    hex_tokens = []
    for t in tokens or []:
        if t.startswith("@out:") or t.startswith(">"):
            out_file = t.split(":", 1)[1] if ":" in t else t[1:]
        elif t.startswith("@"):
            data_files.append(t[1:])
        else:
            hex_tokens.append(t)
    return hex_tokens, data_files, out_file

def _auto_pick_port(vid: int):
    """Pick first serial port matching VID."""
    for p in serial.tools.list_ports.comports():
        if p.vid == vid:
            return p.device
    return None

class SerialSession:
    """Context manager for serial port lifecycle."""
    def __init__(self, port: str, baud: int, timeout: float = 2.0):
        self.port = port
        self.baud = baud
        self.timeout = timeout
        self.ser: Optional[serial.Serial] = None

    def __enter__(self):
        self.ser = serial.Serial(self.port, self.baud, timeout=self.timeout, write_timeout=self.timeout)
        return self.ser

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.ser:
            self.ser.close()
        return False

# CLI parameter parser shared by preloader/DA commands
def _parse_param_tokens(tokens):
    """
    Parse CLI params into bytes.
    Supported formats:
      - Hex byte tokens: 00 FF 0a or 0x1F
      - Raw hex string (even length, >2 chars): 00112233 -> b"\\x00\\x11\\x22\\x33"
      - @file: binary content of file
    """
    buf = bytearray()
    for t in tokens:
        if t.startswith("@"):
            buf.extend(open(t[1:], "rb").read())
            continue
        tok = t.lower()
        # Raw hex string of even length
        if all(c in "0123456789abcdef" for c in tok) and len(tok) > 2:
            if len(tok) % 2 != 0:
                raise ValueError(f"Hex string length must be even: {t}")
            buf.extend(bytes.fromhex(tok))
            continue
        # Single byte hex (with or without 0x)
        v = int(tok, 16)
        if not (0 <= v <= 0xFF):
            raise ValueError(f"Value out of byte range: {t}")
        buf.append(v)
    return bytes(buf)

# --- DA command presets (kept for compatibility) ---
# Command presets for DA stage (non-streaming only; streaming commands are listed separately in help).
DACMD_PRESETS = {
    # 0x01xxxx primary XFlash commands (non-streaming listed here)
    "reset":            {"opcode": 0x010000, "desc": "Reset/Init (no params)", "tag": "CMD_RESET"},
    "format":           {"opcode": 0x010003, "desc": "Format flash [56B params] -> status", "tag": "CMD_FORMAT"},
    "format_partition": {"opcode": 0x010006, "desc": "Format partition [64B params] -> status", "tag": "CMD_FORMAT_PART"},
    "shutdown":         {"opcode": 0x010007, "desc": "Shutdown/Reboot [24B params] (no final status)", "tag": "CMD_SHUTDOWN"},
    "device_ctrl":      {"opcode": 0x010009, "desc": "Device control dispatcher", "tag": "CMD_DEVICE_CTRL"},
    "switch_usb_speed": {"opcode": 0x01000B, "desc": "Switch USB speed [u32 mode]", "tag": "CMD_SWITCH_USB"},
    # Streaming handlers are implemented; keep entries for completeness
    "download":         {"opcode": 0x010001, "desc": "Download (64B hdr + auto len + data stream)", "tag": "CMD_DOWNLOAD", "hidden": True},
    "upload":           {"opcode": 0x010002, "desc": "Upload (64B hdr + 16B params + data stream out)", "tag": "CMD_UPLOAD", "hidden": True},
    "write_data":       {"opcode": 0x010004, "desc": "Write data block (stream in)", "tag": "CMD_WRITE_DATA", "hidden": True},
    "read_data":        {"opcode": 0x010005, "desc": "Read data block (stream out)", "tag": "CMD_READ_DATA", "hidden": True},
    "boot_to":          {"opcode": 0x010008, "desc": "Boot to address with payload (auto len, stream)", "tag": "CMD_BOOT_TO", "hidden": True},
    "read_otp":         {"opcode": 0x01000C, "desc": "Read OTP (stream out)", "tag": "CMD_READ_OTP", "hidden": True},
    "write_otp":        {"opcode": 0x01000D, "desc": "Write OTP (auto len, stream in)", "tag": "CMD_WRITE_OTP", "hidden": True},
    "write_efuse":      {"opcode": 0x01000E, "desc": "Write eFuse (large blob)", "tag": "CMD_WRITE_EFUSE", "hidden": True},
    "read_efuse":       {"opcode": 0x01000F, "desc": "Read eFuse (large blob)", "tag": "CMD_READ_EFUSE", "hidden": True},

    # 0x04xxxx info queries
    "get_emmc_info":    {"opcode": 0x040001, "desc": "Get eMMC info (104B)", "tag": "CMD_GET_EMMC_INFO"},
    "get_nand_info":    {"opcode": 0x040002, "desc": "Get NAND info (48B)", "tag": "CMD_GET_NAND_INFO"},
    "get_nor_info":     {"opcode": 0x040003, "desc": "Get NOR info (16B)", "tag": "CMD_GET_NOR_INFO"},
    "get_ufs_info":     {"opcode": 0x040004, "desc": "Get UFS info (208B)", "tag": "CMD_GET_UFS_INFO"},
    "get_da_version":   {"opcode": 0x040005, "desc": "Get DA version string", "tag": "CMD_GET_DA_VERSION"},
    "get_packet_length": {"opcode": 0x040007, "desc": "Get packet length (write/read)", "tag": "CMD_GET_PACKET_LENGTH"},
    "get_random_id":    {"opcode": 0x040008, "desc": "Get random ID (16B)", "tag": "CMD_GET_RANDOM_ID"},
    "get_part_cata":    {"opcode": 0x040009, "desc": "Get partition table category", "tag": "CMD_GET_PART_CATA"},
    "get_usb_speed":    {"opcode": 0x04000B, "desc": "Get USB speed string", "tag": "CMD_GET_USB_SPEED"},
    "get_ram_info":     {"opcode": 0x04000C, "desc": "Get RAM info (SRAM/DRAM)", "tag": "CMD_GET_RAM_INFO"},
    "get_chip_id":      {"opcode": 0x04000D, "desc": "Get chip/hw/sw IDs (12B)", "tag": "CMD_GET_CHIP_ID"},
    "get_otp_lock":     {"opcode": 0x04000E, "desc": "Get OTP lock status", "tag": "CMD_GET_OTP_LOCK"},
    "get_batt_volt":    {"opcode": 0x04000F, "desc": "Get battery voltage", "tag": "CMD_GET_BATT_VOLT"},
    "get_rpmb_status":  {"opcode": 0x040010, "desc": "Get RPMB status", "tag": "CMD_GET_RPMB_STATUS"},
    "get_dram_type":    {"opcode": 0x040012, "desc": "Get DRAM type (LP4/LP3)", "tag": "CMD_GET_DRAM_TYPE"},
    "get_dev_fw_info":  {"opcode": 0x040013, "desc": "Get device FW info (sample)", "tag": "CMD_GET_DEV_FW_INFO"},
    "get_hrid":         {"opcode": 0x040014, "desc": "Get 128-bit HRID", "tag": "CMD_GET_HRID"},

    # 0x02xxxx control commands (DEVICE_CTRL)
    "set_battery_opt":  {"opcode": 0x020002, "desc": "Set power source [u32 mode]", "tag": "CMD_SET_POWER_SOURCE"},
    "set_meta_mode":    {"opcode": 0x020006, "desc": "Set meta boot mode [3B]", "tag": "CMD_SET_META_MODE"},
    "write_reg":        {"opcode": 0x020009, "desc": "Write register [addr(4B) val(4B)]", "tag": "CMD_WRITE_REG"},
    "rsc_info":         {"opcode": 0x02000D, "desc": "Set RSC info blob [328B/@file]", "tag": "CMD_SET_RSC_INFO"},
    "misc_param":       {"opcode": 0x02000E, "desc": "Misc param hook [u32 arg]", "tag": "CMD_MISC_PARAM"},
    "hacc_auth_cert":   {"opcode": 0x02000F, "desc": "HACC auth cert [blob/@file]", "tag": "CMD_HACC_AUTH_CERT"},
    "ufs_config":       {"opcode": 0x020011, "desc": "Set UFS config [56B/@file]", "tag": "CMD_SET_UFS_CONFIG"},
    "set_sec_policy":   {"opcode": 0x02000B, "desc": "Set security policy mask [u32 mask]", "tag": "CMD_SET_SEC_POLICY"},

    # 0x08xxxx alt entries
    "ufs_config_alt":   {"opcode": 0x080005, "desc": "Set UFS config (alt entry) [56B/@file]", "tag": "CMD_SET_UFS_CONFIG"},
    "get_pl_ver":       {"opcode": 0x080008, "desc": "Get preloader version flag", "tag": "CMD_GET_PL_VER"},
    "start_dl":         {"opcode": 0x080001, "desc": "Start download session", "tag": "CMD_START_DL"},
    "end_dl":           {"opcode": 0x080002, "desc": "End download session", "tag": "CMD_END_DL"},
    "lock_otp":         {"opcode": 0x080003, "desc": "Lock OTP zone [u32 zone]", "tag": "CMD_LOCK_OTP"},
    "emmc_hw_reset":    {"opcode": 0x080004, "desc": "eMMC HW reset", "tag": "CMD_EMMC_HW_RESET"},
    "stor_life_check":  {"opcode": 0x080007, "desc": "Storage life check", "tag": "CMD_STOR_LIFE_CHECK"},

    # 0x0Exxxx register read
    "read_reg":         {"opcode": 0x0E0003, "desc": "Read register [addr(4B) count(4B)] -> data then status", "tag": "CMD_READ_REG"},

}

# --- Preloader command presets (kept) ---
def _pcmd_meid(dev):
    dev.echo(0xE1, name="CMD_MEID")
    dev.read(1, tag="CMD_MEID")
    l = struct.unpack(">I", dev.read(4, tag="CMD_MEID"))[0]
    data = dev.read(l, tag="CMD_MEID")
    dev.read(2, tag="CMD_MEID")
    logger.info(f"MEID: {data.hex().upper()}")


def _pcmd_socid(dev):
    dev.echo(0xE7, name="CMD_SOCID")
    dev.read(1, tag="CMD_SOCID")
    l = struct.unpack(">I", dev.read(4, tag="CMD_SOCID"))[0]
    data = dev.read(l, tag="CMD_SOCID")
    dev.read(2, tag="CMD_SOCID")
    logger.info(f"SOCID: {data.hex().upper()}")


def _pcmd_hwcode(dev):
    dev.echo(0xFD, name="CMD_HWCODE")
    logger.info(f"HWCODE: {dev.read(4, tag='CMD_HWCODE').hex().upper()}")


CMD_PRESETS = {
    "hwcode": {"handler": _pcmd_hwcode, "desc": "Read HWCODE", "tag": "CMD_HWCODE"},
    "meid":   {"handler": _pcmd_meid, "desc": "Read MEID", "tag": "CMD_MEID"},
    "socid":  {"handler": _pcmd_socid, "desc": "Read SOCID", "tag": "CMD_SOCID"},
}


class MtkDevice:
    def __init__(self, debug: bool = False):
        self.vid, self.pids = 0x0E8D, (0x0003, 0x2000)
        self.debug = debug
        self.progress = False  # optional chunk progress logging
        self.write_len_override: Optional[int] = None
        self.read_len_override: Optional[int] = None
        self.ser: Optional[serial.Serial] = None
        # Minimal opcode specification to drive validation/behavior
        self.dacmd_spec = {
            # Streaming download/upload handlers where generic dacmd cannot stream.
            0x010001: {"needs_stream": True, "note": "64B header -> 8B len -> data stream"},
            0x010002: {"needs_stream": True, "note": "64B header -> 16B params -> data stream (RX)"},
            0x010004: {"needs_stream": True, "note": "56B header -> data stream"},
            0x010005: {"needs_stream": True, "note": "56B header -> data stream (RX)"},
            0x010008: {"needs_stream": True, "note": "BOOT_TO with payload"},
            0x01000C: {"needs_stream": True, "note": "Read OTP stream"},
            0x01000D: {"needs_stream": True, "note": "Write OTP stream"},
            0x01000E: {"needs_stream": True, "note": "Write efuse large blob"},
            0x01000F: {"needs_stream": True, "note": "Read efuse large blob"},
            # Parameter length / status behavior hints.
            0x010003: {"param_len": 56, "final_status": True},
            0x010006: {"param_len": 64, "final_status": True},
            0x010007: {"param_len": 24, "no_final_status": True},
            0x010009: {"device_ctrl": True},
            0x01000B: {"param_len": 4, "final_status": False},
            0x02000B: {"param_len": 4},
            0x02000E: {"param_len": 4},
            0x020011: {"param_len": 56},
            0x080003: {"param_len": 4},
            0x080005: {"param_len": 56},
            0x000000D1: {"param_len": 8},
            0x0E0003: {"param_len": 8},  # Read register: returns data payload then final status
        }

        # Protocol hints derived from DA2 reverse engineering; used by run_dacmd to
        # align TX/RX sequences and refuse unsupported streaming commands.
        self.dacmd_spec = {
            # Streaming download/upload handlers where generic dacmd cannot stream.
            0x010001: {"needs_stream": True, "note": "64B header -> 8B len -> data stream"},
            0x010002: {"needs_stream": True, "note": "64B header -> 16B params -> data stream (RX)"},
            0x010004: {"needs_stream": True, "note": "56B header -> data stream"},
            0x010005: {"needs_stream": True, "note": "56B header -> data stream (RX)"},
            0x010008: {"needs_stream": True, "note": "BOOT_TO with payload"},
            0x01000C: {"needs_stream": True, "note": "Read OTP stream"},
            0x01000D: {"needs_stream": True, "note": "Write OTP stream"},
            0x01000E: {"needs_stream": True, "note": "Write efuse large blob"},
            0x01000F: {"needs_stream": True, "note": "Read efuse large blob"},
            # Parameter length / status behavior hints.
            0x010003: {"param_len": 56, "final_status": True},
            0x010006: {"param_len": 64, "final_status": True},
            0x010007: {"param_len": 24, "no_final_status": True},
            0x010009: {"device_ctrl": True},
            0x01000B: {"param_len": 4, "final_status": False},
            0x02000E: {"param_len": 4},
            0x02000B: {"param_len": 4},
            0x020011: {"param_len": 56},
            0x080005: {"param_len": 56},
            0x080003: {"param_len": 4},
            0x000000D1: {"param_len": 8},
            0x0E0003: {"param_len": 8},  # Read register: returns data payload then final status
        }

    def write(self, data, verbose=True, tag: str = ""):
        if isinstance(data, int):
            data = bytes([data])
        elif isinstance(data, (list, bytearray)):
            data = bytes(data)
        if verbose and self.debug and data:
            ts = time.strftime("%H:%M:%S")
            t = tag or "DEFAULT"
            if len(data) > 32:
                print(f"[{ts}] [DEBUG] [{t}] [TX len={len(data)}] {data[:16].hex(' ')}...")
            else:
                print(f"[{ts}] [DEBUG] [{t}] [TX len={len(data)}] {data.hex(' ')}")
        self.ser.write(data)

    def read(self, length=1, tag: str = "", timeout: float = None) -> bytes:
        """Read up to length bytes; optional temporary timeout override."""
        old_to = self.ser.timeout
        if timeout is not None:
            self.ser.timeout = timeout
        data = self.ser.read(length)
        if timeout is not None:
            self.ser.timeout = old_to
        if self.debug and data:
            ts = time.strftime("%H:%M:%S")
            t = tag or "DEFAULT"
            if len(data) > 32:
                print(f"[{ts}] [DEBUG] [{t}] [RX len={len(data)}] {data[:16].hex(' ')}...")
            else:
                print(f"[{ts}] [DEBUG] [{t}] [RX len={len(data)}] {data.hex(' ')}")
        return data

    def echo(self, data, name="echo"):
        if isinstance(data, int):
            data = bytes([data])
        for b in data:
            target = bytes([b])
            self.write(target, tag=name)
            res = self.read(1, tag=name)
            if res != target:
                if res == b"\x00":
                    res = self.read(1, tag=name)
                if res != target:
                    raise RuntimeError(f"{name} lost: {target.hex()} vs {res.hex()}")
        return True

    def echo_block(self, data: bytes, name="echo_block"):
        self.write(data, tag=name)
        res = self.read(len(data), tag=name)
        if res != data:
            raise RuntimeError("Block sync lost")
        return True

    def xstatus(self, tag: str = "", timeout: float = None):
        """Standard XFlash Reader: Header(12B) + Body(Length)."""
        hdr = self.read(12, tag=tag or "XSTAT", timeout=timeout)
        if len(hdr) < 12:
            raise RuntimeError("XFlash header timeout")
        magic, dtype, length = struct.unpack("<III", hdr)
        if magic != MAGIC:
            raise RuntimeError(f"Bad magic in status: {hdr.hex()}")
        body = self.read(length, tag=tag or "XSTAT", timeout=timeout)
        if length == 4:
            return struct.unpack("<I", body)[0]
        return body

    def get_pkt_len(self):
        """Query packet lengths (write_len, read_len) via DEVICE_CTRL 0x040007."""
        self.xsend(struct.pack("<I", 0x010009), tag="CMD_GET_PACKET_LENGTH")
        if self._status_to_int(self.xstatus(tag="CMD_GET_PACKET_LENGTH")) != 0:
            raise RuntimeError("DEVICE_CTRL wrapper failed")
        self.xsend(struct.pack("<I", 0x040007), tag="CMD_GET_PACKET_LENGTH")
        if self._status_to_int(self.xstatus(tag="CMD_GET_PACKET_LENGTH")) not in (0,):
            raise RuntimeError("GET_PACKET_LENGTH opcode ack failed")
        payload = self.xstatus(tag="CMD_GET_PACKET_LENGTH")
        if not isinstance(payload, (bytes, bytearray)) or len(payload) != 8:
            raise RuntimeError("GET_PACKET_LENGTH returned unexpected payload")
        write_len, read_len = struct.unpack("<II", payload)
        return write_len, read_len

    def xsend(self, payload: bytes, verbose=True, tag: str = ""):
        """Standard XFlash Packager: Header + Body."""
        self.write(struct.pack("<III", MAGIC, DATA_PROTOCOL, len(payload)), verbose=verbose, tag=tag or "XSEND")
        if payload:
            for i in range(0, len(payload), 4096):
                self.write(payload[i:i + 4096], verbose=verbose, tag=tag or "XSEND")

    @staticmethod
    def _status_to_int(st):
        """Normalize xstatus return to int when possible."""
        if isinstance(st, int):
            return st
        if isinstance(st, bytes):
            if len(st) == 4:
                return int.from_bytes(st, "little")
            # Non-4-byte payload (e.g., 'preloader' string)
            try:
                text = st.decode(errors="ignore")
            except Exception:
                text = st.hex(" ")
            logger.warning(f"Unexpected status payload (len={len(st)}): {text}")
            return None
        return None

    def find_and_connect(self, da_mode=False):
        logger.info("Scanning MTK device...")
        port_info = None
        while not port_info:
            for p in serial.tools.list_ports.comports():
                if p.vid == self.vid:
                    port_info = p
                    break
            time.sleep(0.1)
        self.ser = serial.Serial(port_info.device, 115200, timeout=2.0, write_timeout=2.0)
        if da_mode:
            logger.info(f"Connected {port_info.device}, probing DA mode...")
            try:
                self.xsend(struct.pack("<I", 0x010009), tag="HS")
                self.xstatus(tag="HS")
                self.xsend(struct.pack("<I", 0x040005), tag="HS")
                self.xstatus(tag="HS")
                v = self.xstatus(tag="HS")
                st = self.xstatus(tag="HS")
                if st == 0:
                    ver = v.decode(errors='ignore').strip() if isinstance(v, bytes) else str(v)
                    logger.info(f"Device is already in DA mode! (Version: {ver})")
                    return True
            except Exception:
                pass
            logger.error("Device is NOT in DA mode.")
            self.ser.close()
            return False
        logger.info(f"Connected {port_info.device}, start handshake...")
        start, h_buf, a0_repeat = time.time(), b"", 0
        while time.time() - start < 15:
            self.write(0xA0, tag="HS")
            res = self.read(1, tag="HS")
            if res:
                if res == b"\xA0":
                    a0_repeat += 1
                    if a0_repeat >= 5:
                        logger.error("Stuck echoing 0xA0. Power off the phone completely, then reconnect.")
                        return False
                if res[0] == 0x5F:
                    break
                h_buf += res
                if b"READY" in h_buf:
                    logger.info("PRELOADER mode detected.")
                    h_buf = b""
            time.sleep(0.01)
        else:
            return False
        for v in (0x0A, 0x50, 0x05):
            self.write(v, tag="HS")
            if self.read(1, tag="HS")[0] != ((~v) & 0xFF):
                return False
        logger.info("Handshake done")
        return True

    def da1_init_pipeline(self):
        """DA1 initialization: pipelined SYNC + setup environment/hw params."""
        self.ser.reset_input_buffer()
        # Pipeline TX: SYNC -> 0x010100 -> Params (no reads between)
        self.xsend(struct.pack("<I", CMD_SYNC_SIGNAL), tag="CMD_SYNC_SIGNAL")
        self.xsend(struct.pack("<I", 0x010100), tag="CMD_SETUP_ENVIRONMENT")
        self.xsend(struct.pack("<IIII", 2, 1, 0, 0), tag="CMD_SETUP_ENVIRONMENT")
        self.xstatus(tag="CMD_SETUP_ENVIRONMENT")  # ACK for 0x010100
        # Next pipeline: 0x010101 + single param block
        self.xsend(struct.pack("<I", 0x010101), tag="CMD_SETUP_HW_INIT_PARAMS")
        self.xsend(struct.pack("<I", 0x00000000), tag="CMD_SETUP_HW_INIT_PARAMS")
        self.xstatus(tag="CMD_SETUP_HW_INIT_PARAMS")  # ACK for 0x010101
        self.xstatus(tag="CMD_SYNC_SIGNAL")  # SYNC echo from DA1
        return True

    def boot_to(self, addr: int, data: bytes, tolerate: Optional[Iterable[int]] = None):
        """BOOT_TO flow: opcode ack -> params (no ack) -> data -> final status (+optional SYNC echo)."""
        tolerate = set(tolerate or [])
        tag = "CMD_BOOT_TO"
        self.xsend(struct.pack("<I", CMD_BOOT_TO), tag=tag)
        st = self._status_to_int(self.xstatus(tag=tag, timeout=2.0))
        if st is None:
            logger.warning("BOOT_TO opcode ack returned non-integer payload; continuing")
        elif st not in (0, CMD_BOOT_TO):
            logger.warning(f"BOOT_TO opcode ack not zero: 0x{st:08X}")
        self.xsend(struct.pack("<QQ", addr, len(data)), tag=tag)
        # BOOT_TO semantics: no param ACK; send data immediately, then read final status
        self.xsend(data, tag=tag)
        st = self._status_to_int(self.xstatus(tag=tag, timeout=5.0))
        if st is None:
            raise RuntimeError("BOOT_TO data status error: non-integer status payload")
        if st not in (0, CMD_SYNC_SIGNAL) and st not in tolerate:
            raise RuntimeError(f"BOOT_TO data status error: 0x{st:08X}")
        # If DA2 success, device may send SYNC echo; wait briefly for it
        try:
            sync_echo = self.xstatus(tag=tag, timeout=2.0)
            if isinstance(sync_echo, bytes) and sync_echo == struct.pack("<I", CMD_SYNC_SIGNAL):
                logger.info("SYNC echo received after BOOT_TO.")
        except Exception:
            pass
        return st

    def _run_streaming_dacmd(self, opcode, raw_tokens):
        """
        Streaming-capable commands. Uses pkt_len hints and auto length from file.
        Supported:
          - 0x010001 Download: header (64B) + auto u64 len + data file
          - 0x010008 BootTo : addr (8B) + auto u64 len + payload file
          - 0x01000C ReadOTP: offset(4B) + len(4B) ; optional @out:path
          - 0x01000D WriteOTP: offset(4B) + auto u32 len + data file
          - 0x010002 Upload  : header(64B) + params(16B) ; stream out to host
          - 0x010004 WriteData: params(56B incl. len@16) + data file
          - 0x010005 ReadData : params(56B incl. len@16) ; stream out to host
          - 0x01000E WriteEfuse: payload(17108B) + tail(248B)
          - 0x01000F ReadEfuse : params(248B) ; return 17108B blob
        """
        write_len, read_len = self.get_pkt_len()
        if self.write_len_override:
            write_len = self.write_len_override
        if self.read_len_override:
            read_len = self.read_len_override
        logger.debug(f"[STREAM] Using write_len={write_len} read_len={read_len}")
        # Helpers

        def send_stream(data: bytes, tag: str):
            total = len(data)
            start_ts = time.time()
            for idx, i in enumerate(range(0, total, write_len), 1):
                self.xsend(data[i:i + write_len], tag=tag)
                if self.progress and total > write_len:
                    pct = min(100, int((i + write_len) * 100 / total))
                    logger.debug(f"[{tag}] stream progress: {pct}% ({idx} chunks)")
            if self.progress and total:
                dur = max(1e-6, time.time() - start_ts)
                rate = total / dur / (1024 * 1024)
                logger.info(f"[{tag}] TX {total} bytes in {dur:.2f}s ({rate:.2f} MiB/s)")

        def recv_stream(total_len: int, tag: str, ack_per_chunk: bool = False):
            chunks = []
            remaining = total_len
            chunk_idx = 0
            start_ts = time.time()
            while remaining > 0:
                chunk = self.read(min(read_len, remaining), tag=tag)
                if not chunk:
                    raise RuntimeError(f"{tag} data timeout")
                chunks.append(chunk)
                remaining -= len(chunk)
                chunk_idx += 1
                if ack_per_chunk:
                    self.write(struct.pack("<I", 0), verbose=False, tag=tag)
                if self.progress and total_len > read_len:
                    pct = min(100, int((total_len - remaining) * 100 / total_len))
                    logger.debug(f"[{tag}] stream progress: {pct}% ({chunk_idx} chunks)")
            data = b"".join(chunks)
            if self.progress and data:
                dur = max(1e-6, time.time() - start_ts)
                rate = len(data) / dur / (1024 * 1024)
                logger.info(f"[{tag}] RX {len(data)} bytes in {dur:.2f}s ({rate:.2f} MiB/s)")
            return data

        if opcode == 0x010001:  # Download
            hex_tokens, data_files, _ = _split_stream_tokens(raw_tokens)
            if not data_files:
                raise RuntimeError("Download requires a data file (@path)")
            header = _parse_param_tokens(hex_tokens)
            if len(header) != 64:
                raise RuntimeError("Download header must be exactly 64 bytes")
            data = open(data_files[0], "rb").read()
            data_len = len(data)
            tag = "CMD_DOWNLOAD"
            self.xsend(struct.pack("<I", opcode), tag=tag)
            if self._status_to_int(self.xstatus(tag=tag)) not in (0, opcode):
                raise RuntimeError("Download opcode ack failed")
            self.xsend(header, tag=tag)
            if self._status_to_int(self.xstatus(tag=tag)) != 0:
                raise RuntimeError("Download header ack failed")
            self.xsend(struct.pack("<Q", data_len), tag=tag)
            if self._status_to_int(self.xstatus(tag=tag)) != 0:
                raise RuntimeError("Download length ack failed")
            send_stream(data, tag)
            st = self._status_to_int(self.xstatus(tag=tag, timeout=5.0))
            return st, []

        if opcode == 0x010008:  # BootTo
            hex_tokens, data_files, _ = _split_stream_tokens(raw_tokens)
            if not data_files:
                raise RuntimeError("BootTo requires a payload file (@path)")
            data = open(data_files[0], "rb").read()
            data_len = len(data)
            params = _parse_param_tokens(hex_tokens)
            if len(params) != 8:
                raise RuntimeError("BootTo requires 8-byte address params")
            addr = struct.unpack("<Q", params.ljust(8, b"\x00"))[0]
            tag = "CMD_BOOT_TO"
            self.xsend(struct.pack("<I", opcode), tag=tag)
            if self._status_to_int(self.xstatus(tag=tag)) not in (0, opcode):
                raise RuntimeError("BootTo opcode ack failed")
            self.xsend(struct.pack("<QQ", addr, data_len), tag=tag)
            # No param ack; send data directly
            send_stream(data, tag)
            st = self._status_to_int(self.xstatus(tag=tag, timeout=5.0))
            return st, []

        if opcode == 0x01000D:  # Write OTP
            hex_tokens, data_files, _ = _split_stream_tokens(raw_tokens)
            if not data_files:
                raise RuntimeError("Write OTP requires a data file (@path)")
            data = open(data_files[0], "rb").read()
            params = _parse_param_tokens(hex_tokens)
            if len(params) < 4:
                raise RuntimeError("Write OTP requires offset (4B)")
            offset = params[:4]
            data_len = len(data)
            tag = "CMD_WRITE_OTP"
            self.xsend(struct.pack("<I", opcode), tag=tag)
            if self._status_to_int(self.xstatus(tag=tag)) not in (0, opcode):
                raise RuntimeError("Write OTP opcode ack failed")
            self.xsend(offset + struct.pack("<I", data_len), tag=tag)
            if self._status_to_int(self.xstatus(tag=tag)) != 0:
                raise RuntimeError("Write OTP param ack failed")
            send_stream(data, tag)
            st = self._status_to_int(self.xstatus(tag=tag, timeout=5.0))
            return st, []

        if opcode == 0x01000C:  # Read OTP
            hex_tokens, _, out_file = _split_stream_tokens(raw_tokens)
            params = _parse_param_tokens(hex_tokens)
            if len(params) < 8:
                raise RuntimeError("Read OTP requires offset(4B) + len(4B)")
            data_len = struct.unpack("<I", params[4:8])[0]
            tag = "CMD_READ_OTP"
            self.xsend(struct.pack("<I", opcode), tag=tag)
            if self._status_to_int(self.xstatus(tag=tag)) not in (0, opcode):
                raise RuntimeError("Read OTP opcode ack failed")
            self.xsend(params[:8], tag=tag)
            if self._status_to_int(self.xstatus(tag=tag)) != 0:
                raise RuntimeError("Read OTP param ack failed")
            chunks = []
            remaining = data_len
            while remaining > 0:
                chunk = self.read(min(read_len, remaining), tag=tag)
                if not chunk:
                    raise RuntimeError("Read OTP data timeout")
                chunks.append(chunk)
                remaining -= len(chunk)
                # Per-chunk ACK expected by DA2
                self.write(struct.pack("<I", 0), verbose=False, tag=tag)
            st = self._status_to_int(self.xstatus(tag=tag, timeout=5.0))
            data = b"".join(chunks)
            if out_file:
                open(out_file, "wb").write(data)
            return st, [data]

        if opcode == 0x010002:  # Upload (device -> host stream)
            hex_tokens, _, out_file = _split_stream_tokens(raw_tokens)
            params = _parse_param_tokens(hex_tokens)
            if len(params) < 80:
                raise RuntimeError("Upload requires 64B header + 16B params (80 bytes hex)")
            header, param_block = params[:64], params[64:80]
            if len(param_block) != 16:
                raise RuntimeError("Upload param block must be 16 bytes")
            data_len = struct.unpack("<Q", param_block[8:16])[0]
            tag = "CMD_UPLOAD"
            self.xsend(struct.pack("<I", opcode), tag=tag)
            if self._status_to_int(self.xstatus(tag=tag)) not in (0, opcode):
                raise RuntimeError("Upload opcode ack failed")
            self.xsend(header, tag=tag)
            if self._status_to_int(self.xstatus(tag=tag)) != 0:
                raise RuntimeError("Upload header ack failed")
            self.xsend(param_block, tag=tag)
            if self._status_to_int(self.xstatus(tag=tag)) != 0:
                raise RuntimeError("Upload params ack failed")
            data = recv_stream(data_len, tag)
            st = self._status_to_int(self.xstatus(tag=tag, timeout=5.0))
            if out_file:
                open(out_file, "wb").write(data)
            return st, [data]

        if opcode == 0x010004:  # Write data block
            hex_tokens, data_files, _ = _split_stream_tokens(raw_tokens)
            if not data_files:
                raise RuntimeError("Write data requires a data file (@path)")
            params = _parse_param_tokens(hex_tokens)
            if len(params) != 56:
                raise RuntimeError("Write data params must be 56 bytes")
            data = open(data_files[0], "rb").read()
            data_len = len(data)
            params = bytearray(params)
            params[16:24] = struct.pack("<Q", data_len)
            params = bytes(params)
            tag = "CMD_WRITE_DATA"
            self.xsend(struct.pack("<I", opcode), tag=tag)
            if self._status_to_int(self.xstatus(tag=tag)) not in (0, opcode):
                raise RuntimeError("Write data opcode ack failed")
            self.xsend(params, tag=tag)
            if self._status_to_int(self.xstatus(tag=tag)) != 0:
                raise RuntimeError("Write data params ack failed")
            send_stream(data, tag)
            st = self._status_to_int(self.xstatus(tag=tag, timeout=5.0))
            return st, []

        if opcode == 0x010005:  # Read data block
            hex_tokens, _, out_file = _split_stream_tokens(raw_tokens)
            params = _parse_param_tokens(hex_tokens)
            if len(params) != 56:
                raise RuntimeError("Read data params must be 56 bytes")
            data_len = struct.unpack("<Q", params[16:24])[0]
            tag = "CMD_READ_DATA"
            self.xsend(struct.pack("<I", opcode), tag=tag)
            if self._status_to_int(self.xstatus(tag=tag)) not in (0, opcode):
                raise RuntimeError("Read data opcode ack failed")
            self.xsend(params, tag=tag)
            if self._status_to_int(self.xstatus(tag=tag)) != 0:
                raise RuntimeError("Read data params ack failed")
            data = recv_stream(data_len, tag)
            st = self._status_to_int(self.xstatus(tag=tag, timeout=5.0))
            if out_file:
                open(out_file, "wb").write(data)
            return st, [data]

        if opcode == 0x01000E:  # Write eFuse
            hex_tokens, data_files, _ = _split_stream_tokens(raw_tokens)
            if not data_files:
                raise RuntimeError("Write eFuse requires a data file (@path)")
            efuse_blob = open(data_files[0], "rb").read()
            extra_tail = b""
            if len(data_files) > 1:
                extra_tail = open(data_files[1], "rb").read()
            # Allow single file containing both segments
            if len(efuse_blob) >= 17108 + 248 and not extra_tail:
                extra_tail = efuse_blob[17108:17108 + 248]
                efuse_blob = efuse_blob[:17108]
            if len(efuse_blob) != 17108:
                raise RuntimeError("Write eFuse main payload must be exactly 17108 bytes")
            if len(extra_tail) != 248:
                raise RuntimeError("Write eFuse secondary payload must be exactly 248 bytes")
            tag = "CMD_WRITE_EFUSE"
            self.xsend(struct.pack("<I", opcode), tag=tag)
            if self._status_to_int(self.xstatus(tag=tag)) not in (0, opcode):
                raise RuntimeError("Write eFuse opcode ack failed")
            # Two consecutive raw blocks expected by DA2: 17108B then 248B
            self.xsend(efuse_blob, tag=tag)
            self.xsend(extra_tail, tag=tag)
            st = self._status_to_int(self.xstatus(tag=tag, timeout=5.0))
            if st != 0:
                return st, []
            st = self._status_to_int(self.xstatus(tag=tag, timeout=5.0))
            return st, []

        if opcode == 0x01000F:  # Read eFuse
            hex_tokens, _, out_file = _split_stream_tokens(raw_tokens)
            params = _parse_param_tokens(hex_tokens)
            if len(params) != 248:
                raise RuntimeError("Read eFuse requires 248-byte params blob")
            tag = "CMD_READ_EFUSE"
            self.xsend(struct.pack("<I", opcode), tag=tag)
            if self._status_to_int(self.xstatus(tag=tag)) not in (0, opcode):
                raise RuntimeError("Read eFuse opcode ack failed")
            self.xsend(params, tag=tag)
            if self._status_to_int(self.xstatus(tag=tag)) != 0:
                raise RuntimeError("Read eFuse params ack failed")
            data = recv_stream(17108, tag)
            # DA expects a 4-byte ack from host after data phase
            self.write(struct.pack("<I", 0), verbose=False, tag=tag)
            st = self._status_to_int(self.xstatus(tag=tag, timeout=5.0))
            if out_file:
                open(out_file, "wb").write(data)
            return st, [data]

        raise RuntimeError(f"Streaming for opcode 0x{opcode:06X} not implemented; use dedicated flow.")

    def run_dacmd(self, opcode, params=None, tag_hint: Optional[str] = None, raw_tokens=None):
        """
        DA command runner with protocol hints:
        - Adds DEVICE_CTRL wrapper for 0x02/0x04/0x08/0x0E subcommands.
        - Validates expected acks and parameter length.
        - Refuses streaming commands that require chunked data/echo to avoid misalignment.
        """
        spec = self.dacmd_spec.get(opcode, {})
        tag = tag_hint or f"CMD_{opcode:06X}"
        is_sub = spec.get("device_ctrl") or (0x020000 <= opcode <= 0x08FFFF) or (opcode == 0x0E0003)
        needs_stream = spec.get("needs_stream", False)

        if needs_stream:
            if raw_tokens is None:
                raise RuntimeError("Streaming command requires raw tokens for data/file parsing.")
            return self._run_streaming_dacmd(opcode, raw_tokens)

        # DEVICE_CTRL wrapper
        if is_sub:
            self.xsend(struct.pack("<I", 0x010009), tag=tag)
            if self._status_to_int(self.xstatus(tag=tag)) != 0:
                return -1, []

        # Opcode phase
        self.xsend(struct.pack("<I", opcode), tag=tag)
        op_ack = self._status_to_int(self.xstatus(tag=tag))
        expected_ack = {0, opcode} if not is_sub else {0}
        if op_ack not in expected_ack:
            return op_ack, []

        # Parameter phase (if any)
        if params:
            expect_len = spec.get("param_len")
            if expect_len is not None and len(params) != expect_len:
                raise RuntimeError(f"Param length mismatch: expected {expect_len} got {len(params)} for 0x{opcode:06X}")
            self.xsend(params, tag=tag)
            # Most commands ack params with 0
            param_ack = self._status_to_int(self.xstatus(tag=tag))
            if param_ack not in (0, opcode):
                return param_ack, []

        # For shutdown-like commands the device may reboot; do not wait further.
        if spec.get("no_final_status"):
            return 0, []

        # Collect final status / payload (for info-returning commands)
        results = []
        start = time.time()
        final_st = 0
        # Allow short window to pull any payload then status (matches DA behavior)
        while time.time() - start < 2.0:
            try:
                self.ser.timeout = 0.2
                v = self.xstatus(tag=tag)
                if isinstance(v, bytes):
                    results.append(v)
                else:
                    final_st = v
                    break
            except Exception:
                break
        return final_st, results


def send_da_brom(dev: MtkDevice, addr: int, data: bytes):
    """BROM DA upload over 0xD7 frame: echo header/length/chunk size then raw payload."""
    tag = "SEND_DA"
    dev.echo(0xD7, tag)
    dev.echo_block(struct.pack(">I", addr), name=tag)
    dev.echo_block(struct.pack(">I", len(data)), name=tag)
    dev.echo_block(struct.pack(">I", 0x100), name=tag)
    dev.read(2, tag=tag)  # RX 00 00
    logger.info(f"Sending DA1 raw payload ({len(data)} bytes) ...")
    # Use dev.write for visibility in debug mode; keep chunk size aligned with DA expectations
    chunk_sz = 8192
    for i in range(0, len(data), chunk_sz):
        chunk = data[i:i + chunk_sz]
        dev.write(chunk, tag=tag)
    old_to = dev.ser.timeout
    dev.ser.timeout = max(old_to or 0, 5.0)
    resp = dev.read(4, tag=tag)
    dev.ser.timeout = old_to
    return resp


def patch_da2_mtkclient(path: str):
    """
    Patch DA2 using mtkclient Carbonara-style security bypass:
      - Zero binding window (legacy)
      - Disable hash binding and boot_to hash check (C0070004)
      - Disable security/anti-rollback/SBC/register RW blocks
      - Relax write-not-allowed checks
    """
    with open(path, "rb") as f:
        da2 = bytearray(f.read())

    def replace_all(buf: bytearray, pat: bytes, repl: bytes, max_replace=None):
        idx = buf.find(pat)
        count = 0
        while idx != -1:
            buf[idx:idx + len(pat)] = repl
            count += 1
            if max_replace and count >= max_replace:
                break
            idx = buf.find(pat, idx + 1)
        return count

    # Legacy binding window zeroing
    if len(da2) >= 0x111F0:
        da2[0x111EC:0x111F0] = b"\x00\x00\x00\x00"

    # Disable hash binding (0xC0020004/5)
    replace_all(da2, b"\x01\x23\x03\x60\x00\x20\x70\x47\x70\xB5", b"\x00" + b"\x23\x03\x60\x00\x20\x70\x47\x70\xB5")

    # Disable boot_to hash check (C0070004)
    replace_all(da2, int.to_bytes(0xC0070004, 4, "little"), b"\x00\x00\x00\x00")
    replace_all(da2, b"\x4F\xF0\x04\x09\xCC\xF2\x07\x09", b"\x4F\xF0\x00\x09\x4F\xF0\x00\x09")
    replace_all(da2, b"\x4F\xF0\x04\x09\x32\x46\x01\x98\x03\x99\xCC\xF2\x07\x09", b"\x4F\xF0\x00\x09\x32\x46\x01\x98\x03\x99\x4F\xF0\x00\x09")

    # Security check disable
    replace_all(da2, b"\x01\x23\x03\x60\x00\x20\x70\x47\x70\xB5", b"\x00\x23\x03\x60\x00\x20\x70\x47\x70\xB5", max_replace=1)
    # Anti-rollback
    replace_all(da2, int.to_bytes(0xC0020053, 4, "little"), b"\x00\x00\x00\x00")
    # SBC disable
    # pattern: 02 4B 18 68 C0 F3 40 00 70 47 -> make MOV R0,#0 (4F F0 00 00)
    sbc = da2.find(b"\x02\x4B\x18\x68\xC0\xF3\x40\x00\x70\x47")
    if sbc != -1:
        da2[sbc + 4:sbc + 8] = b"\x4F\xF0\x00\x00"
    # Register read/write not allowed -> allow
    replace_all(da2, int.to_bytes(0xC004000D, 4, "little"), b"\x00\x00\x00\x00")

    # Write not allowed patches
    replace_all(da2, b"\x37\xB5\x00\x23\x04\x46\x02\xA8", b"\x37\xB5\x00\x20\x03\xB0\x30\xBD")
    replace_all(da2, b"\x0C\x23\xCC\xF2\x02\x03", b"\x00\x23\x00\x23\x00\x23")
    replace_all(da2, b"\x2A\x23\xCC\xF2\x02\x03", b"\x00\x23\x00\x23\x00\x23")

    return bytes(da2), hashlib.sha256(da2).digest()


def patch_da2_mt6833_honor(path: str):
    """Patch DA2 for MT6833 HONOR (legacy zero binding window only)."""
    with open(path, "rb") as f:
        da2 = bytearray(f.read())
    target_off = 0x111EC
    # Zero out literal 0xC004000D so the callee returns success instead of REG_ACCESS_NOT_ALLOWED.
    if len(da2) >= target_off + 4:
        da2[target_off:target_off + 4] = b"\x00\x00\x00\x00"
    return bytes(da2), hashlib.sha256(da2).digest()


def patch_da2_none(path: str):
    """No patch; return raw DA2 and SHA256."""
    with open(path, "rb") as f:
        da2 = f.read()
    return da2, hashlib.sha256(da2).digest()


def find_hash_slot(da1: bytes) -> int:
    """
    Locate the DA2 hash slot in DA1.
    Priority:
      1) V5 style: find 'MMU MAP: VA' and use offset -0x30.
      2) If missing, fall back to any 32-byte region ending with four zero bytes.
    """
    mmu_idx = da1.find(b"MMU MAP: VA")
    if mmu_idx != -1 and mmu_idx >= 0x30:
        return mmu_idx - 0x30
    candidate = da1.find(b"\x00\x00\x00\x00")
    while candidate != -1 and candidate + 32 <= len(da1):
        window = da1[candidate:candidate + 32]
        if window.endswith(b"\x00\x00\x00\x00"):
            return candidate
        candidate = da1.find(b"\x00\x00\x00\x00", candidate + 4)
    raise RuntimeError("Failed to locate DA2 hash slot in DA1")


def load_da_flow(dev: MtkDevice, da1_path: str, da2_path: str, patch_mode: str = "mtkclient"):
    logger.info("Step 0: Target detection...")
    dev.echo(0xFD, name="HWCODE")
    logger.info(f"HWCODE: {dev.read(4, tag='HWCODE').hex().upper()}")

    logger.info("Step 1: Disable WDT...")
    dev.echo(0xD4, name="WDT")
    dev.echo_block(struct.pack(">I", 0x10007000), name="WDT")
    dev.echo_block(struct.pack(">I", 0x00000001), name="WDT")
    dev.read(2, tag="WDT")
    dev.echo_block(struct.pack(">I", 0x22000000), name="WDT")
    dev.read(2, tag="WDT")

    logger.info("Step 2: Security handshake...")
    # Security probe: query config flags then HW/SW version tuple
    dev.echo(0xD8, name="SEC")
    dev.read(6, tag="SEC")
    dev.write(0xFE, tag="SEC")
    dev.read(1, tag="SEC")
    dev.write(0xFF, tag="SEC")
    dev.read(1, tag="SEC")
    dev.echo(0xFC, name="SEC")  # GET_HW_SW_VER
    vals = dev.read(8, tag="SEC")
    hw_sub, hw_ver, sw_ver = struct.unpack(">HHI", vals)
    logger.info(f"HW_SUBCODE: 0x{hw_sub:04X}, HW_VER: 0x{hw_ver:04X}, SW_VER: 0x{sw_ver:08X}")
    # Optional ID reads (informational)
    dev.echo(0xE1, name="SEC_MEID")
    l = struct.unpack(">I", dev.read(4, tag="SEC_MEID"))[0]
    meid = dev.read(l, tag="SEC_MEID")
    dev.read(2, tag="SEC_MEID")
    logger.info(f"MEID: {meid.hex().upper()}")
    dev.echo(0xE7, name="SEC_SOCID")
    l = struct.unpack(">I", dev.read(4, tag="SEC_SOCID"))[0]
    socid = dev.read(l, tag="SEC_SOCID")
    dev.read(2, tag="SEC_SOCID")
    logger.info(f"SOCID: {socid.hex().upper()}")

    with open(da1_path, "rb") as f:
        da1 = f.read()

    logger.info("Step 3: Uploading DA1...")
    send_da_brom(dev, 0x00200000, da1)

    logger.info("Step 4: Jump to DA1...")
    dev.echo(0xD5, "JUMP")
    dev.echo_block(struct.pack(">I", 0x00200000), name="JUMP")
    dev.read(2, tag="JUMP")
    time.sleep(0.5)
    if dev.read(1, tag="JUMP") != b"\xC0":
        raise RuntimeError("DA1 sync fail")

    logger.info("DA1 Online. Initializing XFlash...")
    dev.da1_init_pipeline()

    # Optional DACMD setup skipped for minimal flow to mirror minimal successful sequence

    logger.info(f"Step 5: Patch DA2 (mode={patch_mode})...")
    if patch_mode == "mtkclient":
        da2_patched, dahash = patch_da2_mtkclient(da2_path)
    elif patch_mode == "mt6833_honor":
        da2_patched, dahash = patch_da2_mt6833_honor(da2_path)
    else:
        da2_patched, dahash = patch_da2_none(da2_path)
    hash_offset = find_hash_slot(da1)
    hash_addr = 0x00200000 + hash_offset
    logger.info(f"Hash slot offset: 0x{hash_offset:06X} (addr 0x{hash_addr:08X})")
    logger.info(f"Patched DA2 SHA256: {dahash.hex()}")

    logger.info("Writing patched hash into DA1 (expect 0xC0070004 tolerated)...")
    dev.boot_to(hash_addr, dahash, tolerate={0xC0070004})

    logger.info("Uploading Stage 2 DA...")
    dev.boot_to(0x40000000, da2_patched, tolerate={})
    logger.info("SUCCESS: Stage 2 DA Loaded.")


def _validate_dacmd_params(opcode: int, params: Optional[bytes], raw_tokens, spec=None):
    """
    Preflight parameter validation to fail fast before serial handshake.
    Avoids wasting time entering DA mode when obvious arg/file issues exist.
    """
    spec = spec or MtkDevice().dacmd_spec  # access hints without serial init
    spec_entry = spec.get(opcode, {})
    expect_len = spec_entry.get("param_len")
    if expect_len is not None and params is not None:
        if len(params) != expect_len:
            raise ValueError(f"Param length mismatch: expected {expect_len} got {len(params)} for 0x{opcode:06X}")

    if not spec_entry.get("needs_stream"):
        return

    # Streaming-specific validations
    if opcode == 0x010001:  # Download
        hex_tokens, data_files, _ = _split_stream_tokens(raw_tokens)
        if not data_files:
            raise ValueError("Download requires a data file (@path)")
        header = _parse_param_tokens(hex_tokens)
        if len(header) != 64:
            raise ValueError("Download header must be exactly 64 bytes")
        open(data_files[0], "rb").close()
        return

    if opcode == 0x010008:  # BootTo
        hex_tokens, data_files, _ = _split_stream_tokens(raw_tokens)
        if not data_files:
            raise ValueError("BootTo requires a payload file (@path)")
        params_buf = _parse_param_tokens(hex_tokens)
        if len(params_buf) != 8:
            raise ValueError("BootTo requires 8-byte address params")
        open(data_files[0], "rb").close()
        return

    if opcode == 0x01000D:  # Write OTP
        hex_tokens, data_files, _ = _split_stream_tokens(raw_tokens)
        if not data_files:
            raise ValueError("Write OTP requires a data file (@path)")
        params_buf = _parse_param_tokens(hex_tokens)
        if len(params_buf) < 4:
            raise ValueError("Write OTP requires offset (4B)")
        open(data_files[0], "rb").close()
        return

    if opcode == 0x01000C:  # Read OTP
        hex_tokens, _, _ = _split_stream_tokens(raw_tokens)
        params_buf = _parse_param_tokens(hex_tokens)
        if len(params_buf) < 8:
            raise ValueError("Read OTP requires offset(4B) + len(4B)")
        return

    if opcode == 0x010002:  # Upload
        hex_tokens, _, _ = _split_stream_tokens(raw_tokens)
        params_buf = _parse_param_tokens(hex_tokens)
        if len(params_buf) < 80:
            raise ValueError("Upload requires 64B header + 16B params (80 bytes hex)")
        return

    if opcode == 0x010004:  # Write data
        hex_tokens, data_files, _ = _split_stream_tokens(raw_tokens)
        if not data_files:
            raise ValueError("Write data requires a data file (@path)")
        params_buf = _parse_param_tokens(hex_tokens)
        if len(params_buf) != 56:
            raise ValueError("Write data params must be 56 bytes")
        open(data_files[0], "rb").close()
        return

    if opcode == 0x010005:  # Read data
        hex_tokens, _, _ = _split_stream_tokens(raw_tokens)
        params_buf = _parse_param_tokens(hex_tokens)
        if len(params_buf) != 56:
            raise ValueError("Read data params must be 56 bytes")
        return

    if opcode == 0x01000E:  # Write eFuse
        _, data_files, _ = _split_stream_tokens(raw_tokens)
        if not data_files:
            raise ValueError("Write eFuse requires a data file (@path)")
        efuse_blob = open(data_files[0], "rb").read()
        extra_tail = b""
        if len(data_files) > 1:
            extra_tail = open(data_files[1], "rb").read()
        if len(efuse_blob) >= 17108 + 248 and not extra_tail:
            extra_tail = efuse_blob[17108:17108 + 248]
            efuse_blob = efuse_blob[:17108]
        if len(efuse_blob) != 17108:
            raise ValueError("Write eFuse main payload must be exactly 17108 bytes")
        if len(extra_tail) != 248:
            raise ValueError("Write eFuse secondary payload must be exactly 248 bytes")
        return

    if opcode == 0x01000F:  # Read eFuse
        hex_tokens, _, _ = _split_stream_tokens(raw_tokens)
        params_buf = _parse_param_tokens(hex_tokens)
        if len(params_buf) != 248:
            raise ValueError("Read eFuse requires 248-byte params blob")
        return

    # Fallback: no extra checks
    return


def main():
    parser = argparse.ArgumentParser(description="mtktool - XFlash helper", formatter_class=argparse.RawTextHelpFormatter)
    sub = parser.add_subparsers(dest="command")

    p_load = sub.add_parser(
        "load_da",
        help="Load Stage 1 & 2 DA",
        usage="mtktool.py load_da -1 DA1.bin -2 DA2.bin [--patch MODE] [-d]"
    )
    p_load.add_argument("-1", "--da1", required=True, help="Path to DA1 binary")
    p_load.add_argument("-2", "--da2", required=True, help="Path to DA2 binary")
    p_load.add_argument("--patch", choices=["mtkclient", "mt6833_honor", "none"], default="mtkclient",
                        help="DA2 patch mode (default: mtkclient)")
    p_load.add_argument("-d", "--debug", action="store_true", help="Enable verbose logging (TX/RX)")

    cmd_txt = "\n".join(f"  {k:20}: {CMD_PRESETS[k]['desc']}" for k in sorted(CMD_PRESETS.keys()))
    p_cmd = sub.add_parser(
        "cmd",
        description=f"Available Commands:\n{cmd_txt}",
        formatter_class=argparse.RawTextHelpFormatter,
        help="Preloader cmds",
        usage="mtktool.py cmd [-h] [-d] name [params ...]"
    )
    p_cmd.add_argument("name", help=argparse.SUPPRESS)
    p_cmd.add_argument(
        "params",
        nargs="*",
        help="hex bytes (e.g. 01 FF), raw hex string (001122), or @file for binary blob."
    )
    p_cmd.add_argument("-d", "--debug", action="store_true", help="Enable verbose logging (TX/RX)")

    dac_txt = "\n".join(
        f"  {k:20}: {DACMD_PRESETS[k]['desc']}"
        for k in sorted(DACMD_PRESETS.keys())
        if not DACMD_PRESETS[k].get("hidden")
    )
    p_dac = sub.add_parser(
        "dacmd",
        description=(
            f"Available DA Commands:\n{dac_txt}\n"
            "Params: [hex bytes] or [raw hex string] or [@file], and @out:fn/>fn for read output.\n"
            "Streaming commands:\n"
            "  download   [64B-hex-header] @data.bin                : Download data stream\n"
            "  boot_to    [addr(8B-hex)] @payload.bin               : Boot to address with payload\n"
            "  write_otp  [offset(4B-hex)] @data.bin                : Write OTP (auto len)\n"
            "  read_otp   [offset(4B-hex)] [len(4B-hex)] @out:file  : Read OTP\n"
            "  upload     [64B-hex-header + 16B params] @out:file   : Upload data stream\n"
            "  write_data [56B-hex-params len@0x10] @data.bin       : Write data block\n"
            "  read_data  [56B-hex-params len@0x10] @out:file       : Read data block\n"
            "  read_efuse [248B-hex-params] @out:file               : Read eFuse (returns 17108B)\n"
            "  write_efuse @efuse.bin[@tail.bin]                    : Write eFuse (17108B + 248B)"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
        help="DA stage cmds",
        usage="mtktool.py dacmd [-h] [-d] name [params ...]"
    )
    p_dac.add_argument("name", help=argparse.SUPPRESS)
    p_dac.add_argument("params", nargs="*", help=argparse.SUPPRESS)
    p_dac.add_argument("-p", "--port", help="Serial port to use (auto-pick by VID if omitted with --no-handshake)")
    p_dac.add_argument("-b", "--baud", type=int, default=115200, help="Serial baudrate (default 115200)")
    p_dac.add_argument("-n", "--no-handshake", action="store_true", help="Send directly without handshake (opens port immediately)")
    p_dac.add_argument("--progress", action="store_true", help="Log chunk progress for streaming commands")
    p_dac.add_argument("--write-len", type=int, help="Override stream write packet size")
    p_dac.add_argument("--read-len", type=int, help="Override stream read packet size")
    p_dac.add_argument("-d", "--debug", action="store_true", help="Enable verbose TX/RX logging")

    # Raw TX/RX helpers (no handshake)
    p_raw_tx = sub.add_parser(
        "raw_tx",
        help="Send raw bytes over serial (with optional -x XFlash header).",
        usage="mtktool.py raw_tx -p COM6 [-b 115200] [-x] data..."
    )
    p_raw_tx.add_argument("-p", "--port", required=True, help="Serial port")
    p_raw_tx.add_argument("-b", "--baud", type=int, default=115200, help="Serial baudrate (default 115200)")
    p_raw_tx.add_argument("-x", "--xflash", action="store_true", help="Wrap payload with XFlash header (MAGIC/PROTO/len)")
    p_raw_tx.add_argument("data", nargs="+", help="hex tokens/raw hex/@file")
    p_raw_tx.add_argument("-d", "--debug", action="store_true", help="Enable verbose TX/RX logging")

    p_raw_rx = sub.add_parser(
        "raw_rx",
        help="Receive raw bytes from serial (with optional -x strips XFlash header).",
        usage="mtktool.py raw_rx -p COM6 -l N [-b 115200] [-t 2] [-x]"
    )
    p_raw_rx.add_argument("-p", "--port", required=True, help="Serial port")
    p_raw_rx.add_argument("-b", "--baud", type=int, default=115200, help="Serial baudrate (default 115200)")
    p_raw_rx.add_argument("-l", "--len", type=int, required=True, help="Number of bytes to read (payload or raw)")
    p_raw_rx.add_argument("-t", "--timeout", type=float, default=2.0, help="Read timeout (seconds)")
    p_raw_rx.add_argument("-x", "--xflash", action="store_true", help="Expect XFlash header and strip it")
    p_raw_rx.add_argument("-d", "--debug", action="store_true", help="Enable verbose RX logging")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return

    # Elevate log level when debug flag is provided so XFLASH debug lines are visible
    if getattr(args, "debug", False):
        logger.setLevel(logging.DEBUG)

    dev = MtkDevice(debug=getattr(args, "debug", False))
    dev.progress = getattr(args, "progress", False)
    dev.write_len_override = getattr(args, "write_len", None)
    dev.read_len_override = getattr(args, "read_len", None)
    try:
        if args.command == "load_da":
            if not dev.find_and_connect(da_mode=False):
                return
            load_da_flow(dev, args.da1, args.da2, patch_mode=args.patch)
        elif args.command == "cmd":
            meta = CMD_PRESETS[args.name]
            if not dev.find_and_connect(da_mode=False):
                return
            params = _parse_param_tokens(args.params) if args.params else b""
            # Preloader handlers here do not take dynamic params; warn if any were passed
            if params:
                logger.warning("Preloader cmd currently ignores params; provided params were parsed but not used.")
            meta["handler"](dev)
        elif args.command == "dacmd":
            meta = DACMD_PRESETS[args.name]
            opcode = meta["opcode"]
            tag_hint = meta.get("tag")
            params = _parse_param_tokens(args.params) if args.params else None
            # Preflight validation to fail fast before handshake
            _validate_dacmd_params(opcode, params, args.params, spec=dev.dacmd_spec)
            def _run_and_log():
                st, payloads = dev.run_dacmd(opcode, params, tag_hint=tag_hint, raw_tokens=args.params)
                for p in payloads:
                    if isinstance(p, bytes):
                        try:
                            t = p.decode("utf-8").strip()
                            logger.info(f"Data: {t}" if (t.isprintable() and len(t) > 0) else f"Data (HEX): {p.hex(' ')}")
                        except Exception:
                            logger.info(f"Data (HEX): {p.hex(' ')}")
                    else:
                        logger.info(f"Data: 0x{p:08X}")
                if st != 0:
                    logger.warning(f"Final Status: 0x{st:08X}")

            if args.no_handshake:
                port = args.port or _auto_pick_port(dev.vid)
                if not port:
                    raise ValueError("No port specified and auto-scan failed (no matching VID)")
                with SerialSession(port, args.baud) as ser:
                    dev.ser = ser
                    try:
                        _run_and_log()
                    except Exception:
                        logger.error(f"run_dacmd failed (opcode=0x{opcode:06X}, tag={tag_hint})")
                        raise
            else:
                if not dev.find_and_connect(da_mode=True):
                    return
                try:
                    _run_and_log()
                except Exception:
                    logger.error(f"run_dacmd failed (opcode=0x{opcode:06X}, tag={tag_hint})")
                    raise
        elif args.command == "raw_tx":
            dev.debug = getattr(args, "debug", False)
            payload = _parse_param_tokens(args.data)
            with SerialSession(args.port, args.baud) as ser:
                dev.ser = ser
                if args.xflash:
                    logger.info(f"RAW_TX XFlash len={len(payload)}")
                    dev.xsend(payload, tag="RAW_TX")
                else:
                    logger.info(f"RAW_TX len={len(payload)}")
                    dev.write(payload, tag="RAW_TX")
        elif args.command == "raw_rx":
            dev.debug = getattr(args, "debug", False)
            with SerialSession(args.port, args.baud, timeout=args.timeout) as ser:
                dev.ser = ser
                total_read = args.len + (12 if args.xflash else 0)
                data = dev.read(total_read, tag="RAW_RX", timeout=args.timeout)
                if not data:
                    logger.warning("RAW_RX: no data received")
                else:
                    if args.xflash:
                        if len(data) < 12:
                            logger.warning("RAW_RX: incomplete XFlash header")
                            return
                        hdr, body = data[:12], data[12:]
                        logger.info(f"RAW_RX_HDR: {hdr.hex(' ')}")
                        logger.info(f"RAW_RX ({len(body)}B of {args.len} expected): {body.hex(' ')}")
                    else:
                        logger.info(f"RAW_RX ({len(data)}B): {data.hex(' ')}")
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)
    finally:
        if dev.ser:
            dev.ser.close()


if __name__ == "__main__":
    main()
