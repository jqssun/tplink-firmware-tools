"""
repacks misc partition from plain text configs and device data

- automatically creates minimal base config if missing after factory reset
- encrypts both plain text xml configs and writes required headers for each
- preserves everything after a certain offset (device-specific data)
"""

import glob
import struct
import sys

from Cryptodome.Cipher import AES
from dotenv import dotenv_values

KEY = dotenv_values(glob.glob(".env*")[0]).get("misc_key").encode()
IV = dotenv_values(glob.glob(".env*")[0]).get("misc_iv").encode()
MAGIC = int(dotenv_values(glob.glob(".env*")[0]).get("misc_magic"), 16)
CONFIGS = {
    "main": 0x00000,
    "base": 0x20000,
}

HEADER_SIZE = 0x10
MAX_CONFIG = CONFIGS["base"]  # firmware limit per config
DEVICE_DATA_START = 0x4F100  # top of device data (MAC address)
SAFE_WRITE_LIMIT = 0x30000  # leaves margin for undocumented data


def pad_to_16(data):
    padding_len = 16 - (len(data) % 16)
    if padding_len == 16:
        padding_len = 0
    return data + bytes([padding_len] * padding_len) if padding_len else data


def repack_config(reference_bin, xml_file):
    with open(reference_bin, "rb") as f:
        reference_data = f.read()

    assert len(reference_data) == 0x100000, "reference partition is not 1 MiB"
    with open(xml_file, "rb") as f:
        xml_data = f.read()

    xml_size = len(xml_data)
    encrypted_size = ((xml_size + 15) // 16) * 16
    total_size = encrypted_size + HEADER_SIZE

    # firmware checks: if ((size + 0x10) >= 0x20000)
    assert total_size < MAX_CONFIG, "xml config is too large"

    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    encrypted = cipher.encrypt(pad_to_16(xml_data))
    orig_header = reference_data[0x00:0x10]
    _, _, field3, orig_type = struct.unpack(">4I", orig_header)  # preserve field3
    enc_type = 2 if orig_type in [2, 3] else 2
    header = struct.pack(">4I", xml_size, MAGIC, field3, enc_type)
    print(f"size: {xml_size:,} bytes (0x{xml_size:x})")
    print(f"magic: 0x{MAGIC:08x}")

    output_data = bytearray(reference_data)
    output_data[0x00:0x10] = header
    output_data[0x10 : 0x10 + len(encrypted)] = encrypted
    config_end = 0x10 + len(encrypted)
    if config_end < SAFE_WRITE_LIMIT:
        fill_end = min(SAFE_WRITE_LIMIT, DEVICE_DATA_START)
        if config_end < fill_end:
            output_data[config_end:fill_end] = bytes([0xFF] * (fill_end - config_end))

    base_xml = (
        b'<?xml version="1.0"?>\n<DslCpeConfig></DslCpeConfig>\n'  # minimal base config
    )
    base_cipher = AES.new(KEY, AES.MODE_CBC, IV)
    base_encrypted = base_cipher.encrypt(pad_to_16(base_xml))
    base_header = struct.pack(">4I", len(base_xml), MAGIC, field3, enc_type)
    output_data[CONFIGS["base"] : CONFIGS["base"] + 0x10] = base_header
    output_data[
        CONFIGS["base"] + 0x10 : CONFIGS["base"] + 0x10 + len(base_encrypted)
    ] = base_encrypted
    base_config_end = CONFIGS["base"] + 0x10 + len(base_encrypted)
    safe_fill_end = min(base_config_end + 0x100, CONFIGS["base"] + 0x1000)
    if base_config_end < safe_fill_end:
        output_data[base_config_end:safe_fill_end] = bytes(
            [0xFF] * (safe_fill_end - base_config_end)
        )

    output_file = xml_file.rsplit(".", 1)[0] + "_repacked.bin"
    with open(output_file, "wb") as f:
        f.write(output_data)
    print(f"- done: {output_file}")


def main():
    if len(sys.argv) < 3:
        print(f"usage: {sys.argv[0]} <misc.bin|mtdblock3.bin> <*_main.xml>")
        sys.exit(1)
    repack_config(sys.argv[1], sys.argv[2])


if __name__ == "__main__":
    main()
