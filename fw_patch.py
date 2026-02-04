"""
patches firmware.bin bypass version and md5 checks

header format: [magic:4][hardware_id:33][oem_id:33][product_id:4][product_version:4][additional_hardware_version:4][md5:16][software_version:4][special_version:4] (tested on EX230v)
"""

import glob
import hashlib
import struct
import sys

from dotenv import dotenv_values

SOFTWARE_VERSION_MAJOR = 15
SPECIAL_VERSION_MAJOR = 2
MD5_CONSTANTS = [
    int(dotenv_values(glob.glob(".env*")[0]).get("fw_md5_constants_0"), 16),
    int(dotenv_values(glob.glob(".env*")[0]).get("fw_md5_constants_1"), 16),
    int(dotenv_values(glob.glob(".env*")[0]).get("fw_md5_constants_2"), 16),
    int(dotenv_values(glob.glob(".env*")[0]).get("fw_md5_constants_3"), 16),
]
PRODUCT_VERSION = None  # set None to skip
SOFTWARE_VERSION = (SOFTWARE_VERSION_MAJOR << 24) | 0x00AA55
SPECIAL_VERSION = (SPECIAL_VERSION_MAJOR << 24) | 0x00000000
TAG_OFFSET = 0x0
FIELD_OFFSETS = {
    "product_version": TAG_OFFSET + 0x38,
    "md5": TAG_OFFSET + 0x40,
    "software_version": TAG_OFFSET + 0x8C,
    "special_version": TAG_OFFSET + 0x94,
}


def patch_fw(input_file):
    with open(input_file, "rb") as f:
        firmware = bytearray(f.read())

    for field_name, field_value in [
        ("software_version", SOFTWARE_VERSION),
        ("special_version", SPECIAL_VERSION),
        ("product_version", PRODUCT_VERSION),
    ]:
        if field_value is not None:
            offset = FIELD_OFFSETS[field_name]
            old_val = struct.unpack("<I", firmware[offset : offset + 4])[0]
            firmware[offset : offset + 4] = struct.pack("<I", field_value)
            print(f"{field_name}: 0x{old_val:08x} -> 0x{field_value:08x}")

    for i, const in enumerate(MD5_CONSTANTS):
        firmware[FIELD_OFFSETS["md5"] + i * 4 : FIELD_OFFSETS["md5"] + i * 4 + 4] = (
            struct.pack(">I", const)
        )
    old_md5 = firmware[FIELD_OFFSETS["md5"] : FIELD_OFFSETS["md5"] + 16]
    new_md5 = hashlib.md5(firmware).digest()
    firmware[FIELD_OFFSETS["md5"] : FIELD_OFFSETS["md5"] + 16] = new_md5
    print(f"md5: 0x{old_md5.hex()} -> 0x{new_md5.hex()}")

    output_file = f"{input_file.rsplit('.', 1)[0]}_patched.bin"
    with open(output_file, "wb") as f:
        f.write(firmware)
    print(f"- done: {output_file}")


def main():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <firmware.bin>")
        sys.exit(1)
    patch_fw(sys.argv[1])


if __name__ == "__main__":
    main()
