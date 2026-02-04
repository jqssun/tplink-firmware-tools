"""
unpacks misc partition into plain text xml configs

partition holds aes-128-cbc encrypted configs at offsets:
- 0x00000: main config
- 0x20000: base/isp config

header format: [size:4][magic:4][field3:4][type:4][encrypted data] (tested on EX230v)
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


def decrypt_config_at_offset(data, offset):
    assert offset + 0x10 <= len(data), f"offset 0x{offset:05x} exceeds file size"
    header = data[offset : offset + 0x10]
    assert len(header) == 0x10, "insufficient data for header"

    size, magic, _, enc_type = struct.unpack(">4I", header)
    assert magic == MAGIC, f"invalid magic (expected 0x{MAGIC:08x})"
    assert size < 0x20000, "size >= 0x20000, likely erased flash"
    print(f"size: {size:,} bytes (0x{size:x})")
    print(f"magic: 0x{magic:08x}")
    print(f"type: {enc_type} ({'encrypted' if enc_type in [2, 3] else 'plain'})")

    data_offset = offset + 0x10
    encrypted = data[data_offset:]
    aligned_size = (len(encrypted) // 16) * 16
    assert aligned_size > 0, "no encrypted data found"
    encrypted = encrypted[:aligned_size]
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    decrypted = cipher.decrypt(encrypted)

    if size > len(decrypted):
        print(f"warning: declared size {size} > decrypted size {len(decrypted)}")
        decrypted = decrypted[: len(decrypted)]
    else:
        decrypted = decrypted[:size]
    return decrypted


def decrypt_configs(input_file):
    with open(input_file, "rb") as f:
        data = f.read()
    output_prefix = input_file.rsplit(".", 1)[0]
    for config_name, offset in CONFIGS.items():
        print(f"- decrypting {config_name} config at offset 0x{offset:05x}")
        config = decrypt_config_at_offset(data, offset)
        if config:
            output = f"{output_prefix}_{config_name}.xml"
            with open(output, "wb") as f:
                f.write(config)
            print(f"- done: {output}")


def main():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <misc.bin|mtdblock3.bin>")
        sys.exit(1)
    decrypt_configs(sys.argv[1])


if __name__ == "__main__":
    main()
