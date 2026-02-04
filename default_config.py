import glob
import sys

from Cryptodome.Cipher import DES
from dotenv import dotenv_values

KEY = dotenv_values(glob.glob(".env*")[0]).get("default_config_key")


def des_decrypt(encrypted_data, key):  # enc:cen_desMinDo()
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted = cipher.decrypt(encrypted_data)
    while len(decrypted) > 0 and decrypted[-1] == 0:
        decrypted = decrypted[:-1]
    return decrypted


def main():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <encrypted.xml>")
        sys.exit(1)
    with open(sys.argv[1], "rb") as f:
        encrypted_data = f.read()

    if len(encrypted_data) % 8 != 0:
        print("input file size is not a multiple of 8 bytes; padding with zeroes.")
        padded = encrypted_data + b"\x00" * (8 - len(encrypted_data) % 8)
    else:
        padded = encrypted_data

    decrypted = des_decrypt(padded, bytes.fromhex(KEY))
    sys.stdout.buffer.write(decrypted)


if __name__ == "__main__":
    main()
