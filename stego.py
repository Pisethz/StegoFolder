#!/usr/bin/env python3
import os
import io
import sys
import json
import base64
import struct
import argparse
import zipfile
from typing import Tuple

from PIL import Image  # pip install pillow
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt  # pip install cryptography
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

MAGIC = b"STF1"  # StegoFolder v1

# ---------- Zip helpers ----------
def zip_folder_to_bytes(folder_path: str, archive_name: str = None) -> Tuple[bytes, str]:
    """
    Create a ZIP (deflated) of folder_path in-memory and return (zip_bytes, archive_name).
    Preserves relative paths under folder_path.
    """
    folder_path = os.path.abspath(folder_path)
    if not os.path.isdir(folder_path):
        raise ValueError(f"Not a folder: {folder_path}")

    if archive_name is None:
        archive_name = os.path.basename(folder_path.rstrip(os.sep)) or "archive"
    archive_name = archive_name + ".zip"

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(folder_path):
            for f in files:
                full = os.path.join(root, f)
                rel = os.path.relpath(full, start=folder_path)
                zf.write(full, arcname=rel)
    return buf.getvalue(), archive_name

def unzip_bytes_to_dir(zip_bytes: bytes, out_dir: str):
    os.makedirs(out_dir, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
        zf.extractall(out_dir)

# ---------- Crypto helpers ----------
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=32,     # AES-256
        n=2**14,
        r=8,
        p=1,
    )
    return kdf.derive(password.encode("utf-8"))

def encrypt_bytes(plaintext: bytes, password: str) -> Tuple[bytes, bytes, bytes]:
    """
    Returns (ciphertext, nonce, salt)
    AESGCM.encrypt returns ciphertext||tag (tag appended).
    """
    salt = os.urandom(16)
    key = derive_key(password, salt)
    nonce = os.urandom(12)
    aes = AESGCM(key)
    ciphertext = aes.encrypt(nonce, plaintext, None)
    return ciphertext, nonce, salt

def decrypt_bytes(ciphertext: bytes, password: str, nonce: bytes, salt: bytes) -> bytes:
    key = derive_key(password, salt)
    aes = AESGCM(key)
    return aes.decrypt(nonce, ciphertext, None)

# ---------- LSB helpers ----------
def bytes_to_bits(data: bytes):
    for byte in data:
        for i in range(8):
            yield (byte >> (7 - i)) & 1  # MSB-first

def bits_to_bytes(bits_iter, total_bytes: int) -> bytes:
    out = bytearray()
    cur = 0
    count = 0
    for b in bits_iter:
        cur = (cur << 1) | (b & 1)
        count += 1
        if count == 8:
            out.append(cur)
            cur = 0
            count = 0
            if len(out) == total_bytes:
                break
    if len(out) != total_bytes:
        raise ValueError("Not enough bits to reconstruct requested bytes.")
    return bytes(out)

def embed_lsb_rgb(cover_png_path: str, payload: bytes, out_png_path: str):
    img = Image.open(cover_png_path).convert("RGB")
    pixels = bytearray(img.tobytes())  # sequence of [R,G, B, R, G, B, ...]
    capacity_bits = len(pixels)  # 1 bit per channel byte
    needed_bits = len(payload) * 8

    if needed_bits > capacity_bits:
        raise ValueError(
            f"Cover too small. Need {needed_bits} bits, have {capacity_bits} bits. "
            f"Try a larger image or smaller payload."
        )

    bit_stream = bytes_to_bits(payload)
    for i, bit in enumerate(bit_stream):
        pixels[i] = (pixels[i] & 0b11111110) | bit

    stego = Image.frombytes("RGB", img.size, bytes(pixels))
    stego.save(out_png_path, format="PNG")

def extract_lsb_rgb(stego_png_path: str, num_bytes_to_read: int) -> bytes:
    img = Image.open(stego_png_path).convert("RGB")
    pixels = img.tobytes()
    # Read num_bytes_to_read * 8 bits from the first bytes of pixels
    def bit_gen():
        for byte in pixels:
            yield byte & 1
    return bits_to_bytes(bit_gen(), num_bytes_to_read)

# ---------- Container format ----------
# [ MAGIC(4) | HEADER_LEN(4 LE) | HEADER_JSON(header_len bytes) | DATA_LEN(8 LE) | CIPHERTEXT(data_len bytes) ]
def build_payload(ciphertext: bytes, nonce: bytes, salt: bytes, archive_name: str) -> bytes:
    header = {
        "ver": 1,
        "method": "lsb1",
        "archive": archive_name,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "salt": base64.b64encode(salt).decode("ascii"),
    }
    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    payload = bytearray()
    payload += MAGIC
    payload += struct.pack("<I", len(header_bytes))
    payload += header_bytes
    payload += struct.pack("<Q", len(ciphertext))
    payload += ciphertext
    return bytes(payload)

def parse_header_and_sizes(prefix_bytes: bytes):
    """
    Given bytes starting at the beginning of the payload, return:
    (header_len, header_dict)
    Requires at least 8 bytes to read header_len, then header_len bytes for header.
    """
    if prefix_bytes[:4] != MAGIC:
        raise ValueError("Magic not found: not an embedded StegoFolder payload.")
    header_len = struct.unpack("<I", prefix_bytes[4:8])[0]
    header_json = prefix_bytes[8:8 + header_len]
    header = json.loads(header_json.decode("utf-8"))
    return header_len, header

# ---------- High-level ops ----------
def embed(cover_png: str, folder: str, out_png: str, password: str):
    zip_bytes, archive_name = zip_folder_to_bytes(folder)
    ciphertext, nonce, salt = encrypt_bytes(zip_bytes, password)
    payload = build_payload(ciphertext, nonce, salt, archive_name)
    embed_lsb_rgb(cover_png, payload, out_png)
    print(f"[+] Embedded folder '{folder}' ({len(zip_bytes)} bytes zipped) into '{out_png}'.")

def extract(stego_png: str, out_dir: str, password: str):
    # Step 1: read enough to get header length (MAGIC + header_len = 8 bytes)
    prefix = extract_lsb_rgb(stego_png, 8)
    if prefix[:4] != MAGIC:
        raise ValueError("Magic not found: not an embedded StegoFolder payload.")
    header_len = struct.unpack("<I", prefix[4:8])[0]

    # Step 2: read full (MAGIC + header + DATA_LEN) to know ciphertext size
    total_prefix_len = 4 + 4 + header_len + 8
    full_prefix = extract_lsb_rgb(stego_png, total_prefix_len)

    # Parse header
    _, header = parse_header_and_sizes(full_prefix)
    nonce = base64.b64decode(header["nonce"])
    salt  = base64.b64decode(header["salt"])
    archive_name = header.get("archive", "archive.zip").replace(".zip", "")

    # Read data_len
    data_len_offset = 4 + 4 + header_len
    data_len = struct.unpack("<Q", full_prefix[data_len_offset:data_len_offset + 8])[0]

    # Step 3: read the ciphertext
    total_len = total_prefix_len + data_len
    payload = extract_lsb_rgb(stego_png, total_len)
    ciphertext = payload[-data_len:]

    # Decrypt and unzip
    try:
        plaintext = decrypt_bytes(ciphertext, password, nonce, salt)
    except InvalidTag:
        raise ValueError("Decryption failed. Wrong password or corrupted data.")

    # Always restore in a subfolder with original name
    restore_path = os.path.join(out_dir, archive_name)
    unzip_bytes_to_dir(plaintext, restore_path)
    print(f"[+] Extracted to '{restore_path}' ({header.get('archive','archive.zip')}).")

# ---------- CLI ----------
def main():
    parser = argparse.ArgumentParser(
        description="Hide/extract a whole folder in a PNG using LSB + AES-256-GCM."
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_embed = sub.add_parser("embed", help="Embed a folder into a PNG image.")
    p_embed.add_argument("-c", "--cover", required=True, help="Cover PNG path (lossless).")
    p_embed.add_argument("-i", "--input-folder", required=True, help="Folder to embed.")
    p_embed.add_argument("-o", "--out", required=True, help="Output stego PNG path.")
    p_embed.add_argument("-p", "--password", required=True, help="Passphrase for encryption.")

    p_extract = sub.add_parser("extract", help="Extract the hidden folder from a stego PNG.")
    p_extract.add_argument("-s", "--stego", required=True, help="Stego PNG path.")
    p_extract.add_argument("-o", "--out-dir", required=True, help="Where to extract files.")
    p_extract.add_argument("-p", "--password", required=True, help="Passphrase used for embedding.")

    args = parser.parse_args()
    if args.cmd == "embed":
        embed(args.cover, args.input_folder, args.out, args.password)
    elif args.cmd == "extract":
        extract(args.stego, args.out_dir, args.password)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)
