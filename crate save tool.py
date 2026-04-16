#!/usr/bin/env python3

import json
from pathlib import Path

DEFAULT_KEY = "K9#mXqL2$vRnT5@w"
PREFIX = "ENC1:"


def derive_key_bytes(seed: str) -> list[int]:
    n = max(len(seed), 4)
    arr = [0] * n
    for i, ch in enumerate(seed):
        arr[i % n] = (arr[i % n] + (ord(ch) * 31) + (i * 7)) & 0xFF
    return arr


def crypt_bytes(data: bytes, seed: str) -> bytes:
    arr = derive_key_bytes(seed)
    state = (arr[0] << 8) | arr[1] if len(arr) > 1 else (arr[0] << 8)

    out = bytearray(len(data))
    for i, b in enumerate(data):
        state = (state * 1664525 + 1013904223) & 0x7FFFFFFF
        ks = (state ^ arr[i % len(arr)]) & 0xFF
        out[i] = b ^ ks
    return bytes(out)


def checksum16(text: str) -> int:
    return sum(ord(ch) for ch in text) & 0xFFFF


def build_seed(base_key: str, username: str | None, transfer_mode: bool) -> str:
    if transfer_mode:
        if not username:
            raise ValueError("Transfer mode needs your exact VRChat display name.")
        return base_key + username
    return base_key


def load_text(text_or_path: str) -> str:
    p = Path(text_or_path.strip('"'))
    if p.exists() and p.is_file():
        return p.read_text(encoding="utf-8")
    return text_or_path


def decrypt_blob(blob: str, username: str | None = None, transfer_mode: bool = False) -> str:
    blob = blob.strip().replace("\n", "").replace("\r", "").replace(" ", "")
    if not blob.startswith(PREFIX):
        raise ValueError("Invalid format: save must start with ENC1:")

    hex_part = blob[len(PREFIX):]
    if len(hex_part) < 6:
        raise ValueError("Too short.")

    if len(hex_part) % 2 != 0:
        raise ValueError("Length mismatch.")

    checksum_hex = hex_part[-4:]
    encrypted_hex = hex_part[:-4]

    if len(encrypted_hex) % 2 != 0:
        raise ValueError("Length mismatch.")

    try:
        encrypted = bytes.fromhex(encrypted_hex)
    except ValueError:
        raise ValueError("Invalid data: not valid hex.")

    seed = build_seed(DEFAULT_KEY, username, transfer_mode)
    plaintext_bytes = crypt_bytes(encrypted, seed)

    try:
        plaintext = plaintext_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Decrypt failed — wrong username or bad data.")

    expected = checksum16(plaintext)
    actual = int(checksum_hex, 16)

    if expected != actual:
        if transfer_mode:
            raise ValueError("Transfer checksum mismatch — wrong username or corrupted blob.")
        raise ValueError("Checksum mismatch — save data may be corrupted or tampered with.")

    return plaintext


def encrypt_text(plaintext: str, username: str | None = None, transfer_mode: bool = False) -> str:
    seed = build_seed(DEFAULT_KEY, username, transfer_mode)
    encrypted = crypt_bytes(plaintext.encode("utf-8"), seed)
    chk = checksum16(plaintext)
    return PREFIX + encrypted.hex() + f"{chk:04x}"


def ask_yes_no(prompt: str) -> bool:
    while True:
        ans = input(prompt).strip().lower()
        if ans in ("y", "yes"):
            return True
        if ans in ("n", "no"):
            return False
        print("Please type y or n.")


def main():
    print("UVRSAVE Tool")
    print("1) Decrypt save")
    print("2) Encrypt save")
    choice = input("> ").strip()

    if choice not in ("1", "2"):
        print("Invalid choice.")
        return

    transfer_mode = ask_yes_no("Is this a transfer/export save tied to a username? (y/n): ")
    username = None
    if transfer_mode:
        username = input("Enter your exact VRChat display name: ").strip()

    if choice == "1":
        raw = input("Paste the ENC1 save here, or type a file path: ").strip()
        raw = load_text(raw)

        try:
            result = decrypt_blob(raw, username=username, transfer_mode=transfer_mode)
            print("\nDecrypted save:\n")
            try:
                parsed = json.loads(result)
                print(json.dumps(parsed, indent=2, ensure_ascii=False))
            except json.JSONDecodeError:
                print(result)
        except Exception as e:
            print(f"\nError: {e}")

    else:
        raw = input("Paste the JSON/save text here, or type a file path: ").strip()
        raw = load_text(raw)

        minify = ask_yes_no("Minify JSON before encrypting? (recommended) (y/n): ")
        if minify:
            try:
                parsed = json.loads(raw)
                raw = json.dumps(parsed, separators=(",", ":"), ensure_ascii=False)
            except json.JSONDecodeError:
                print(" not valid JSON...left it unchanged.")

        try:
            result = encrypt_text(raw, username=username, transfer_mode=transfer_mode)
            print("\nEncrypted save:\n")
            print(result)
        except Exception as e:
            print(f"\nError: {e}")


if __name__ == "__main__":
    main()