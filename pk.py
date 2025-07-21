#!/usr/bin/env python3
# pip install cryptography brotli base32-crockford prompt_toolkit

import os, sys, re, brotli, getpass
import base32_crockford as c32
from prompt_toolkit import PromptSession
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend


# ── BIP‑39 helpers ────────────────────────────────────────────────────────────
def load_bip39(p="english.txt"):
    with open(p, encoding="utf-8") as f:
        w = [x.strip() for x in f]
    if len(w) != 2048:
        raise ValueError("Invalid BIP39 word‑list")
    return {v: i for i, v in enumerate(w)}, w


def to_bits(v, n):
    return [(v >> i) & 1 for i in range(n)][::-1]


def from_bits(bits):
    x = 0
    for bit in bits:
        x = (x << 1) | bit
    return x


def pack_words(ws, b2i):
    bits = []
    for w in ws:
        if w in b2i:                       # BIP‑39 dictionary word
            bits.append(0)
            bits += to_bits(b2i[w], 11)
        else:                              # raw UTF‑8 fallback
            bits.append(1)
            b = w.encode()
            bits += to_bits(len(b), 16)
            for byte in b:
                bits += to_bits(byte, 8)

    while len(bits) % 8:
        bits.append(0)

    return bytes(from_bits(bits[i:i + 8]) for i in range(0, len(bits), 8))


def unpack_words(data, i2b):
    bits = [bit for byte in data for bit in to_bits(byte, 8)]
    ws, i = [], 0
    while i < len(bits):

        # --- stop if the rest is just zero padding -------------------------
        if all(b == 0 for b in bits[i:]):
            break
        # -------------------------------------------------------------------

        if bits[i] == 0:                   # dictionary word
            i += 1
            if i + 11 > len(bits): break
            idx = from_bits(bits[i:i + 11]); i += 11
            ws.append(i2b[idx])
        else:                              # raw UTF‑8 word
            i += 1
            if i + 16 > len(bits): break
            ln = from_bits(bits[i:i + 16]); i += 16
            if i + 8 * ln > len(bits): break
            bb = [from_bits(bits[i + 8 * k:i + 8 * (k + 1)]) for k in range(ln)]
            i += 8 * ln
            ws.append(bytes(bb).decode())
    return ws


# ── Crypto helpers ────────────────────────────────────────────────────────────
def kdf(pw: str, salt: bytes, length: int = 32) -> bytes:
    return Scrypt(salt=salt, length=length, n=2 ** 15, r=8, p=1,
                  backend=default_backend()).derive(pw.encode())


def aes_encrypt(raw: bytes, key: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    return nonce, AESGCM(key).encrypt(nonce, raw, None)


def aes_decrypt(nonce: bytes, ct: bytes, key: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, ct, None)


# ── Crockford armour (unchanged) ─────────────────────────────────────────────
ANSI_RE = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
ALLOWED = set("0123456789ABCDEFGHJKMNPQRSTVWXYZ")


def armour(data: bytes, groups_per_line: int = 3, group_len: int = 6) -> str:
    n = int.from_bytes(data, "big")
    txt = c32.encode(n, checksum=True, split=group_len)
    groups = txt.split('-')
    lines = ['-'.join(groups[i:i + groups_per_line])
             for i in range(0, len(groups), groups_per_line)]
    return '\n'.join(lines)


def dearmour(text: str) -> bytes:
    text = ANSI_RE.sub('', text)
    compact = ''.join(ch.upper() for ch in text if ch.upper() in ALLOWED)
    n = c32.decode(compact, checksum=True)
    bl = (n.bit_length() + 7) // 8
    return n.to_bytes(bl, "big")


# ── Public API ───────────────────────────────────────────────────────────────
def encrypt_words(words, password, b2i):
    raw = pack_words(words, b2i)
    compressed = brotli.compress(raw)
    salt = os.urandom(8)
    key = kdf(password, salt)
    nonce, ct = aes_encrypt(compressed, key)
    return armour(salt + nonce + ct)


def decrypt_words(text, password, i2b):
    blob = dearmour(text)
    salt, nonce, ct = blob[:8], blob[8:20], blob[20:]
    key = kdf(password, salt)
    data = aes_decrypt(nonce, ct, key)
    return unpack_words(brotli.decompress(data), i2b)


# ── CLI ──────────────────────────────────────────────────────────────────────
def main():
    b2i, i2b = load_bip39()
    mode = input("Encrypt or Decrypt? [E/D]: ").lower()
    if mode not in ("e", "encrypt", "d", "decrypt"):
        sys.exit("Invalid choice")

    pw = getpass.getpass("Password: ")
    try:
        if mode.startswith("e"):
            ws = input("Enter words: ").split()
            # ── Warn if any word is not in the BIP‑39 list ────────────────
            non = [(i + 1, w) for i, w in enumerate(ws) if w not in b2i]
            if non:
                print("\n⚠️  Non‑BIP39 words detected:")
                for pos, word in non:
                    print(f"   • word #{pos}: {word}")
                print("   (continuing anyway)\n")
            # ----------------------------------------------------------------
            print("\n" + encrypt_words(ws, pw, b2i))
        else:
            print("\nPaste / edit ciphertext (Esc‑Enter or Ctrl‑D to finish):")
            enc = PromptSession(multiline=True).prompt()
            print("\n" + " ".join(decrypt_words(enc, pw, i2b)))
    except Exception as e:
        sys.exit(f"Error: {e}")


if __name__ == "__main__":
    main()
