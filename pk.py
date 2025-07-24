#!/usr/bin/env python3
# pip install cryptography brotli prompt_toolkit
# source venv/bin/activate
# python pk.py

import os, sys, re, brotli, getpass, base64
from prompt_toolkit import PromptSession
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

# ── BIP-39 helpers ───────────────────────────────────────────────────────────
def load_bip39(p="english.txt"):
    with open(p, encoding="utf-8") as f:
        words = [x.strip() for x in f]
    if len(words) != 2048:
        raise ValueError("Invalid BIP39 word-list")
    return {w: i for i, w in enumerate(words)}, words


def to_bits(v, n):                     # LSB first → MSB last
    return [(v >> i) & 1 for i in range(n)][::-1]


def from_bits(bits):                   # MSB first
    val = 0
    for b in bits:
        val = (val << 1) | b
    return val


def pack_words(ws, b2i):
    bits = []
    for w in ws:
        if w in b2i:                  # mode-0: dictionary word
            bits.append(0)
            bits += to_bits(b2i[w], 11)
        else:                         # mode-1: arbitrary UTF-8 word
            bits.append(1)
            b = w.encode()
            bits += to_bits(len(b), 16)
            for byte in b:
                bits += to_bits(byte, 8)

    while len(bits) % 8:
        bits.append(0)                # pad with zero bits

    return bytes(from_bits(bits[i:i + 8]) for i in range(0, len(bits), 8))


def unpack_words(data, i2b):
    bits = [bit for byte in data for bit in to_bits(byte, 8)]
    ws, i = [], 0
    while i < len(bits):

        # stop if the remainder is just zero padding
        if all(b == 0 for b in bits[i:]):
            break

        mode = bits[i]; i += 1
        if mode == 0:                 # dictionary word
            if i + 11 > len(bits): break
            idx = from_bits(bits[i:i + 11]); i += 11
            ws.append(i2b[idx])
        else:                         # raw word
            if i + 16 > len(bits): break
            ln = from_bits(bits[i:i + 16]); i += 16
            if i + 8 * ln > len(bits): break
            bb = [from_bits(bits[i + 8 * k:i + 8 * (k + 1)]) for k in range(ln)]
            i += 8 * ln
            ws.append(bytes(bb).decode())
    return ws


# ── Crypto helpers ───────────────────────────────────────────────────────────
def kdf(pw: str, salt: bytes, ln: int = 32) -> bytes:
    return Scrypt(salt=salt, length=ln, n=2 ** 15, r=8, p=1,
                  backend=default_backend()).derive(pw.encode())


def aes_encrypt(raw: bytes, key: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    return nonce, AESGCM(key).encrypt(nonce, raw, None)


def aes_decrypt(nonce: bytes, ct: bytes, key: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, ct, None)


# ── Crockford-32 armour (no checksum) ────────────────────────────────────────
ANSI_RE = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')        # CSI sequences

# Crockford alphabet (value -> char)
CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
# Reverse map for decoding; include common ambiguous chars
REV_MAP = {c: i for i, c in enumerate(CROCKFORD)}
REV_MAP.update({
    'O': 0,  # treat O as 0
    'I': 1, 'L': 1,  # I/L -> 1
})

def _chunk(s, n):
    return [s[i:i + n] for i in range(0, len(s), n)]

def _crockford_encode(data: bytes) -> str:
    """
    Encode bytes to Crockford Base32 WITHOUT checksum.
    We keep RFC4648 padding semantics internally via base64.b32encode,
    then translate to Crockford alphabet and strip '=' (padding) characters.
    """
    b32 = base64.b32encode(data).decode('ascii')  # RFC4648 alphabet + '='
    out = []
    for ch in b32:
        if ch == '=':
            continue  # remove padding; length is recoverable
        val = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".index(ch)
        out.append(CROCKFORD[val])
    return ''.join(out)

def _crockford_decode(text: str) -> bytes:
    """
    Decode Crockford Base32 text (no checksum).
    Accepts dashes, whitespace, and ambiguous chars.
    """
    # Strip ANSI & collect valid chars
    cleaned = ANSI_RE.sub('', text).upper()
    compact = ''.join(ch for ch in cleaned if ch in REV_MAP)

    if not compact:
        raise ValueError("No Crockford characters found.")

    # Map back to RFC4648 alphabet indices
    vals = [REV_MAP[c] for c in compact]
    # Convert to RFC4648 string (without padding)
    rfc = ''.join("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[v] for v in vals)
    # Reconstruct padding to nearest multiple of 8
    pad_len = (-len(rfc)) % 8
    rfc_padded = rfc + "=" * pad_len
    try:
        return base64.b32decode(rfc_padded)
    except Exception as e:
        raise ValueError(f"Base32 decode failed: {e}")

def armour(data: bytes, groups_per_line: int = 3, group_len: int = 5) -> str:
    body = _crockford_encode(data)
    groups = _chunk(body, group_len)
    lines = ['-'.join(groups[i:i + groups_per_line])
             for i in range(0, len(groups), groups_per_line)]
    return '\n'.join(lines)

def dearmour(text: str) -> bytes:
    return _crockford_decode(text)


# ── Public API ───────────────────────────────────────────────────────────────
def encrypt_words(word_list, password, b2i):
    raw = pack_words(word_list, b2i)
    compressed = brotli.compress(raw)
    salt = os.urandom(8)
    key = kdf(password, salt)
    nonce, ct = aes_encrypt(compressed, key)
    return armour(salt + nonce + ct)


def decrypt_words(text, password, i2b):
    blob = dearmour(text)
    if len(blob) < 8 + 12 + 16:
        raise ValueError("Ciphertext too short.")
    salt, nonce, ct = blob[:8], blob[8:20], blob[20:]
    key = kdf(password, salt)
    try:
        data = aes_decrypt(nonce, ct, key)
    except Exception:
        raise ValueError("Decryption failed (wrong password or corrupted ciphertext).")
    return unpack_words(brotli.decompress(data), i2b)


# ── CLI ──────────────────────────────────────────────────────────────────────
def main():
    b2i, i2b = load_bip39()
    mode = input("Encrypt or Decrypt? [E/D]: ").strip().lower()
    if mode not in ("e", "encrypt", "d", "decrypt"):
        sys.exit("Invalid choice")

    pw = getpass.getpass("Password: ")

    try:
        if mode.startswith('e'):
            ws = input("Enter words: ").split()

            # warn about non-BIP39 words
            non = [(idx + 1, w) for idx, w in enumerate(ws) if w not in b2i]
            if non:
                print("\n⚠️  Non-BIP39 words detected:")
                for pos, w in non:
                    print(f"   • word #{pos}: {w}")
                print("   (continuing anyway)\n")

            print("\n" + encrypt_words(ws, pw, b2i))

        else:
            print("\nPaste / edit ciphertext (Esc-Enter or Ctrl-D to finish):")
            enc = PromptSession(multiline=True).prompt()
            words = decrypt_words(enc, pw, i2b)
            print("\n" + " ".join(words))

    except Exception as e:
        sys.exit(f"Error: {e}")


if __name__ == "__main__":
    main()
