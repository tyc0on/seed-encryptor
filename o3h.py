#!/usr/bin/env python3
import os
import sys
import math
import getpass
import brotli
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

# -------------- Base36 helper functions --------------
def base36_encode(data: bytes) -> str:
    """Encode bytes into a base36 string."""
    num = int.from_bytes(data, "big")
    if num == 0:
        return "0"
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
    result = ""
    while num:
        num, rem = divmod(num, 36)
        result = alphabet[rem] + result
    return result

def base36_decode(s: str) -> bytes:
    """Decode a base36 string into bytes."""
    try:
        num = int(s, 36)
    except ValueError:
        raise ValueError("Input is not valid base36.")
    # Compute the minimal number of bytes needed.
    num_bytes = (num.bit_length() + 7) // 8
    return num.to_bytes(num_bytes, "big")

# -------------- Mnemonic packing/unpacking --------------
def pack_mnemonic_indices(indices):
    """
    Pack a list of integers (each 0 <= x < 2048) into a compact bytes string.
    Each index is stored in 11 bits. A 1-byte header with the count is prepended.
    """
    count = len(indices)
    total_bits = count * 11
    acc = 0
    for index in indices:
        # Each index should fit in 11 bits.
        if index >= (1 << 11):
            raise ValueError("Index out of range.")
        acc = (acc << 11) | index
    byte_len = (total_bits + 7) // 8
    # Pack header: one byte for the count
    header = count.to_bytes(1, "big")
    packed = acc.to_bytes(byte_len, "big")
    return header + packed

def unpack_mnemonic_indices(data: bytes):
    """
    Unpack bytes into a list of mnemonic indices.
    Expects the first byte to be the count.
    """
    if len(data) < 1:
        raise ValueError("Data is too short.")
    count = data[0]
    packed = data[1:]
    total_bits = count * 11
    total_bytes = (total_bits + 7) // 8
    if len(packed) < total_bytes:
        raise ValueError("Not enough data to extract all indices.")
    # Convert packed bytes into a binary string.
    bit_str = bin(int.from_bytes(packed, "big"))[2:].zfill(len(packed) * 8)
    # Remove extra bits from the left (if any)
    extra = len(packed) * 8 - total_bits
    bit_str = bit_str[extra:]
    indices = []
    for i in range(count):
        chunk = bit_str[i * 11 : (i + 1) * 11]
        indices.append(int(chunk, 2))
    return indices

# -------------- KDF and Encryption --------------
def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a symmetric key from the password and salt using scrypt.
    """
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_data(data: bytes, password: str) -> bytes:
    """
    Encrypt data using AES-GCM. Returns salt || nonce || ciphertext.
    """
    salt = os.urandom(16)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    # Clear sensitive variables (best effort)
    del key
    return salt + nonce + ciphertext

def decrypt_data(encrypted: bytes, password: str) -> bytes:
    """
    Decrypt data that was encrypted using encrypt_data.
    Expects encrypted = salt (16) || nonce (12) || ciphertext.
    """
    if len(encrypted) < 16 + 12:
        raise ValueError("Encrypted data is too short.")
    salt = encrypted[:16]
    nonce = encrypted[16:28]
    ciphertext = encrypted[28:]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    # Clear sensitive variables (best effort)
    del key
    return aesgcm.decrypt(nonce, ciphertext, None)

# -------------- BIP39 Wordlist Loading --------------
def load_bip39_wordlist(filepath="english.txt"):
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            words = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error loading BIP39 wordlist from {filepath}: {e}")
        sys.exit(1)
    # Create a mapping from word to its index (0-based)
    word_to_index = {word: idx for idx, word in enumerate(words)}
    return words, word_to_index

# -------------- Main Program --------------
def main():
    # Load BIP39 word list and mapping.
    wordlist, word_to_index = load_bip39_wordlist()

    # Ask user if encrypting or decrypting.
    mode = input("Do you want to (e)ncrypt or (d)ecrypt? ").strip().lower()
    if mode not in ("e", "encrypt", "d", "decrypt"):
        print("Invalid mode selected.")
        sys.exit(1)

    password = getpass.getpass("Enter password: ")

    if mode in ("e", "encrypt"):
        mnemonic = input("Enter mnemonic (BIP39 words separated by spaces): ").strip()
        words = mnemonic.split()
        if not words:
            print("No words entered.")
            sys.exit(1)
        # Validate words.
        invalid = [w for w in words if w not in word_to_index]
        if invalid:
            print("Warning: The following words are not valid BIP39 words:")
            for w in invalid:
                print(f"  {w}")
            sys.exit(1)
        # Convert words to their indices.
        indices = [word_to_index[w] for w in words]
        # Pack indices into a compact bytes representation.
        packed = pack_mnemonic_indices(indices)
        # Compress the packed data with Brotli.
        compressed = brotli.compress(packed)
        # Encrypt the compressed data.
        encrypted_blob = encrypt_data(compressed, password)
        # Encode the binary blob in base36.
        encoded = base36_encode(encrypted_blob)
        print("\nEncrypted (base36) output:")
        print(encoded)
    else:  # decryption mode
        encoded = input("Enter base36 encrypted data: ").strip()
        try:
            encrypted_blob = base36_decode(encoded)
        except ValueError as e:
            print(f"Error decoding base36 data: {e}")
            sys.exit(1)
        try:
            # Decrypt to get the compressed bytes.
            compressed = decrypt_data(encrypted_blob, password)
        except Exception as e:
            print("Decryption failed. Possibly incorrect password or corrupted data.")
            sys.exit(1)
        try:
            # Decompress the data.
            packed = brotli.decompress(compressed)
        except Exception as e:
            print("Decompression failed.")
            sys.exit(1)
        try:
            # Unpack the mnemonic indices.
            indices = unpack_mnemonic_indices(packed)
        except Exception as e:
            print(f"Error unpacking mnemonic data: {e}")
            sys.exit(1)
        try:
            # Convert indices back to words.
            recovered_words = [wordlist[i] for i in indices]
        except Exception as e:
            print(f"Error converting indices to words: {e}")
            sys.exit(1)
        print("\nDecrypted mnemonic:")
        print(" ".join(recovered_words))

    # Clear sensitive data variables if possible.
    del password

if __name__ == "__main__":
    main()
