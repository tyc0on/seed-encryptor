# Seed Encryptor

**Encrypt BIP39 seed phrases into compact, base36-encoded strings for secure and stamp-friendly backups.**

---

## Features

- **Strong Encryption**: Uses AES-GCM with Scrypt key derivation for robust security.
- **Compact Format**: Converts encrypted data into a short, human-readable base36 string, ideal for physical backups.
- **BIP39 Compatibility**: Works seamlessly with standard BIP39 wordlists.
- **Backup-Friendly**: Designed to create backups suitable for stamps, QR codes, or small physical tokens.

---

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Examples](#examples)
- [Contributing](#contributing)
- [License](#license)

---

## Installation

Clone the repository and install the dependencies:

```bash
# Clone the repository
git clone https://github.com/tyc0on/seed-encryptor.git

# Navigate to the directory
cd seed-encryptor

# Install dependencies
pip install -r requirements.txt
```

---

## Usage

Run the script directly from the command line:

```bash
python seed_encryptor.py
```

### Modes

- **Encrypt**: Converts BIP39 seed phrases into an encrypted base36 string.
- **Decrypt**: Restores the original BIP39 seed phrases from the encrypted string.

### Command-Line Interaction

1. **Encryption**:
   - Input a seed phrase.
   - Provide a password.
   - Receive a base36-encoded string.

2. **Decryption**:
   - Input the base36 string.
   - Provide the correct password.
   - Retrieve the original seed phrase.

---

## Examples

### Encryption

Input:
```text
Encrypt or Decrypt? [E/D]: E
Password: ********
Enter words: apple banana cherry date elderberry fig grape
```

Output:
```text
Encrypted Base36 Ciphertext:
3p4h7xtz6wry2mk9b5jf0nqvl8g1d
```

### Decryption

Input:
```text
Encrypt or Decrypt? [E/D]: D
Password: ********
Base36 ciphertext: 3p4h7xtz6wry2mk9b5jf0nqvl8g1d
```

Output:
```text
Decrypted Seed Phrase:
apple banana cherry date elderberry fig grape
```

---

## Contributing

We welcome contributions to improve Seed Encryptor! Please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Commit your changes with clear messages.
4. Submit a pull request for review.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Acknowledgements

- **BIP39 Standard**: Ensures compatibility with industry-standard mnemonic phrases.
- **Cryptography Library**: Powers the robust encryption features.
- **brotli**: Enables efficient data compression.

---

Secure your seed phrases with confidence using **Seed Encryptor**! 🔒

