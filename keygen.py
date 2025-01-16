import secrets
from mnemonic import Mnemonic

def generate_bip39_private_key():
    # Initialize the BIP39 mnemonic generator
    mnemo = Mnemonic("english")

    # Generate 256 bits (32 bytes) of entropy securely
    entropy = secrets.token_bytes(32)

    # Generate the mnemonic (24 words) from the entropy
    mnemonic_words = mnemo.to_mnemonic(entropy)

    return mnemonic_words

if __name__ == "__main__":
    # Generate the 24-word private key
    private_key = generate_bip39_private_key()
    
    print("Your 24-word BIP39 private key:")
    print(private_key)