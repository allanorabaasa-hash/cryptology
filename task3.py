"""
Cryptology and Code Theory
Task 3: Asymmetric Cryptography with RSA and ECC

"""

#import math
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def heading(text):
    print("\n" + "=" * 62)
    print(text)
    print("=" * 62)

# ---------------------------------------------------------------
# Task 3(c): ECC P-256 key pair and ECIES
# ECIES = ECDH (shared secret) + HKDF (make AES key) + AES-GCM (encrypt)
# ---------------------------------------------------------------
def make_aes_key(shared_secret):
    """Turn the ECDH shared secret into a 128-bit AES key."""
    return HKDF(algorithm=hashes.SHA256(), length=16,
                salt=None, info=b"ecies").derive(shared_secret)


def task_3c():
    heading("Task 3(c): ECC P-256 key pair and ECIES")

    # Step 1: the receiver (hospital) makes a P-256 key pair
    receiver_private = ec.generate_private_key(ec.SECP256R1())
    receiver_public = receiver_private.public_key()
    print("Step 1: receiver key pair created on curve P-256")

    message = b"my name is samuel"
    print(f"Message: {message.decode()}")

    # Step 2: the sender (clinic) encrypts
    temp_private = ec.generate_private_key(ec.SECP256R1())  # new key each time
    shared_sender = temp_private.exchange(ec.ECDH(), receiver_public)
    key_sender = make_aes_key(shared_sender)
    nonce = os.urandom(12)
    ciphertext = AESGCM(key_sender).encrypt(nonce, message, None)
    print(f"Step 2: encrypted -> {ciphertext.hex()}")

    # Step 3: the receiver decrypts using the sender's temporary public key
    shared_receiver = receiver_private.exchange(ec.ECDH(), temp_private.public_key())
    key_receiver = make_aes_key(shared_receiver)
    decrypted = AESGCM(key_receiver).decrypt(nonce, ciphertext, None)
    print(f"Step 3: both sides got the same AES key: {key_sender == key_receiver}")
    print(f"Decrypted: {decrypted.decode()}")
    print("ECIES round trip OK" if decrypted == message else "FAILED")


if __name__ == "__main__":
    task_3c()