import hashlib
import hmac
import base64
import bcrypt

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding


# ------------------------------------------------------------
# (a) SHA-256 and avalanche effect
# ------------------------------------------------------------
MESSAGE = "Patient: John Doe, Diagnosis: MCI"
CHANGED_MESSAGE = "Patient: John Doe, Diagnosis: MC1"

def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def bit_difference(hex_a: str, hex_b: str) -> int:
    a = bytes.fromhex(hex_a)
    b = bytes.fromhex(hex_b)
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))

hash_original = sha256_hex(MESSAGE)
hash_changed = sha256_hex(CHANGED_MESSAGE)

print("=" * 70)
print("(a) SHA-256 HASHING AND AVALANCHE EFFECT")
print("=" * 70)
print("Original message:")
print(MESSAGE)
print("\nChanged message:")
print(CHANGED_MESSAGE)
print("\nSHA-256(original):")
print(hash_original)
print("\nSHA-256(changed):")
print(hash_changed)

changed_bits = bit_difference(hash_original, hash_changed)
print(f"\nDifferent output bits: {changed_bits} out of 256")
print(f"Percentage changed: {changed_bits / 256 * 100:.2f}%")

# ------------------------------------------------------------
# (b) HMAC-SHA256
# ------------------------------------------------------------
SHARED_SECRET = b"MMU-CS2104-Task4-Key"

hmac_tag = hmac.new(
    SHARED_SECRET,
    MESSAGE.encode("utf-8"),
    hashlib.sha256
).hexdigest()

print("\n" + "=" * 70)
print("(b) HMAC-SHA256")
print("=" * 70)
print("Shared secret key:")
print(SHARED_SECRET.decode())
print("\nHMAC-SHA256:")
print(hmac_tag)

# Demonstrate verification.
received_message = MESSAGE
received_tag = hmac_tag

valid = hmac.compare_digest(
    hmac.new(
        SHARED_SECRET,
        received_message.encode("utf-8"),
        hashlib.sha256
    ).hexdigest(),
    received_tag
)

print("\nHMAC verification:", "VALID" if valid else "INVALID")

# Demonstrate failure after tampering.
tampered_message = "Patient: John Doe, Diagnosis: HIV"
tampered_valid = hmac.compare_digest(
    hmac.new(
        SHARED_SECRET,
        tampered_message.encode("utf-8"),
        hashlib.sha256
    ).hexdigest(),
    received_tag
)

print("Verification after message tampering:",
      "VALID" if tampered_valid else "INVALID")

# ------------------------------------------------------------
# (c) RSA digital signature
# ------------------------------------------------------------
REPORT = (
    "Radiology Report: Patient John Doe. "
    "Finding: MCI. Status: Verified."
)

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

signature = private_key.sign(
    REPORT.encode("utf-8"),
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

print("\n" + "=" * 70)
print("(c) RSA DIGITAL SIGNATURE")
print("=" * 70)
print("Report:")
print(REPORT)
print("\nSHA-256(report):")
print(hashlib.sha256(REPORT.encode("utf-8")).hexdigest())
print(f"\nSignature length: {len(signature)} bytes")
print("Signature (Base64, first 80 characters):")
print(base64.b64encode(signature).decode()[:80] + "...")

try:
    public_key.verify(
        signature,
        REPORT.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("\nSignature verification: VALID")
except Exception:
    print("\nSignature verification: INVALID")

# Test tampering.
tampered_report = REPORT.replace("MCI", "Normal")

try:
    public_key.verify(
        signature,
        tampered_report.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Tampered report verification: VALID (unexpected)")
except Exception:
    print("Tampered report verification: INVALID (tampering detected)")

