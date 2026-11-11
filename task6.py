"""
BCS 2104 - Cryptology and Code Theory            SHUTzTER GROUP
Task 6: Integrated Secure Communication System
"""
import hashlib
import hmac
import sys
import time

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

BLOCK_SIZE = 16          # AES block size in bytes (task2.py)
SIG_SIZE = 256           # an RSA-2048 signature is always 256 bytes


# ---------------------------------------------------------------
# From task5.py: Hamming (7,4), parity bits at positions 1, 2, 4
# ---------------------------------------------------------------
def hamming74_encode(data):
    d1, d2, d3, d4 = map(int, data)
    p1 = d1 ^ d2 ^ d4          # covers positions 1,3,5,7
    p2 = d1 ^ d3 ^ d4          # covers positions 2,3,6,7
    p4 = d2 ^ d3 ^ d4          # covers positions 4,5,6,7
    return "".join(map(str, [p1, p2, d1, p4, d2, d3, d4]))


def hamming74_decode(code: str):
    b = [None] + list(map(int, code))
    s1 = b[1] ^ b[3] ^ b[5] ^ b[7]
    s2 = b[2] ^ b[3] ^ b[6] ^ b[7]
    s4 = b[4] ^ b[5] ^ b[6] ^ b[7]
    syndrome = s4 * 4 + s2 * 2 + s1
    corrected = b[:]
    if syndrome:
        corrected[syndrome] ^= 1
    corrected_word = "".join(map(str, corrected[1:]))
    data = "".join(str(corrected[i]) for i in (3, 5, 6, 7))
    return syndrome, corrected_word, data


def encode_frame(frame: bytes) -> str:
    """Whole frame -> bit string -> one 7-bit codeword per 4 data bits."""
    bits = "".join(format(byte, "08b") for byte in frame)
    return "".join(hamming74_encode(bits[i:i + 4]) for i in range(0, len(bits), 4))


def decode_frame(code: str):
    """Returns (frame bytes, list of (codeword number, error position))."""
    data_bits, corrections = [], []
    for i in range(0, len(code), 7):
        syndrome, _, data = hamming74_decode(code[i:i + 7])
        if syndrome:
            corrections.append((i // 7, syndrome))
        data_bits.append(data)
    bits = "".join(data_bits)
    frame = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))
    return frame, corrections


# ---------------------------------------------------------------
# From task4.py: RSA-2048 signature with PSS padding and SHA-256
# ---------------------------------------------------------------
def pss():
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                       salt_length=padding.PSS.MAX_LENGTH)


def sign(private_key, data: bytes) -> bytes:
    """The library takes the SHA-256 digest of data and signs that digest."""
    return private_key.sign(data, pss(), hashes.SHA256())


def signature_valid(public_key, signature: bytes, data: bytes) -> bool:
    try:
        public_key.verify(signature, data, pss(), hashes.SHA256())
        return True
    except Exception:
        return False


# ---------------------------------------------------------------
# From task3.py: ECDH on P-256, then HKDF gives the 128-bit key
# ---------------------------------------------------------------
def make_aes_key(shared_secret):
    """Turn the ECDH shared secret into a 128-bit AES key."""
    return HKDF(algorithm=hashes.SHA256(), length=16,
                salt=None, info=b"ecies").derive(shared_secret)


def make_hmac_key(session_key):
    """A separate key for HMAC, so one key is not used for two jobs."""
    return HKDF(algorithm=hashes.SHA256(), length=32,
                salt=None, info=b"hmac").derive(session_key)


def establish_session(clinic_rsa, hospital_ec, clinic_rsa_public=None):
    """Task 3(c) key agreement. Returns (clinic's key, hospital's key).

    The clinic signs its temporary public key, which is the fix for the
    man-in-the-middle attack of Task 3(e). Returns (None, None) if the
    hospital finds the signature invalid.
    """
    clinic_rsa_public = clinic_rsa_public or clinic_rsa.public_key()

    # Clinic: new temporary key pair, shared secret with hospital's public key
    temp_private = ec.generate_private_key(ec.SECP256R1())
    temp_public = temp_private.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint)
    temp_signature = sign(clinic_rsa, temp_public)
    key_clinic = make_aes_key(
        temp_private.exchange(ec.ECDH(), hospital_ec.public_key()))

    # Hospital: check the signature, then compute the same shared secret
    if not signature_valid(clinic_rsa_public, temp_signature, temp_public):
        return None, None
    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), temp_public)
    key_hospital = make_aes_key(hospital_ec.exchange(ec.ECDH(), peer))
    return key_clinic, key_hospital


# ---------------------------------------------------------------
# Sender
# ---------------------------------------------------------------
def build_frame(plaintext: bytes, session_key: bytes, sender_rsa):
    """Encrypt, MAC and sign. Returns (frame bytes, details)."""
    # 1. AES-128 in CBC mode with a random IV (task2.py)
    iv = get_random_bytes(BLOCK_SIZE)
    ciphertext = AES.new(session_key, AES.MODE_CBC, iv=iv).encrypt(
        pad(plaintext, BLOCK_SIZE))

    # 2. HMAC-SHA256 over IV + ciphertext (task4.py)
    tag = hmac.new(make_hmac_key(session_key), iv + ciphertext,
                   hashlib.sha256).digest()

    # 3. RSA signature over the SHA-256 digest of IV + ciphertext (task4.py)
    digest = hashlib.sha256(iv + ciphertext).hexdigest()
    signature = sign(sender_rsa, iv + ciphertext)

    # 4. Frame = IV (16) | MAC (32) | signature (256) | ciphertext
    frame = iv + tag + signature + ciphertext
    return frame, {"iv": iv, "ciphertext": ciphertext, "tag": tag,
                   "digest": digest, "signature": signature}


def send(plaintext: bytes, session_key: bytes, sender_rsa):
    """Full sender side. Returns (bit string for the channel, details)."""
    frame, details = build_frame(plaintext, session_key, sender_rsa)
    code = encode_frame(frame)             # 5. Hamming (7,4) (task5.py)
    details["frame_bytes"], details["bits"] = len(frame), len(code)
    return code, details

# ---------------------------------------------------------------
# Channel
# ---------------------------------------------------------------
def noisy_channel(code: str, flip_positions=()):
    """Copies the bit string and flips the bits at the given positions."""
    bits = list(code)
    for p in flip_positions:
        bits[p] = "1" if bits[p] == "0" else "0"
    return "".join(bits)


# ---------------------------------------------------------------
# Receiver
# ---------------------------------------------------------------
class Rejected(Exception):
    """The frame failed a check and must be sent again."""


def receive(code: str, session_key: bytes, sender_rsa_public):
    """Decode, verify and decrypt. Returns (plaintext, corrections)."""
    # 1. Hamming decode: locate and correct single-bit errors
    frame, corrections = decode_frame(code)

    # 2. Split the frame back into its fields
    iv, tag = frame[:16], frame[16:48]
    signature, ciphertext = frame[48:48 + SIG_SIZE], frame[48 + SIG_SIZE:]

    # 3. HMAC check first; nothing is decrypted if it fails
    expected = hmac.new(make_hmac_key(session_key), iv + ciphertext,
                        hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise Rejected("HMAC INVALID - frame altered or uncorrectable")

    # 4. Signature check with the sender's public key
    if not signature_valid(sender_rsa_public, signature, iv + ciphertext):
        raise Rejected("SIGNATURE INVALID - sender not authentic")

    # 5. AES-128-CBC decryption and padding removal
    padded = AES.new(session_key, AES.MODE_CBC, iv=iv).decrypt(ciphertext)
    return unpad(padded, BLOCK_SIZE), corrections


# ---------------------------------------------------------------
# Demonstration
# ---------------------------------------------------------------
MESSAGE = b"Patient: John Doe, Diagnosis: MCI"                    # task4.py
REPORT = (b"Radiology Report: Patient John Doe. "
          b"Finding: MCI. Status: Verified.")                       # task4.py
BAR = "=" * 76


def show(label, value):
    print(f"  {label:<18}: {value}")


def new_rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def demo(clinic_rsa, hospital_rsa, session_key):
    """Task 6(c): successful transmission and single-bit error correction."""
    print("\n[1] SUCCESSFUL TRANSMISSION (clinic -> hospital, clean channel)")
    code, d = send(MESSAGE, session_key, clinic_rsa)
    show("Plaintext sent", MESSAGE.decode())
    show("AES-128-CBC IV", d["iv"].hex())
    show("Ciphertext", d["ciphertext"].hex()[:48] + "...")
    show("HMAC-SHA256", d["tag"].hex()[:48] + "...")
    show("SHA-256 digest", d["digest"][:48] + "...")
    show("RSA signature", d["signature"].hex()[:48] + "...")
    show("Hamming(7,4)",
         f"{d['frame_bytes']} bytes -> {d['bits']} bits on the channel")
    received, fixes = receive(noisy_channel(code), session_key,
                              clinic_rsa.public_key())
    show("Errors corrected", len(fixes))
    show("HMAC / signature", "VALID / VALID")
    show("Plaintext received", received.decode())
    show("RESULT", "SUCCESS" if received == MESSAGE else "FAILED")

    print("\n[2] SINGLE-BIT ERROR DETECTED AND CORRECTED")
    word, position = 650, 6                 # a codeword inside the ciphertext
    flip = word * 7 + (position - 1)
    damaged = noisy_channel(code, [flip])
    show("Channel error", f"bit {flip} flipped (codeword {word}, position {position})")
    show("Codeword sent", code[word * 7:word * 7 + 7])
    show("Codeword received", damaged[word * 7:word * 7 + 7])
    received, fixes = receive(damaged, session_key, clinic_rsa.public_key())
    for n, s in fixes:
        show("Syndrome C4C2C1", f"{s:03b} = {s} -> error at position {s} -> bit flipped back")
    show("Errors corrected", len(fixes))
    show("HMAC / signature", "VALID / VALID")
    show("Plaintext received", received.decode())
    show("RESULT", "ERROR CORRECTED, MESSAGE RECOVERED" if received == MESSAGE else "FAILED")
    return code


def more_tests(clinic_rsa, hospital_rsa, hospital_ec, session_key, code):
    print("\n[3] TWO ERRORS IN ONE CODEWORD (beyond Hamming's ability)")
    try:
        receive(noisy_channel(code, [650 * 7 + 2, 650 * 7 + 5]),
                session_key, clinic_rsa.public_key())
    except Rejected as e:
        show("RESULT", f"REJECTED ({e})")

    print("\n[4] ATTACKER CHANGES ONE CIPHERTEXT BYTE")
    frame, _ = decode_frame(code)
    forged = bytearray(frame)
    forged[-1] ^= 0x01
    try:
        receive(encode_frame(bytes(forged)), session_key, clinic_rsa.public_key())
    except Rejected as e:
        show("RESULT", f"REJECTED ({e})")

    print("\n[5] SIGNED DIAGNOSIS REPORT RETURNED (hospital -> clinic)")
    report_code, _ = send(REPORT, session_key, hospital_rsa)
    received, fixes = receive(noisy_channel(report_code, [333]), session_key,
                              hospital_rsa.public_key())
    show("Errors corrected", len(fixes))
    show("Signature", "VALID (hospital's public key)")
    show("Report received", received.decode()[:35])
    show("", received.decode()[36:])
    fake_code, _ = send(REPORT.replace(b"MCI", b"Normal"), session_key, new_rsa_key())
    try:
        receive(fake_code, session_key, hospital_rsa.public_key())
    except Rejected as e:
        show("Forged report", f"REJECTED ({e})")

    print("\n[6] MAN-IN-THE-MIDDLE ON THE KEY EXCHANGE")
    k1, _ = establish_session(new_rsa_key(), hospital_ec, clinic_rsa.public_key())
    show("RESULT", "REJECTED (signature on the temporary key INVALID)"
         if k1 is None else "ACCEPTED")

    print("\n[7] OVERHEAD AND TIMING (100 KB payload, this machine)")
    payload = get_random_bytes(100 * 1024)
    t_crypto, t_hamming, t_receive = [], [], []
    for _ in range(3):                       # best of 3 runs
        t0 = time.perf_counter()
        frame, _ = build_frame(payload, session_key, clinic_rsa)
        t1 = time.perf_counter()
        big = encode_frame(frame)
        t2 = time.perf_counter()
        out, _ = receive(big, session_key, clinic_rsa.public_key())
        t3 = time.perf_counter()
        t_crypto.append(t1 - t0)
        t_hamming.append(t2 - t1)
        t_receive.append(t3 - t2)
    show("Payload", f"{len(payload)} bytes")
    extra = len(frame) - len(payload)
    show("Frame", f"{len(frame)} bytes (+{extra} for IV, MAC, signature, padding)")
    ratio = len(big) / 8 / len(payload)
    show("On the channel", f"{len(big) // 8} bytes ({ratio:.2f} x the payload)")
    show("AES + HMAC + RSA", f"{min(t_crypto) * 1000:.1f} ms")
    show("Hamming encode", f"{min(t_hamming) * 1000:.1f} ms")
    show("Receiver total", f"{min(t_receive) * 1000:.1f} ms")
    show("Round trip correct", out == payload)


def main():
    clinic_rsa, hospital_rsa = new_rsa_key(), new_rsa_key()
    hospital_ec = ec.generate_private_key(ec.SECP256R1())

    print(BAR)
    print(" BCS 2104 TASK 6 - SECURE TELEMEDICINE SYSTEM   (SHUTTER GROUP)")
    print(BAR)
    key_clinic, key_hospital = establish_session(clinic_rsa, hospital_ec)
    show("Session key (ECDH)", key_clinic.hex())
    show("Both sides match", key_clinic == key_hospital)

    code = demo(clinic_rsa, hospital_rsa, key_clinic)
    if "--more" in sys.argv:
        more_tests(clinic_rsa, hospital_rsa, hospital_ec, key_clinic, code)
    print(BAR)


if __name__ == "__main__":
    main()
