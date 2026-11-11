# BCS 2104 – Cryptology and Code Theory Coursework
## Shutter Group

This folder contains the Python scripts for Tasks 1–5 and the integrated
prototype for Task 6, together with the coursework report.

## 1. Requirements

- Python 3.10 or later
- `pycryptodome`
- `cryptography`
- `bcrypt`

The Python standard-library modules used by the scripts (such as `hashlib`,
`hmac`, `collections`, `string`, `os`, `sys`, and `time`) do not need to be
installed separately.

## 2. Setup

Open Command Prompt or PowerShell in this folder (the folder containing
`task1.py` through `task6.py`).

It is recommended to create and activate a virtual environment:

### Windows (Command Prompt)

```bat
py -m venv .venv
.venv\Scripts\activate
py -m pip install --upgrade pip
py -m pip install -r requirements.txt
```

### Windows (PowerShell)

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
py -m pip install --upgrade pip
py -m pip install -r requirements.txt
```

If Windows does not recognize `py`, use `python` in its place.

## 3. Running the coursework scripts

Run each script from this folder:

```bash
python task1.py
python task2.py
python task3.py
python task4.py
python task5.py
python task6.py
```

For the additional Task 6 tests and timing output, run:

```bash
python task6.py --more
```

On Windows, `py` can be used instead of `python`, for example:

```bat
py task6.py --more
```

### What each script demonstrates

| File | Main contents |
|---|---|
| `task1.py` | Letter-frequency analysis and estimated Caesar-shift decryption of the supplied ciphertext. |
| `task2.py` | AES-128 block encryption, XOR demonstration, ECB/CBC comparison, and AES-128 key expansion. |
| `task3.py` | Elliptic-curve Diffie–Hellman (P-256), HKDF-SHA256 key derivation, and AES-GCM encryption/decryption. |
| `task4.py` | SHA-256 hashing, HMAC-SHA256, RSA-PSS signing/verification, and bcrypt password hashing. |
| `task5.py` | Hamming (7,4) encoding, single-bit error detection/correction demonstration. |
| `task6.py` | Integrated secure telemedicine communication prototype using ECDH/HKDF, AES-CBC, HMAC-SHA256, RSA-PSS signatures, and Hamming (7,4) error correction. |

## 4. Notes

- Run the commands from the `CCT` project folder so that the script paths
  resolve correctly.
- Some outputs contain randomly generated keys, IVs, nonces, or signatures.
  Therefore, those values can differ between runs.
- Task 6's normal run performs the main demonstration. The `--more` option
  runs the additional tests and timing demonstration.
- Task 4 currently executes its demonstrations when the file is run. It
  imports `bcrypt`, so install all packages listed in `requirements.txt`
  before running it.
- The supplied Task 5 script demonstrates Hamming (7,4). Although its
  introductory comment mentions a cyclic (7,4) code, a cyclic-code
  implementation is not present in the supplied script. This README
  describes the code as supplied and does not claim that missing feature
  has been implemented.

## 5. Project files

- `task1.py` – Task 1 source code
- `task2.py` – Task 2 source code
- `task3.py` – Task 3 source code
- `task4.py` – Task 4 source code
- `task5.py` – Task 5 source code
- `task6.py` – Task 6 integrated prototype
- `BCS2104_Cryptology_Coursework_Report.docx` – Coursework report
- `requirements.txt` – Third-party Python dependencies
- `README.md` – Setup and execution instructions
