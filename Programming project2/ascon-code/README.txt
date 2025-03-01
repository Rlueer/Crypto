Requirements
Python 3.6 or higher
No additional dependencies required (uses standard library only)
Notes
All tests should be run from the project root directory
Test files will be created in temporary directories and cleaned up automatically
The implementation uses 128-bit keys and 128-bit blocks throughout


## Instructions for Running Tests

### Part (a)
Run Ascon cryptographic algorithms or generate test outputs:
- Execute Ascon modes: `python3 ascon.py`
- Generate multiple test outputs in TXT/JSON format: `python3 genkat.py` with one of these modes:
  - "Ascon-Mac", "Ascon-Prf", "Ascon-PrfShort"
  - "Ascon-Hash256", "Ascon-XOF128", "Ascon-CXOF128"
  - "Ascon-AEAD128"

### Part (b)
Run test modes: `python3 test_modes.py`

### Part (c)
Test file changes and document signing: `python3 changes.py`

### Part (d)
Run integrity tests for Ascon: `python3 ascon_test_integrity.py`

## Notes
Ensure required dependencies are installed before running the scripts.