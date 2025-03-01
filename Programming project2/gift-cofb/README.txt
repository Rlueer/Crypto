Requirements
Python 3.6 or higher
No additional dependencies required (uses standard library only)
Notes
All tests should be run from the project root directory
Test files will be created in temporary directories and cleaned up automatically
The implementation uses 128-bit keys and 128-bit blocks throughout



## Instructions for Running Tests

### Part (a)
Run Ascon cryptographic algorithms:
- Execute Gift-cofb : `python3 gift_cofb.py`

### Part (b)
Run test modes: `python3 test_gift_cofb_modes.py`

### Part (c)
Test file changes and document signing: `python3 changes.py`

### Part (d)
Run integrity tests for Ascon: `python3 gift_test_integrity.py`

## Notes
Ensure required dependencies are installed before running the scripts.