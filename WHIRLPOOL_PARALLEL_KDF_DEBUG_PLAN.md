# Whirlpool Parallel KDF Import Issue - Debug Plan

## Problem Summary
`test_parallel_all_hash_algorithms` fails in GitLab CI with:
```
ModuleNotFoundError: No module named 'whirlpool'
```

**Current Status:**
- ✅ Test passes locally with venv activated
- ❌ Test fails in GitLab CI pipeline
- 📍 Branch: `releases/1.4.x`
- 📍 File: `openssl_encrypt/modules/parallel_kdf.py`
- 📍 Function: `_hash_worker()` (multiprocessing worker)

## Root Cause Hypothesis
The `_hash_worker()` function runs in a **separate process** (via multiprocessing), and the whirlpool module is not being imported correctly in the worker process.

## What We've Tried (All Failed)
1. ❌ Called `setup_whirlpool()` inside the iteration loop (inefficient)
2. ❌ Called `setup_whirlpool()` before the loop
3. ❌ Direct `sys.modules` aliasing in worker
4. ❌ Using a `whirlpool_module` variable with import aliasing

## Investigation Steps for Tomorrow

### Step 1: Verify Package Installation in CI
Check if `whirlpool-py311` is actually installed in the Docker image.

**GitLab CI Image:** `registry.rm-rf.ch/world/openssl_encrypt/python-liboqs:3.13-alpine`

**Actions:**
1. Add debug output to CI pipeline before tests:
   ```yaml
   - pip list | grep whirlpool
   - python3 -c "import sys; print(sys.version)"
   - python3 -c "import whirlpool_py311; print(whirlpool_py311.__file__)"
   ```

2. Check if the package is in `requirements.txt`:
   ```
   whirlpool-py311>=1.0.0,<2.0.0 ; python_version >= '3.11'
   ```

### Step 2: Test Multiprocessing Import Directly
Create a minimal test case to reproduce the issue:

**File:** `test_whirlpool_mp.py`
```python
import multiprocessing as mp

def worker():
    try:
        import whirlpool
        print("✅ whirlpool import succeeded")
        return True
    except ImportError as e:
        print(f"❌ whirlpool import failed: {e}")
        try:
            import whirlpool_py311
            print("✅ whirlpool_py311 import succeeded")
            return True
        except ImportError as e2:
            print(f"❌ whirlpool_py311 import failed: {e2}")
            return False

if __name__ == "__main__":
    # Test in main process
    print("Main process:")
    worker()

    # Test in subprocess
    print("\nSubprocess:")
    with mp.Pool(1) as pool:
        result = pool.apply(worker)
        print(f"Result: {result}")
```

Run this in CI to see what happens.

### Step 3: Check Multiprocessing Start Method
The multiprocessing start method matters:
- **fork**: Child inherits parent's memory (Linux default)
- **spawn**: Fresh Python interpreter (may not have imports)
- **forkserver**: Hybrid approach

**Check current method:**
```python
import multiprocessing as mp
print(mp.get_start_method())
```

### Step 4: Potential Solutions to Try

#### Option A: Skip Whirlpool in Parallel KDF
Whirlpool is deprecated anyway. We could:
1. Skip whirlpool in `parallel_kdf.py` test
2. Add a warning that whirlpool doesn't work in parallel mode
3. Still support it in regular (non-parallel) hash operations

**Code change:**
```python
# In test_parallel_kdf.py
HASH_ALGORITHMS = ["sha256", "sha512", "sha3_256", "blake2b", "blake3"]
# Note: whirlpool excluded due to multiprocessing import issues
```

#### Option B: Use `importlib` Instead of `import`
Try dynamic import with importlib:
```python
import importlib

whirlpool_module = None
if algorithm == "whirlpool":
    try:
        whirlpool_module = importlib.import_module("whirlpool")
    except ImportError:
        try:
            whirlpool_module = importlib.import_module("whirlpool_py311")
        except ImportError:
            raise ImportError("Whirlpool module not available")
```

#### Option C: Pre-import in Main Process
Import whirlpool in the main process before creating the pool:
```python
# In parallel_kdf.py, before creating ProcessPoolExecutor
try:
    import whirlpool  # Pre-import for fork to work
except ImportError:
    try:
        import whirlpool_py311 as whirlpool
        import sys
        sys.modules["whirlpool"] = whirlpool_py311
    except ImportError:
        pass
```

#### Option D: Use Thread Pool Instead of Process Pool
For hash algorithms, threads might work (GIL is released during hashing):
```python
from concurrent.futures import ThreadPoolExecutor
# Instead of ProcessPoolExecutor
```

#### Option E: Initialize Worker with Whirlpool
Use pool initializer to set up each worker:
```python
def init_worker():
    """Initialize worker process with whirlpool module."""
    try:
        import whirlpool
    except ImportError:
        try:
            import whirlpool_py311
            import sys
            sys.modules["whirlpool"] = whirlpool_py311
        except ImportError:
            pass

# When creating pool
with ProcessPoolExecutor(max_workers=..., initializer=init_worker) as executor:
    ...
```

### Step 5: Check for Alpine Linux Issues
The CI uses Alpine Linux (`python:3.13-alpine`). Alpine has musl libc instead of glibc.

**Potential issues:**
- Binary wheels may not work on Alpine
- Need to check if `whirlpool-py311` has proper Alpine support

**Test:**
```bash
# In CI, check the wheel
pip download whirlpool-py311==1
ls -la whirlpool*
file whirlpool*.whl
```

### Step 6: Check Python Version Mismatch
- Local: Python 3.14.2
- CI: Python 3.13

**Action:** Check if `whirlpool-py311` is compatible with Python 3.13.

## Recommended Approach for Tomorrow

### Quick Fix (Recommended)
**Skip whirlpool in parallel KDF tests** since it's deprecated:
1. Remove whirlpool from the test's hash algorithm list
2. Add a comment explaining the limitation
3. Keep whirlpool working in non-parallel code paths

### Proper Fix (If Time Permits)
1. Add debug output to CI pipeline
2. Run minimal multiprocessing test in CI
3. Try Option E (pool initializer)
4. If that fails, implement quick fix

## Files to Check
- `openssl_encrypt/modules/parallel_kdf.py` - Worker function
- `openssl_encrypt/unittests/test_parallel_kdf.py` - Test file
- `.gitlab-ci.yml` - CI configuration
- `requirements.txt` - Dependencies

## Related Issues
- Whirlpool is deprecated in the codebase
- Only used for backward compatibility
- Should not block releases

## Success Criteria
- ✅ All tests pass in GitLab CI
- ✅ Whirlpool still works in non-parallel code
- ✅ Clear documentation of limitations
