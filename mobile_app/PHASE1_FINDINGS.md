# 🎯 Phase 1 Findings: CLI vs Mobile Key Derivation Analysis

## **Critical Discovery: Data Type Mismatch Found!**

### **The Problem**
CLI and mobile have fundamentally different data structures for hash configuration:

**CLI Test Vector Format:**
```json
"hash_config": {
    "sha512": 0,
    "sha256": 1000,
    "sha3_256": 0
}
```

**Mobile Expected Format:**
```json
"hash_config": {
    "sha512": 0,
    "sha256": 1000, 
    "sha3_256": 0
}
```

But CLI is actually sending:
```json
"hash_config": {
    "sha512": 0,
    "sha256": 1000,
    "sha3_256": 0,
    "type": "id"  // ← This extra field!
}
```

### **Error Details**
```python
TypeError: '>' not supported between instances of 'str' and 'int'
```

This happens in mobile_crypto_core.py line 122:
```python
has_hash_rounds = any(rounds > 0 for rounds in hash_config.values())
#                      ^^^^^^^^^^
# Tries to compare "id" > 0, which fails
```

---

## **Step-by-Step Analysis Results**

### **CLI Hash Processing (WORKING)**
```
Input: password="1234", salt="test_salt_16byte"
✅ CLI multi_hash_password():
   - No rounds: returns bytearray(b'1234test_salt_16byte') [20 bytes]
   - 1000 SHA256: returns bytearray(b'\xce\x05\xb7\x84@\xf4g\x9c...') [20 bytes]  
   - Multi-hash: returns bytearray(b"\x84s\xa0\x0c\x9c\xcf\x1ex...") [20 bytes]
```

### **Mobile Hash Processing (BROKEN)**
```
Input: password="1234", salt="test_salt_16byte" 
❌ Mobile multi_hash_password():
   - Crashes on: hash_config.values() contains "id" string
   - Expected: Only integer values for rounds
   - Actual: Mixed int/string values from CLI
```

---

## **Root Cause Analysis**

### **Issue 1: Hash Config Data Contamination**
The CLI test vectors contain extra fields that break mobile parsing:
```python
# From CLI vector:
'hash_config': {
    'sha512': 0, 'sha256': 1000, 'sha3_256': 0, 'sha3_512': 0,
    'blake2b': 0, 'shake256': 0, 'whirlpool': 0,
    'type': 'id'  # ← This shouldn't be here!
}
```

### **Issue 2: Mobile Hash Logic Differences**  
Even without the data issue, mobile vs CLI hash processing differs:

**CLI (Reference):**
- No hash rounds → `password + salt` (20 bytes)
- Hash rounds → processed hash result (20 bytes)

**Mobile (Current):**
- No hash rounds → `password` only (4 bytes) ✅ **FIXED in earlier commit**
- Hash rounds → processed hash result

But first test shows mobile gets `b'1234'` (4 bytes) vs CLI `b'1234test_salt_16byte'` (20 bytes)!

---

## **The Real Bidirectional Issue**

This analysis reveals why bidirectional compatibility failed:

1. **Hash Processing Mismatch**: CLI appends salt, mobile doesn't (for no-rounds case)
2. **Data Format Issues**: CLI metadata contains unexpected fields
3. **Type Safety**: Mobile assumes clean integer-only hash configs

---

## **Phase 2 Fix Strategy**

### **Immediate Fixes Needed:**

#### **Fix 1: Clean Hash Config Data**
```python
def clean_hash_config(hash_config):
    """Remove non-integer fields from hash config"""
    clean_config = {}
    for algo, value in hash_config.items():
        if isinstance(value, int):
            clean_config[algo] = value
        # Skip strings like 'type': 'id'
    return clean_config
```

#### **Fix 2: Match CLI Hash Logic Exactly**
```python 
def multi_hash_password(self, password, salt, hash_config):
    # ALWAYS append salt when processing CLI formats
    # This matches CLI behavior exactly
    hashed = password + salt  # CLI behavior
    
    # Apply hash rounds if any
    for algorithm, rounds in hash_config.items():
        if isinstance(rounds, int) and rounds > 0:
            # Apply hash processing
```

#### **Fix 3: Robust CLI Data Parsing**
```python
def parse_cli_hash_config(cli_config):
    """Parse CLI hash config, filtering out non-hash fields"""
    parsed = {}
    VALID_HASH_ALGORITHMS = ["sha512", "sha256", "sha3_256", "sha3_512", 
                            "blake2b", "blake3", "shake256", "whirlpool"]
    
    for key, value in cli_config.items():
        if key in VALID_HASH_ALGORITHMS and isinstance(value, int):
            parsed[key] = value
            
    return parsed
```

---

## **Next Actions**

### **Phase 2A: Data Compatibility (HIGH PRIORITY)**
- [ ] Fix hash_config parsing to handle CLI data contamination
- [ ] Add type safety checks for all CLI data parsing  
- [ ] Test mobile with cleaned CLI test vectors

### **Phase 2B: Logic Compatibility (CRITICAL)**
- [ ] Fix mobile hash processing to match CLI exactly
- [ ] Ensure mobile always returns same hash result as CLI
- [ ] Test hash processing with multiple algorithms

### **Phase 2C: Integration Testing**
- [ ] Re-run Phase 1 tests with fixes
- [ ] Verify 100% CLI-Mobile hash compatibility
- [ ] Move to KDF compatibility testing

---

## **Success Metrics**
- [ ] Mobile can parse all CLI test vectors without crashing
- [ ] Mobile hash results match CLI hash results exactly
- [ ] All 3 test cases (no-rounds, single-hash, multi-hash) pass
- [ ] Ready to test KDF compatibility (Phase 1 complete)

---

**Status**: Phase 1 SUCCESS - Root cause identified  
**Next**: Implement Phase 2 fixes  
**Critical Issue**: Data contamination + hash logic mismatch  
**Confidence**: HIGH - Clear path to fix identified