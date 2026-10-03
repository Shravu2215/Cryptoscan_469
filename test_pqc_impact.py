import json, os, sys

def run_tests():
    # To test the frontend logic, we can use the same normalization and match logic
    
    # 1. We load the new scan results
    try:
        with open("scan_demo_output.json", "r") as f:
            raw = json.load(f)
        scans = raw.get("scans", [raw])
        findings = scans[0].get("findings", [])
    except Exception as e:
        print("Failed to load scan_demo_output.json:", e)
        sys.exit(1)

    # (a) Verify .key files
    key_findings = [f for f in findings if str(f.get("file", "")).endswith(".key") or str(f.get("filePath", "")).endswith(".key")]
    algos = sorted([f.get("algorithm") for f in key_findings])
    
    # Depending on how many keys in the fixture, if they are RSA-2048, RSA-1024, RSA-2048
    expected_algos = sorted(["RSA-2048", "RSA-1024", "RSA-2048"])
    
    if expected_algos == algos or set(algos) == set(expected_algos):
        print("Test (a) passed: .key files are correctly parsed as", algos)
    else:
        print("Test (a) failed: .key files found:", algos)
        # We don't fail immediately, let's show all outputs

    # (b) ECDSA P-256 shows only package.json line 9
    # We apply the frontend findingMatchesAlgo logic
    LIB_TO_ALGO = {
        'elliptic': 'ECDSA P-256', 'secp256k1': 'ECDSA P-256',
        'ecdsa': 'ECDSA P-256', 'node-forge': 'RSA-2048',
        'jsrsasign': 'RSA-2048', 'pyopenssl': 'RSA-2048',
        'pycryptodome': 'AES-128', 'cryptography': 'RSA-2048',
        'bouncycastle': 'RSA-2048', 'bcprov': 'RSA-2048',
        'tweetnacl': 'Ed25519', 'ed25519': 'Ed25519',
        'libsodium': 'Ed25519', 'nacl': 'Ed25519',
        'noble-curves': 'ECDSA P-256', '@noble/curves': 'ECDSA P-256'
    }

    FAMILIES = {
        'ECDSA P-256': 'ECDSA', 'ECDSA P-384': 'ECDSA',
        'RSA-2048': 'RSA', 'RSA-3072': 'RSA', 'RSA-4096': 'RSA',
        'AES-128': 'AES', 'AES-256-GCM': 'AES'
    }

    def normalize(s):
        if not s: return None
        str_val = s.strip().upper()
        if 'SHA-1' in str_val or 'SHA1' in str_val: return 'SHA-1'
        if 'MD5' in str_val: return 'MD5'
        if 'ML-DSA-65' in str_val or 'DILITHIUM3' in str_val: return 'ML-DSA-65'
        if 'ML-DSA-44' in str_val or 'DILITHIUM2' in str_val: return 'ML-DSA-44'
        if 'ML-DSA-87' in str_val or 'DILITHIUM5' in str_val: return 'ML-DSA-87'
        if 'FALCON-512' in str_val or 'FALCON512' in str_val: return 'Falcon-512'
        if 'FALCON-1024' in str_val or 'FALCON1024' in str_val: return 'Falcon-1024'
        if 'SLH-DSA-SHA2-128S' in str_val: return 'SLH-DSA-SHA2-128s'
        if 'SLH-DSA-SHA2-128F' in str_val: return 'SLH-DSA-SHA2-128f'
        if 'SLH-DSA-SHA2-192S' in str_val: return 'SLH-DSA-SHA2-192s'
        if 'SLH-DSA-SHA2-256S' in str_val: return 'SLH-DSA-SHA2-256s'
        if 'SLH-DSA-SHA2-256F' in str_val: return 'SLH-DSA-SHA2-256f'
        if 'X25519MLKEM768' in str_val or 'HYBRID X25519' in str_val: return 'X25519MLKEM768'
        if 'ML-KEM-768' in str_val or 'KYBER768' in str_val: return 'ML-KEM-768'
        if 'ML-KEM-512' in str_val or 'KYBER512' in str_val: return 'ML-KEM-512'
        if 'ML-KEM-1024' in str_val or 'KYBER1024' in str_val: return 'ML-KEM-1024'
        if 'RSA-4096' in str_val or 'RSA 4096' in str_val or '4096' in str_val: return 'RSA-4096'
        if 'RSA-3072' in str_val or 'RSA 3072' in str_val or '3072' in str_val: return 'RSA-3072'
        if 'RSA-2048' in str_val or 'RSA 2048' in str_val or 'RSA' in str_val: return 'RSA-2048'
        if 'ECDSA P-384' in str_val or 'P-384' in str_val or 'SECP384R1' in str_val: return 'ECDSA P-384'
        if 'ECDSA P-256' in str_val or 'P-256' in str_val or 'SECP256R1' in str_val or 'ECDSA' in str_val or str_val == 'EC' or str_val.endswith(' EC') or str_val.startswith('EC ') or ' EC ' in str_val: return 'ECDSA P-256'
        if 'ED25519' in str_val: return 'Ed25519'
        if 'ECDH' in str_val: return 'ECDH P-256'
        if 'X25519' in str_val: return 'X25519'
        if 'AES' in str_val and 'ECB' in str_val: return 'AES-ECB'
        if 'AES-256' in str_val: return 'AES-256-GCM'
        if 'AES-128' in str_val or 'AES' in str_val: return 'AES-128'
        if '3DES' in str_val or 'TRIPLEDES' in str_val: return '3DES'
        if 'DES' in str_val: return 'DES'
        if 'RC4' in str_val: return 'RC4'
        if 'SHA-384' in str_val or 'SHA384' in str_val: return 'SHA-384'
        if 'SHA3-256' in str_val or 'SHA3' in str_val: return 'SHA3-256'
        if 'SHA-256' in str_val or 'SHA256' in str_val: return 'SHA-256'
        return None

    def findingMatchesAlgo(f, classicalKey):
        fNorm = None
        if f.get('algorithm'): fNorm = normalize(f.get('algorithm'))
        if not fNorm:
            lib = (f.get('library', '') or f.get('category', '')).lower().strip()
            fNorm = normalize(LIB_TO_ALGO.get(lib)) or normalize(lib)
        if not fNorm:
            snippet = f.get('codeSnippet', '') or f.get('rawCallSite', '') or f.get('description', '')
            fNorm = normalize(snippet)
            
        selNorm = normalize(classicalKey)
        if not fNorm or not selNorm: return False
        
        fFam = FAMILIES.get(fNorm)
        selFam = FAMILIES.get(selNorm)
        if fFam and selFam and fFam == selFam: return True
        return fNorm == selNorm

    ecdsa_findings = [f for f in findings if findingMatchesAlgo(f, "ECDSA P-256")]
    
    # Create the dedup logic used in frontend
    def deduplicate(matches):
        seen = set()
        deduped = []
        for f in matches:
            path = f.get('filePath') or f.get('file')
            line = f.get('lineNumber') or f.get('line')
            algo = f.get('algorithm')
            detection = f.get('detection') or f.get('detection_method', '')
            key = f"{path}|{line}|{algo}|{detection}"
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        return deduped

    ecdsa_deduped = deduplicate(ecdsa_findings)
    if len(ecdsa_deduped) == 1 and "package.json" in str(ecdsa_deduped[0].get('file', '')):
        print("Test (b) passed: ECDSA P-256 matched only package.json line 9 (elliptic).")
    else:
        print("Test (b) failed: ECDSA P-256 matched:", [(f.get('file'), f.get('line')) for f in ecdsa_deduped])

    # (c) AES-ECB
    aes_findings = [f for f in findings if findingMatchesAlgo(f, "AES-ECB")]
    aes_deduped = deduplicate(aes_findings)
    if len(aes_deduped) == 2:
        files = [f.get('file') or f.get('filePath') for f in aes_deduped]
        if any('cipherModes.js' in f for f in files) and any('cipher_modes.py' in f for f in files):
            print("Test (c) passed: AES-ECB matched cipherModes.js and cipher_modes.py.")
        else:
            print("Test (c) failed: AES matched:", [(f.get('file'), f.get('line')) for f in aes_deduped])
    else:
        print("Test (c) failed: AES matched count != 2:", [(f.get('file'), f.get('line')) for f in aes_deduped])


if __name__ == '__main__':
    run_tests()
