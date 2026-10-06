/**
 * assuranceKnowledge.js - Single Source of Truth for PQC Assurance Reference Data
 *
 * Provides judge-grade technical assurance knowledge keyed by algorithm family and replacement.
 * Standards cited: FIPS 180-4 (SHA-2), FIPS 202 (SHA-3), FIPS 203 (ML-KEM),
 * FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), NIST SP 800-38D (AES-GCM),
 * RFC 8439 (ChaCha20-Poly1305), NIST IR 8547 (Transition Timelines), NIST SP 800-131A.
 *
 * UMD module for browser and Node.js test environments.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.AssuranceKnowledge = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // Master Technical Assurance Knowledge Base
  var KNOWLEDGE_BASE = {
    'ML-KEM': {
      id: 'ML-KEM',
      title: 'Lattice-Based Key Encapsulation (ML-KEM)',
      standards: ['FIPS 203', 'NIST IR 8547'],
      category: 'Asymmetric Key Exchange / KEM',
      classicalSecurity: {
        status: 'Legacy / Weakened for <=2048-bit; Strong classically for 3072-bit',
        reason: 'RSA-1024 disallowed (NIST SP 800-131A). RSA-2048 provides 112 bits classical security with factoring difficulty based on General Number Field Sieve (GNFS).'
      },
      quantumThreat: {
        attack: "Shor's Algorithm (Polynomial Time Factoring / Discrete Log)",
        detail: "Shor's algorithm solves integer factorization in O((log N)^3) operations on a Cryptographically Relevant Quantum Computer (CRQC), reducing RSA and classical Diffie-Hellman security to 0 bits. Immediate 'Harvest Now, Decrypt Later' (HNDL) exposure for stored ciphertexts."
      },
      securityBits: {
        oldClassical: '112 bits (RSA-2048) / 128 bits (RSA-3072 / ECDH P-256)',
        oldQuantum: '0 bits (Completely broken by Shor\'s algorithm)',
        newClassical: '128 bits (ML-KEM-768 Category 3) / 256 bits (ML-KEM-1024 Category 5)',
        newQuantum: '128 bits (ML-KEM-768 Category 3) / 256 bits (ML-KEM-1024 Category 5)'
      },
      statusBadges: {
        oldBadge: 'Quantum-Broken',
        oldBadgeClass: 'badge-crit',
        newBadge: 'Quantum-Safe',
        newBadgeClass: 'badge-safe'
      },
      whyQuantumSafe: [
        'Security rests on the computational hardness of the Module Learning With Errors (M-LWE) problem over algebraic lattices, with no known polynomial-time quantum algorithm.',
        'Hybrid construction (e.g. X25519 + ML-KEM-768) dual-encapsulates shared secrets via HKDF, preserving full classical security even if unanticipated lattice cryptanalysis emerges.',
        'Neutralizes passive "Harvest Now, Decrypt Later" (HNDL) interception by ensuring recorded sessions cannot be decrypted by future quantum adversaries.'
      ],
      futureOutlook: {
        crqcImpact: 'CRQC completely recovers classical private keys and decrypts past traffic; ML-KEM remains secure against both classical GNFS and quantum Shor/Grover solvers.',
        replacementStatus: 'FIPS 203 finalized by NIST in August 2024 as the primary standard for post-quantum key encapsulation.',
        timeline: 'NIST IR 8547: Classical RSA/ECDH key establishment deprecated by 2030, completely disallowed after 2035. NSA CNSA 2.0 requires full PQC key exchange by 2030.'
      },
      migrationTradeoffs: {
        keySizeChange: 'Public key: RSA-2048 256 bytes vs ML-KEM-768 1184 bytes (~4.6x expansion). Ciphertext: 256 bytes vs 1088 bytes (~4.25x expansion).',
        latencyImpact: 'Key generation and encapsulation are exceptionally fast (<0.1ms CPU), but larger packet sizes may cause TCP segmentation or TLS handshake fragmentation.',
        migrationEffort: 'Medium (Requires TLS 1.3 hybrid KEM suite support or library upgrade to OpenSSL 3.2+ / BoringSSL).',
        sizeNotes: 'ML-KEM-768 public key: 1184 bytes; ciphertext: 1088 bytes; shared secret: 32 bytes.'
      },
      codeSnippet: {
        language: 'python',
        beforeTitle: 'Vulnerable: Classical RSA Key Encapsulation',
        beforeCode: '# Classical RSA key exchange (Quantum-Vulnerable to Shor\'s algorithm)\nfrom cryptography.hazmat.primitives.asymmetric import padding, rsa\nfrom cryptography.hazmat.primitives import hashes\n\nciphertext = public_key.encrypt(\n    session_key,\n    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)\n)',
        afterTitle: 'Assurance: FIPS 203 ML-KEM-768 Hybrid Encapsulation',
        afterCode: '# Quantum-Safe Hybrid X25519 + ML-KEM-768 (FIPS 203)\nimport oqs\n\nwith oqs.KeyEncapsulation("ML-KEM-768") as client_kem:\n    # Encapsulate shared secret against peer\'s public key\n    ciphertext, shared_secret = client_kem.encap_secret(server_public_key)\n    # Combine with classical X25519 secret via dual-PRF HKDF'
      }
    },

    'ML-DSA': {
      id: 'ML-DSA',
      title: 'Lattice-Based Digital Signature Algorithm (ML-DSA)',
      standards: ['FIPS 204', 'FIPS 205 (SLH-DSA alternative)', 'NIST IR 8547'],
      category: 'Asymmetric Signatures & Identity',
      classicalSecurity: {
        status: 'Legacy / Weakened for DSA-1024; Strong classically for ECDSA P-256 / Ed25519',
        reason: 'ECDSA P-256 provides 128 bits classical security against Pollard rho algorithm. DSA-1024 is disallowed by NIST SP 800-131A.'
      },
      quantumThreat: {
        attack: "Shor's Algorithm (Discrete Logarithm Over Elliptic Curves & Finite Fields)",
        detail: "Shor's algorithm extracts the private scalar key d from public key Q = d*G in polynomial time O(n^3). A quantum computer can forge digital signatures, manipulate code signing, and impersonate CA roots."
      },
      securityBits: {
        oldClassical: '128 bits (ECDSA P-256 / Ed25519) / 112 bits (RSA-2048)',
        oldQuantum: '0 bits (Shor\'s algorithm computes discrete log/factoring)',
        newClassical: '128 bits (ML-DSA-65 Category 3) / 192 bits (ML-DSA-87 Category 5)',
        newQuantum: '128 bits (ML-DSA-65 Category 3) / 192 bits (ML-DSA-87 Category 5)'
      },
      statusBadges: {
        oldBadge: 'Quantum-Broken',
        oldBadgeClass: 'badge-crit',
        newBadge: 'Quantum-Safe',
        newBadgeClass: 'badge-safe'
      },
      whyQuantumSafe: [
        'ML-DSA (Dilithium) security is grounded in the hardness of Module Learning With Errors (M-LWE) and Module Short Integer Solution (M-SIS) lattice problems.',
        'SLH-DSA (FIPS 205 SPHINCS+) provides a stateless hash-based fallback with no lattice assumptions, relying purely on the security of underlying hash functions.',
        'Eliminates identity impersonation, forgery of X.509 PKI certificates, and rogue software distribution in the presence of a CRQC.'
      ],
      futureOutlook: {
        crqcImpact: 'CRQC enables real-time forging of ECDSA/RSA signatures and MITM TLS identity spoofing; ML-DSA/SLH-DSA maintains cryptographic unforgeability.',
        replacementStatus: 'FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA) finalized by NIST in August 2024.',
        timeline: 'NIST IR 8547: RSA and ECDSA signature algorithms deprecated for generation by 2030, disallowed after 2035.'
      },
      migrationTradeoffs: {
        keySizeChange: 'Public key: ECDSA P-256 64 bytes vs ML-DSA-65 1952 bytes (~30x). Signature: ECDSA P-256 64 bytes vs ML-DSA-65 3309 bytes (~51x expansion).',
        latencyImpact: 'Signing and verification are mathematically efficient, but certificate chain bloat increases network latency for bandwidth-constrained devices.',
        migrationEffort: 'High (Requires X.509 certificate hierarchy migration, CRL/OCSP updates, and client crypto library compatibility).',
        sizeNotes: 'ML-DSA-65: public key 1952 bytes; signature 3309 bytes. SLH-DSA-SHA2-128s: public key 32 bytes; signature 7856 bytes.'
      },
      codeSnippet: {
        language: 'python',
        beforeTitle: 'Vulnerable: Classical ECDSA P-256 Signature',
        beforeCode: '# Classical ECDSA signature (Vulnerable to Shor\'s algorithm)\nfrom cryptography.hazmat.primitives.asymmetric import ec\nfrom cryptography.hazmat.primitives import hashes\n\nsignature = private_key.sign(\n    payload,\n    ec.ECDSA(hashes.SHA256())\n)',
        afterTitle: 'Assurance: FIPS 204 ML-DSA-65 Post-Quantum Signature',
        afterCode: '# Quantum-Safe ML-DSA-65 Signature (FIPS 204)\nimport oqs\n\nwith oqs.Signature("ML-DSA-65") as signer:\n    signature = signer.sign(payload)\n    # Verifiable with signer.verify(payload, signature, public_key)'
      }
    },

    'SHA-256': {
      id: 'SHA-256',
      title: 'Cryptographic Hash Transition (SHA-2 / SHA-3)',
      standards: ['FIPS 180-4 (SHA-2)', 'FIPS 202 (SHA-3)', 'NIST SP 800-131A'],
      category: 'Cryptographic Hash Function',
      classicalSecurity: {
        status: 'Broken for MD5 / SHA-1; Strong for SHA-256 / SHA-3-256',
        reason: 'MD5 broken by practical chosen-prefix collisions (Wang et al., Stevens). SHA-1 collisions demonstrated (SHAttered, Shaken). Both disallowed by NIST SP 800-131A.'
      },
      quantumThreat: {
        attack: "Grover's Algorithm (Quantum Search for Preimages / BHT for Collisions)",
        detail: "Grover's algorithm reduces preimage search complexity from 2^n to 2^(n/2). For MD5 (128-bit), Grover yields only ~64 bits of security; for SHA-256, Grover leaves 128 bits of security, which is well above the quantum-safe security threshold."
      },
      securityBits: {
        oldClassical: '<18 bits collision (MD5) / ~60 bits collision (SHA-1)',
        oldQuantum: '0 bits (Broken classically; trivial under quantum search)',
        newClassical: '128 bits collision / 256 bits preimage (SHA-256 / SHA-3-256)',
        newQuantum: '128 bits preimage resistance under Grover\'s algorithm'
      },
      statusBadges: {
        oldBadge: 'Legacy-Broken',
        oldBadgeClass: 'badge-crit',
        newBadge: 'Quantum-Safe',
        newBadgeClass: 'badge-safe'
      },
      whyQuantumSafe: [
        'SHA-256 (FIPS 180-4) output length of 256 bits guarantees 128 bits of preimage resistance against Grover\'s quantum search algorithm.',
        'SHA-3 (FIPS 202) utilizes the Keccak permutation sponge construction, offering algorithmic diversity and immunity against length extension attacks.',
        'BLAKE3 provides high-speed tree hashing with 128-bit collision resistance and 256-bit preimage resistance.'
      ],
      futureOutlook: {
        crqcImpact: 'MD5/SHA-1 are compromised today on classical laptops. Under a CRQC, SHA-256/384/512 and SHA-3 remain completely sound.',
        replacementStatus: 'FIPS 180-4 (SHA-256) and FIPS 202 (SHA-3) are active, approved NIST standards.',
        timeline: 'NIST formally retired SHA-1 in December 2022; federal transition deadline is December 31, 2030.'
      },
      migrationTradeoffs: {
        keySizeChange: 'Digest size increases from 16 bytes (MD5) or 20 bytes (SHA-1) to 32 bytes (SHA-256/SHA-3-256).',
        latencyImpact: 'Hardware SHA extensions (Intel SHA-NI / ARMv8 Crypto) provide gigabytes/sec throughput with negligible CPU overhead.',
        migrationEffort: 'Low (Drop-in hash library replacement in application code).',
        sizeNotes: 'SHA-256: 32 bytes output; SHA-3-256: 32 bytes output; SHA-512: 64 bytes output.'
      },
      codeSnippet: {
        language: 'python',
        beforeTitle: 'Vulnerable: Broken MD5 / SHA-1 Hash',
        beforeCode: '# Deprecated collision-broken hash\nimport hashlib\n\ndigest = hashlib.md5(payload).hexdigest()  # Insecure collision risk',
        afterTitle: 'Assurance: FIPS 180-4 SHA-256 / FIPS 202 SHA-3',
        afterCode: '# Standard Quantum-Safe Hash (FIPS 180-4 / FIPS 202)\nimport hashlib\n\ndigest_sha256 = hashlib.sha256(payload).hexdigest()    # FIPS 180-4\ndigest_sha3   = hashlib.sha3_256(payload).hexdigest()  # FIPS 202 (Keccak)'
      }
    },

    'AES-256-GCM': {
      id: 'AES-256-GCM',
      title: 'Authenticated Symmetric Encryption (AES-256-GCM)',
      standards: ['NIST SP 800-38D (AES-GCM)', 'FIPS 197 (AES)', 'RFC 8439 (ChaCha20-Poly1305)', 'NIST SP 800-131A'],
      category: 'Symmetric AEAD Cipher',
      classicalSecurity: {
        status: 'Broken for DES/3DES/RC4/ECB; Weakened for AES-128; Strong for AES-256-GCM',
        reason: 'DES 56-bit key broken by brute force. 3DES vulnerable to Sweet32 64-bit block collisions. ECB leaks plaintext patterns. Unauthenticated CBC vulnerable to padding oracles.'
      },
      quantumThreat: {
        attack: "Grover's Algorithm (Quadratic Key Search O(sqrt(N)))",
        detail: "Grover's quantum search halves effective symmetric key length. AES-128 is reduced to ~64 bits of effective security (borderline vulnerable to quantum supercomputing). AES-256 is reduced to 128 bits, maintaining complete quantum resistance."
      },
      securityBits: {
        oldClassical: '0 bits (ECB) / 56 bits (DES) / 112 bits (3DES) / 128 bits (AES-128)',
        oldQuantum: '0 bits (ECB/DES) / 64 bits (AES-128 under Grover search)',
        newClassical: '256 bits classical key space with IND-CCA2 authentication',
        newQuantum: '128 bits effective quantum security under Grover search (Quantum-Safe)'
      },
      statusBadges: {
        oldBadge: 'Harmful',
        oldBadgeClass: 'badge-crit',
        newBadge: 'Quantum-Safe',
        newBadgeClass: 'badge-safe'
      },
      whyQuantumSafe: [
        'AES-256 256-bit key length guarantees that Grover\'s quadratic quantum speedup (sqrt(2^256) = 2^128) leaves 128 bits of effective security, satisfying NSA CNSA 2.0 requirements.',
        'Galois/Counter Mode (GCM, NIST SP 800-38D) provides Authenticated Encryption with Associated Data (AEAD), preventing ciphertext bit-flipping and padding oracle attacks.',
        'ChaCha20-Poly1305 (RFC 8439) provides an equally quantum-resilient 256-bit alternative immune to cache-timing attacks on non-AES-NI hardware.'
      ],
      futureOutlook: {
        crqcImpact: 'DES/3DES/ECB are trivial to attack. AES-128 becomes weakened. AES-256-GCM remains quantum-safe against known quantum cryptanalytic methods.',
        replacementStatus: 'NIST SP 800-38D is the worldwide gold standard for authenticated symmetric encryption.',
        timeline: 'NIST SP 800-131A disallowed 3DES for encryption after 2023. NSA CNSA 2.0 specifies AES-256 as mandatory for national security systems.'
      },
      migrationTradeoffs: {
        keySizeChange: 'Key size: 32 bytes (256 bits). Nonce: 12 bytes (96 bits). Authentication tag: 16 bytes (128 bits).',
        latencyImpact: 'Near-zero latency overhead (<0.5 cycles/byte on AES-NI and ARMv8 Cryptography hardware).',
        migrationEffort: 'Low-to-Medium (Requires managing unique 96-bit nonces per key and appending 16-byte authentication tags).',
        sizeNotes: 'Ciphertext is plaintext length + 16-byte tag. Nonce (12 bytes) must never be repeated for the same key.'
      },
      codeSnippet: {
        language: 'python',
        beforeTitle: 'Vulnerable: Insecure ECB Mode / Legacy DES',
        beforeCode: '# Pattern-leaking ECB or broken DES\nfrom cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n\n# Insecure ECB mode leaks structural patterns\ncipher = Cipher(algorithms.AES(key), modes.ECB())',
        afterTitle: 'Assurance: NIST SP 800-38D AES-256-GCM Authenticated Encryption',
        afterCode: '# Standard Quantum-Safe AEAD (NIST SP 800-38D)\nimport os\nfrom cryptography.hazmat.primitives.ciphers.aead import AESGCM\n\nkey = AESGCM.generate_key(bit_length=256)  # 256-bit key (Grover-safe)\nnonce = os.urandom(12)                    # 96-bit random nonce\naead = AESGCM(key)\nciphertext = aead.encrypt(nonce, plaintext, associated_data=None)'
      }
    },

    'SECRETS-MANAGER': {
      id: 'SECRETS-MANAGER',
      title: 'Hardware Custody & Envelope Encryption (KMS / HSM)',
      standards: ['FIPS 140-3 (Cryptographic Modules)', 'NIST SP 800-57 (Key Management)'],
      category: 'Key Management & Custody',
      classicalSecurity: {
        status: 'Broken (Hardcoded / Plaintext)',
        reason: 'Hardcoded secrets and committed .env credentials are exposed to repository readers, CI logs, and decompiled binaries with 0 bits access protection.'
      },
      quantumThreat: {
        attack: "Direct Secret Compromise (Pre-Quantum Exposure)",
        detail: "Hardcoded cryptographic keys are compromised immediately without requiring any quantum computer. Furthermore, static hardcoded keys cannot be dynamically transitioned to PQC."
      },
      securityBits: {
        oldClassical: '0 bits (Plaintext disclosure in code/configuration)',
        oldQuantum: '0 bits (Direct compromise)',
        newClassical: 'FIPS 140-3 Level 3 Hardware Security Module isolation',
        newQuantum: 'Crypto-Agile Envelope Encryption with automated rotation'
      },
      statusBadges: {
        oldBadge: 'Harmful',
        oldBadgeClass: 'badge-crit',
        newBadge: 'Quantum-Resilient',
        newBadgeClass: 'badge-safe'
      },
      whyQuantumSafe: [
        'Migrates key custody into hardware security modules (HSMs) and managed KMS vaults (AWS KMS, Azure Key Vault, HashiCorp Vault).',
        'Enables cryptographic agility: when post-quantum algorithms are standardized across KMS providers, keys can be migrated centrally without code refactoring.',
        'Implements automated key rotation, strict IAM boundary controls, and comprehensive audit trails.'
      ],
      futureOutlook: {
        crqcImpact: 'Hardcoded keys remain compromised forever in git history. Centralized KMS keys allow rapid mass migration to quantum-safe algorithms.',
        replacementStatus: 'FIPS 140-3 is the active NIST benchmark for cryptographic module security.',
        timeline: 'NIST SP 800-57 recommends continuous credential rotation and elimination of all static embedded secrets.'
      },
      migrationTradeoffs: {
        keySizeChange: 'Replaces hardcoded string with secure remote key reference / ARN.',
        latencyImpact: 'Network roundtrip to KMS API (typically 5-15ms; mitigated via local envelope encryption caching).',
        migrationEffort: 'Medium (Requires configuring IAM roles and updating secret loading routines).',
        sizeNotes: 'Data keys are protected via envelope encryption using HSM-protected root master keys.'
      },
      codeSnippet: {
        language: 'python',
        beforeTitle: 'Vulnerable: Hardcoded Plaintext Secret',
        beforeCode: '# Hardcoded secret exposed in source control\nSECRET_KEY = "8f4b7a2c1e9d3f6058a7c4b1e9d2f605"  # Severe leak risk',
        afterTitle: 'Assurance: Managed KMS / Secrets Vault',
        afterCode: '# FIPS 140-3 Hardware Key Custody\nimport os, boto3\n\nclient = boto3.client("secretsmanager")\nsecret = client.get_secret_value(SecretId="prod/app/encryption-key")\nkey_bytes = secret["SecretBinary"]'
      }
    },

    'TLS-PQC': {
      id: 'TLS-PQC',
      title: 'Transport Layer Security (TLS 1.3 + Post-Quantum Hybrid)',
      standards: ['RFC 8446 (TLS 1.3)', 'FIPS 203', 'RFC 8996 (Deprecation of SSLv3, TLS 1.0, TLS 1.1)'],
      category: 'Transport Security',
      classicalSecurity: {
        status: 'Broken for SSLv3 / TLS 1.0 / TLS 1.1; Strong for TLS 1.3',
        reason: 'Legacy TLS versions vulnerable to POODLE, BEAST, DROWN, SWEET32, and lack forward secrecy. Formally deprecated by RFC 8996.'
      },
      quantumThreat: {
        attack: "Shor's Algorithm (HNDL Session Decryption)",
        detail: "Adversaries record encrypted TLS sessions today. Once a CRQC arrives, Shor's algorithm solves the ECDHE/DHE key exchange to decrypt all historical network payloads."
      },
      securityBits: {
        oldClassical: '0 bits (SSLv3/TLS 1.0/1.1) / 128 bits (TLS 1.2/1.3 ECDHE)',
        oldQuantum: '0 bits (HNDL decryption via Shor\'s algorithm)',
        newClassical: '256 bits with AEAD authenticated cipher suite',
        newQuantum: '128 bits post-quantum session forward secrecy via X25519MLKEM768'
      },
      statusBadges: {
        oldBadge: 'Quantum-Broken',
        oldBadgeClass: 'badge-crit',
        newBadge: 'Quantum-Safe',
        newBadgeClass: 'badge-safe'
      },
      whyQuantumSafe: [
        'Enforces TLS 1.3 with hybrid key exchange (X25519MLKEM768, standardized in Chrome/Cloudflare/OpenSSL 3.2+).',
        'Guarantees forward secrecy against future quantum computers: past session keys cannot be derived even with a CRQC.',
        'Disables legacy CBC ciphers, weak Diffie-Hellman groups, and broken hash algorithms.'
      ],
      futureOutlook: {
        crqcImpact: 'Unprotected TLS traffic is retroactively decrypted via HNDL. Hybrid TLS 1.3 maintains absolute confidentiality.',
        replacementStatus: 'TLS 1.3 (RFC 8446) is the active IETF standard; post-quantum hybrid groups are already broadly deployed.',
        timeline: 'NIST IR 8547: Transition all federal endpoints to PQC-enabled TLS by 2030.'
      },
      migrationTradeoffs: {
        keySizeChange: 'Client Hello Key Share increases from 32 bytes (X25519) to ~1216 bytes (X25519MLKEM768).',
        latencyImpact: 'Fits within standard 1500-byte TCP MTU in initial congestion window (IW10); negligible latency delta.',
        migrationEffort: 'Low (Web server / reverse proxy configuration update in Nginx / Cloudflare / Envoy).',
        sizeNotes: 'X25519MLKEM768 combined key share: 1216 bytes.'
      },
      codeSnippet: {
        language: 'javascript',
        beforeTitle: 'Vulnerable: Legacy TLS Configuration',
        beforeCode: '// Insecure deprecated TLS protocols\nssl_protocols TLSv1 TLSv1.1 TLSv1.2;\nssl_ciphers RC4:3DES:HIGH:!aNULL:!MD5;',
        afterTitle: 'Assurance: TLS 1.3 with Hybrid Post-Quantum Key Exchange',
        afterCode: '// Modern TLS 1.3 + Post-Quantum Group\nssl_protocols TLSv1.3;\nssl_ecdh_curve X25519MLKEM768:X25519:secp384r1;\nssl_prefer_server_ciphers off;'
      }
    },

    'SAFE-MODERN': {
      id: 'SAFE-MODERN',
      title: 'Current Cryptographic Baseline (Compliant / Agile)',
      standards: ['NIST SP 800-131A', 'FIPS 180-4', 'FIPS 197'],
      category: 'Approved Modern Cryptography',
      classicalSecurity: {
        status: 'Strong Classically',
        reason: 'Meets or exceeds NIST SP 800-131A minimum 128-bit classical security requirements.'
      },
      quantumThreat: {
        attack: 'Grover\'s Algorithm (Symmetric/Hash) or Routine Lifecycle',
        detail: 'For symmetric algorithms (AES-256) and hashes (SHA-256), Grover\'s algorithm reduces effective security by at most half, leaving >=128 bits of security (Quantum-Safe).'
      },
      securityBits: {
        oldClassical: '>=128 bits classical security',
        oldQuantum: '>=128 bits quantum resistance',
        newClassical: '>=128 bits',
        newQuantum: '>=128 bits'
      },
      statusBadges: {
        oldBadge: 'Quantum-Safe',
        oldBadgeClass: 'badge-safe',
        newBadge: 'Quantum-Safe',
        newBadgeClass: 'badge-safe'
      },
      whyQuantumSafe: [
        'Utilizes modern 256-bit symmetric primitives and secure hashing structures compliant with current NIST guidelines.',
        'Sufficient key length retains >=128 bits of effective security against Grover search.',
        'No immediate migration required; maintain crypto-agility and monitor NIST standards progression.'
      ],
      futureOutlook: {
        crqcImpact: 'Remains robust against quantum cryptanalysis under currently known attack paradigms.',
        replacementStatus: 'Active compliant cryptographic primitive.',
        timeline: 'NIST IR 8547: Monitor lifecycle and adhere to planned organizational migration milestones.'
      },
      migrationTradeoffs: {
        keySizeChange: 'No change needed.',
        latencyImpact: 'Optimal baseline performance.',
        migrationEffort: 'None (Verify configuration and crypto-agility).',
        sizeNotes: 'Standard compliant sizes.'
      },
      codeSnippet: {
        language: 'python',
        beforeTitle: 'Current Implementation: Secure Baseline',
        beforeCode: '# Currently compliant with modern standards\nimport hashlib\nhashlib.sha256(data).hexdigest()',
        afterTitle: 'Assurance: Verified Quantum-Resilient Baseline',
        afterCode: '# Verified safe against Shor\'s algorithm;\n# Retains >=128-bit quantum security against Grover\'s algorithm.'
      },
      isAlreadySafe: true
    },

    'GENERIC-FALLBACK': {
      id: 'GENERIC-FALLBACK',
      title: 'Cryptographic Component Under Assurance Assessment',
      standards: ['NIST IR 8547 (PQC Migration)', 'NIST SP 800-131A', 'FIPS 203/204/205'],
      category: 'Cryptographic Primitive',
      classicalSecurity: {
        status: 'Audit Required',
        reason: 'Assess algorithm key length and cipher mode against NIST SP 800-131A transition guidelines.'
      },
      quantumThreat: {
        attack: "Shor's Algorithm (if Asymmetric) / Grover's Algorithm (if Symmetric/Hash)",
        detail: "Asymmetric public-key components are completely vulnerable to Shor's polynomial-time factoring/discrete log algorithm. Symmetric keys <=128 bits are halved by Grover's search."
      },
      securityBits: {
        oldClassical: 'Variable (Verify key size and mode)',
        oldQuantum: 'Vulnerable if asymmetric or key <= 128 bits',
        newClassical: '>= 128 bits NIST PQC Standard',
        newQuantum: '>= 128 bits NIST PQC Standard'
      },
      statusBadges: {
        oldBadge: 'Quantum-Weakened',
        oldBadgeClass: 'badge-high',
        newBadge: 'Quantum-Safe',
        newBadgeClass: 'badge-safe'
      },
      whyQuantumSafe: [
        'Post-quantum algorithms standardized in FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA) eliminate quantum mathematical vulnerabilities.',
        'Lattice-based constructions (Module-LWE and Module-SIS) have no known sub-exponential quantum solving algorithms.',
        'Follows Mosca\'s inequality (X + Y <= Z) to ensure migration completes before a Cryptographically Relevant Quantum Computer (CRQC) becomes operational.'
      ],
      futureOutlook: {
        crqcImpact: 'Legacy asymmetric primitives will be fully broken; standardized PQC primitives remain cryptographically secure.',
        replacementStatus: 'FIPS 203, FIPS 204, and FIPS 205 were finalized in August 2024.',
        timeline: 'NIST IR 8547: Transition away from classical public-key cryptography begins immediately, deprecated 2030, disallowed 2035.'
      },
      migrationTradeoffs: {
        keySizeChange: 'Evaluate key and signature size expansion according to specific PQC algorithm family.',
        latencyImpact: 'Low computational impact; evaluate network packet fragmentation where applicable.',
        migrationEffort: 'Dependent on application integration architecture.',
        sizeNotes: 'Refer to FIPS 203/204/205 specifications for exact parameter byte sizes.'
      },
      codeSnippet: {
        language: 'python',
        beforeTitle: 'Legacy / Unassessed Primitive',
        beforeCode: '# Audit algorithm usage and verify cipher agility',
        afterTitle: 'Assurance: Standardized NIST PQC Migration Target',
        afterCode: '# Adopt NIST Post-Quantum Standard (FIPS 203 ML-KEM or FIPS 204 ML-DSA)'
      }
    }
  };

  /**
   * Resolves any algorithm and recommended replacement to a judge-grade assurance entry.
   * Guaranteed to NEVER return null or throw. Always returns a fully-populated entry.
   *
   * @param {string} algo - The algorithm name from scan/migration-plan
   * @param {string} replacement - The recommended replacement string from migration-plan
   * @returns {Object} Complete assurance entry
   */
  function resolve(algo, replacement) {
    var rawAlgo = (algo || '').trim();
    var rawRepl = (replacement || '').trim();
    var a = rawAlgo.toUpperCase();
    var r = rawRepl.toUpperCase();

    var baseKey = 'GENERIC-FALLBACK';

    // 1. Direct replacement matching (canonical PQC standard targets)
    if (r.indexOf('ML-KEM') !== -1 || r.indexOf('KYBER') !== -1) {
      baseKey = 'ML-KEM';
    } else if (r.indexOf('ML-DSA') !== -1 || r.indexOf('DILITHIUM') !== -1 || r.indexOf('SLH-DSA') !== -1 || r.indexOf('SPHINCS') !== -1 || r.indexOf('FALCON') !== -1) {
      baseKey = 'ML-DSA';
    } else if (r.indexOf('SHA-256') !== -1 || r.indexOf('SHA-3') !== -1 || r.indexOf('SHA3') !== -1 || r.indexOf('BLAKE') !== -1) {
      baseKey = 'SHA-256';
    } else if (r.indexOf('AES-256') !== -1 || r.indexOf('CHACHA20') !== -1) {
      baseKey = 'AES-256-GCM';
    } else if (r.indexOf('SECRETS') !== -1 || r.indexOf('KMS') !== -1 || r.indexOf('VAULT') !== -1) {
      baseKey = 'SECRETS-MANAGER';
    } else if (r.indexOf('TLS') !== -1) {
      baseKey = 'TLS-PQC';
    }

    // 2. Algorithm name matching (overrides or confirms)
    if (a.indexOf('HARDCODED') !== -1 || a.indexOf('SECRET') !== -1 || a.indexOf('PLAINTEXT') !== -1) {
      baseKey = 'SECRETS-MANAGER';
    } else if (a.indexOf('TLS') !== -1 || a.indexOf('SSL') !== -1 || a.indexOf('CIPHER SUITE') !== -1) {
      baseKey = 'TLS-PQC';
    } else if (a.indexOf('MD5') !== -1 || a.indexOf('MD4') !== -1 || a.indexOf('MD2') !== -1 || a.indexOf('SHA-1') !== -1 || a.indexOf('SHA1') !== -1) {
      baseKey = 'SHA-256';
    } else if (a.indexOf('DES') !== -1 || a.indexOf('RC4') !== -1 || a.indexOf('BLOWFISH') !== -1 || a.indexOf('ECB') !== -1) {
      baseKey = 'AES-256-GCM';
    } else if (a.indexOf('AES-128') !== -1 || a.indexOf('AES128') !== -1 || (a.indexOf('AES') !== -1 && a.indexOf('CBC') !== -1)) {
      baseKey = 'AES-256-GCM';
    } else if (a.indexOf('ECDSA') !== -1 || a.indexOf('ED25519') !== -1 || a.indexOf('DSA') !== -1) {
      baseKey = 'ML-DSA';
    } else if (a.indexOf('ECDH') !== -1 || a.indexOf('X25519') !== -1 || a.indexOf('DH') !== -1 || a.indexOf('DIFFIE') !== -1) {
      baseKey = 'ML-KEM';
    } else if (a.indexOf('RSA') !== -1) {
      // RSA can be key exchange or signature; if replacement specifies ML-DSA, use ML-DSA, else ML-KEM
      if (r.indexOf('ML-DSA') !== -1 || r.indexOf('DILITHIUM') !== -1) {
        baseKey = 'ML-DSA';
      } else {
        baseKey = 'ML-KEM';
      }
    } else if (a.indexOf('AES-256-GCM') !== -1 || a.indexOf('SHA-256') !== -1 || a.indexOf('SHA-384') !== -1 || a.indexOf('SHA-512') !== -1 || a.indexOf('CSPRNG') !== -1 || a.indexOf('PKCS#11') !== -1) {
      baseKey = 'SAFE-MODERN';
    }

    var template = KNOWLEDGE_BASE[baseKey] || KNOWLEDGE_BASE['GENERIC-FALLBACK'];

    // Clone and enrich with concrete algorithm and replacement strings
    var result = JSON.parse(JSON.stringify(template));
    result.algorithm = rawAlgo || 'Unknown Algorithm';
    result.recommendedReplacement = rawRepl && rawRepl !== 'None specified' && rawRepl !== '-'
      ? rawRepl
      : (template.recommendedReplacement || 'ML-KEM / ML-DSA Post-Quantum Standard');

    // Customize badges and classical security text for specific variants
    if (a.indexOf('RSA-1024') !== -1) {
      result.classicalSecurity.status = 'Broken Classically';
      result.classicalSecurity.reason = 'RSA 1024-bit modulus is vulnerable to distributed GNFS factoring (~80 bits security). Formally disallowed by NIST SP 800-131A.';
      result.statusBadges.oldBadge = 'Legacy-Broken';
      result.statusBadges.oldBadgeClass = 'badge-crit';
    } else if (a.indexOf('RSA-2048') !== -1) {
      result.classicalSecurity.status = 'Classically Safe Today (112-bit), Quantum-Broken';
      result.classicalSecurity.reason = 'Provides 112 bits classical security under GNFS. Secure against classical computers today, but completely broken by Shor\'s algorithm upon CRQC arrival.';
      result.statusBadges.oldBadge = 'Quantum-Broken';
      result.statusBadges.oldBadgeClass = 'badge-crit';
    } else if (a.indexOf('RSA-3072') !== -1) {
      result.classicalSecurity.status = 'Classically Strong (128-bit), Quantum-Broken';
      result.classicalSecurity.reason = 'Provides full 128-bit classical security under NIST SP 800-131A. Classically secure, but vulnerable to polynomial-time Shor\'s quantum factoring.';
      result.statusBadges.oldBadge = 'Quantum-Broken';
      result.statusBadges.oldBadgeClass = 'badge-crit';
    } else if (a.indexOf('ECDSA') !== -1 || a.indexOf('ED25519') !== -1) {
      result.classicalSecurity.status = 'Classically Strong (128-bit), Quantum-Broken';
      result.classicalSecurity.reason = 'Curve P-256 / Ed25519 provides 128 bits of security against Pollard\'s rho algorithm. Classically sound, but broken by Shor\'s quantum discrete log solver.';
    } else if (a.indexOf('MD5') !== -1) {
      result.classicalSecurity.status = 'Broken Classically';
      result.statusBadges.oldBadge = 'Legacy-Broken';
      result.statusBadges.oldBadgeClass = 'badge-crit';
    } else if (a.indexOf('DES') !== -1 || a.indexOf('ECB') !== -1) {
      result.statusBadges.oldBadge = 'Harmful';
      result.statusBadges.oldBadgeClass = 'badge-crit';
    }

    return result;
  }

  /**
   * Helper to retrieve all standard knowledge entries.
   */
  function getAllEntries() {
    return Object.keys(KNOWLEDGE_BASE).map(function (k) {
      return KNOWLEDGE_BASE[k];
    });
  }

  return {
    KNOWLEDGE_BASE: KNOWLEDGE_BASE,
    resolve: resolve,
    getAllEntries: getAllEntries
  };
}));
