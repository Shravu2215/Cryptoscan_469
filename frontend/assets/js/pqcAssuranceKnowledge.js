(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.PQCAssuranceKnowledge = api;
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const SOURCES = [
    { label: 'NIST FIPS 203 · ML-KEM', url: 'https://doi.org/10.6028/NIST.FIPS.203', status: 'Final' },
    { label: 'NIST FIPS 204 · ML-DSA', url: 'https://doi.org/10.6028/NIST.FIPS.204', status: 'Final' },
    { label: 'NIST FIPS 205 · SLH-DSA', url: 'https://doi.org/10.6028/NIST.FIPS.205', status: 'Final' },
    { label: 'NIST FIPS 206 · FN-DSA', url: 'https://csrc.nist.gov/pubs/fips/206/ipd', status: 'Draft / check current publication status' },
    { label: 'NIST FIPS 180-4 · Secure Hash Standard', url: 'https://doi.org/10.6028/NIST.FIPS.180-4', status: 'Final' },
    { label: 'NIST FIPS 202 · SHA-3 Standard', url: 'https://doi.org/10.6028/NIST.FIPS.202', status: 'Final' },
    { label: 'NIST SP 800-38D · GCM', url: 'https://doi.org/10.6028/NIST.SP.800-38D', status: 'Final' },
    { label: 'NIST SP 800-57 Part 1 Rev. 5 · Key Management', url: 'https://doi.org/10.6028/NIST.SP.800-57pt1r5', status: 'Final' },
    { label: 'NIST IR 8547 · Transition to Post-Quantum Cryptography', url: 'https://csrc.nist.gov/pubs/ir/8547/ipd', status: 'Draft transition guidance; proposed dates are not universal law' },
    { label: 'NIST SP 800-208 · Stateful hash-based signatures', url: 'https://doi.org/10.6028/NIST.SP.800-208', status: 'Final' },
    { label: 'NIST · HQC selected as backup KEM', url: 'https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption', status: 'Selected for standardization; not a final standard' },
    { label: 'NSA · CNSA 2.0 algorithms', url: 'https://media.defense.gov/2022/Sep/07/2003071831/-1/-1/0/CSI_CNSA_2.0_ALGORITHMS.PDF', status: 'Policy guidance; scope-specific' }
  ];

  // Reference knowledge only. Algorithm -> replacement decisions stay in QuantumRules / Migration Plan.
  const ENTRIES = {
    'ML-KEM (Kyber-768/1024) + Hybrid X25519/ML-KEM': {
      category: 'Key establishment', standard: 'NIST FIPS 203 (2024)',
      safeStatus: 'Quantum-resilient; hybrid also retains a classical X25519 contribution.',
      points: ['ML-KEM is based on Module-LWE lattice problems; no efficient classical or quantum attack is known against the standardized parameters.', 'A hybrid X25519/ML-KEM exchange is intended to retain security if either component remains secure; use a reviewed protocol combiner.', 'ML-KEM protects key establishment, not data encryption or signatures.'],
      quantum: 'Shor breaks the old RSA/DH/ECDH public-key exchange. A CRQC has no known efficient attack on standardized ML-KEM; the hybrid retains its classical component as well.',
      classical: 'The old public-key method is generally considered strong classically at recommended sizes; undersized keys may already be weak.',
      oldClassical: 'Strong at recommended parameters; assess the actual key size and usage.', oldQuantum: 'Quantum-Broken (Shor)',
      oldBits: 'Depends on algorithm and key size; not inferred from the label alone.', newBits: 'NIST security category 3 or 5, depending on the selected ML-KEM parameter set; not a directly comparable symmetric bit count.',
      sizes: 'ML-KEM-768 public key: 1,184 bytes; ciphertext: 1,088 bytes. Hybrid framing adds protocol-specific overhead.', latency: 'Protocol/provider dependent; benchmark the actual handshake.', effort: 'High — protocol negotiation, key serialization, and peer compatibility.',
      before: 'classicalDhExchange()', after: '// Negotiate a reviewed X25519 + ML-KEM-768 hybrid group\n// Exact API/configuration depends on the TLS or protocol provider.'
    },
    'ML-KEM (Kyber-768/1024) or Hybrid X25519+ML-KEM': {
      category: 'Key establishment', standard: 'NIST FIPS 203 (2024)',
      safeStatus: 'Quantum-resilient; choose the hybrid option when supported by the protocol and provider.',
      points: ['ML-KEM security is based on Module-LWE lattice problems.', 'A reviewed hybrid combiner can provide protection against failure of either the classical or PQC component.', 'Confirm the selected parameter set and wire protocol with every peer.'],
      quantum: 'Shor breaks the old RSA/DH/ECDH key-establishment method. No efficient quantum attack is known against standardized ML-KEM.',
      classical: 'The classical public-key method is generally strong at recommended sizes; inspect observed key size.',
      oldClassical: 'Strong at recommended parameters; undersized keys may be classically weak.', oldQuantum: 'Quantum-Broken (Shor)',
      oldBits: 'Algorithm/key-size dependent.', newBits: 'NIST security category 3 or 5 depending on parameter set; no direct equivalent bit value.',
      sizes: 'ML-KEM-768 public key: 1,184 bytes; ciphertext: 1,088 bytes. Hybrid overhead is protocol-specific.', latency: 'Provider and network dependent; measure in the target protocol.', effort: 'High — update negotiation, peers, and key handling.',
      before: 'classicalKeyAgreement()', after: '// Select a supported ML-KEM or reviewed hybrid key-establishment suite\n// Provider-specific configuration; do not implement a custom combiner.'
    },
    'ML-DSA (Dilithium-3/5) or SLH-DSA (SPHINCS+)': {
      category: 'Digital signatures', standard: 'NIST FIPS 204 (ML-DSA, 2024); NIST FIPS 205 (SLH-DSA, 2024)',
      safeStatus: 'Quantum-resilient standardized signature families.',
      points: ['ML-DSA is based on module-lattice problems; SLH-DSA is hash-based.', 'No efficient quantum algorithm is known that breaks the standardized schemes.', 'Update signers and verifiers together; public-key and signature formats differ from RSA/ECDSA.'],
      quantum: 'Shor breaks the old RSA/ECDSA/DSA signature keys and enables forgery. No known efficient quantum attack breaks FIPS 204/205 at standardized parameters.',
      classical: 'RSA/ECDSA/DSA are generally strong classically at recommended parameters; DSA and undersized keys may already be disallowed or weak.',
      oldClassical: 'Usually strong at recommended sizes; DSA/undersized keys have separate classical policy concerns.', oldQuantum: 'Quantum-Broken (Shor)',
      oldBits: 'Key and scheme dependent.', newBits: 'ML-DSA parameter sets target NIST categories 2/3/5; SLH-DSA has category-specific parameter sets. These are not direct bit-for-bit comparisons.',
      sizes: 'ML-DSA-65 signature: 3,309 bytes. Other parameter sets and SLH-DSA differ.', latency: 'Implementation and parameter-set dependent; benchmark sign and verify paths.', effort: 'High — update key formats, certificate/signature envelopes, and all verifiers.',
      before: 'signature = rsa_private_key.sign(message, padding, hashes.SHA256())', after: '# Provider API shape varies; use an implementation validated for FIPS 204\nsignature = mldsa_private_key.sign(message)'
    },
    'ML-KEM (Kyber-768/1024) or ML-DSA (Dilithium-3/5)': {
      category: 'Post-quantum primitive selection', standard: 'NIST FIPS 203 (ML-KEM, 2024) or NIST FIPS 204 (ML-DSA, 2024), selected by purpose',
      safeStatus: 'Use ML-KEM for key establishment or ML-DSA for digital signatures; they are not interchangeable.',
      points: ['ML-KEM is a key-encapsulation mechanism based on Module-LWE.', 'ML-DSA is a digital-signature scheme based on module lattices.', 'Select strictly by the observed operation; a signature finding must not be migrated to a KEM.'],
      quantum: 'Shor breaks classical RSA/ECC/DH. No efficient quantum break is known for FIPS 203/204 parameter sets.',
      classical: 'The old asymmetric primitive is generally strong classically at recommended parameters.',
      oldClassical: 'Assess algorithm, key size, and actual operation.', oldQuantum: 'Quantum-Broken (Shor)',
      oldBits: 'Algorithm dependent.', newBits: 'FIPS 203/204 parameter sets target NIST security categories; there is no single replacement bit count.',
      sizes: 'ML-KEM-768 public key 1,184 bytes/ciphertext 1,088 bytes; ML-DSA-65 signature 3,309 bytes. Select only the relevant primitive.', latency: 'Provider and operation dependent.', effort: 'High — confirm purpose and migrate all consumers.',
      before: 'classical_public_key_operation(data)', after: '# Choose ML-KEM for key establishment OR ML-DSA for signatures\n# Do not substitute one primitive for the other.'
    },
    'SHA-256 / SHA-3-256': {
      category: 'Cryptographic hash', standard: 'SHA-256: NIST FIPS 180-4 (2015); SHA3-256: NIST FIPS 202 (2015)',
      safeStatus: 'Classically strong and retains about 128-bit preimage security against Grover search.',
      points: ['SHA-256 is a SHA-2 member specified by FIPS 180-4.', 'SHA3-256 uses the SHA-3 sponge construction specified by FIPS 202.', 'Choose based on protocol compatibility; a hash function is not a password-hashing/KDF replacement.'],
      quantum: 'Grover gives a quadratic speedup for preimage search: a 256-bit output has approximately 128-bit generic quantum preimage work. Collision resistance has a different bound.',
      classical: 'SHA-1 is collision-broken in practice; SHA-256/SHA3-256 remain strong for ordinary hash uses.',
      oldClassical: 'SHA-1: collision-broken; MD5: collision-broken. Use case matters.', oldQuantum: 'SHA-1: Grover-weakened; MD5 is already classically broken.',
      oldBits: 'MD5/SHA-1 have 128/160-bit outputs; practical collision attacks mean those output sizes do not represent current collision security.', newBits: 'SHA-256/SHA3-256: 256-bit output; about 128-bit generic quantum preimage work under Grover.',
      sizes: 'Digest output remains 32 bytes for SHA-256 and SHA3-256.', latency: 'Typically low; benchmark the implementation and payload sizes.', effort: 'Low to medium — update digest identifiers and stored digest migration/verification.',
      before: 'digest = hashlib.md5(data).digest()', after: 'digest = hashlib.sha256(data).digest()  # or hashlib.sha3_256(data).digest()'
    },
    'SHA-256 / SHA-3-256 / BLAKE3': {
      category: 'Cryptographic hash', standard: 'SHA-256: NIST FIPS 180-4 (2015); SHA3-256: NIST FIPS 202 (2015). BLAKE3 is not a NIST FIPS standard.',
      safeStatus: 'SHA-256 and SHA3-256 are standardized choices; BLAKE3 is a non-FIPS option where policy permits.',
      points: ['SHA-256 and SHA3-256 are standardized by NIST.', 'BLAKE3 is a modern hash, but is not specified by FIPS 180-4/202; check compliance requirements.', 'Do not use a general hash as a password storage scheme.'],
      quantum: 'Grover reduces generic preimage work for a 256-bit output to about 128-bit quantum work; it does not make these hashes trivially breakable.',
      classical: 'MD5 and SHA-1 have practical collision attacks. Replace them regardless of quantum timelines.',
      oldClassical: 'MD5/SHA-1: classically collision-broken.', oldQuantum: 'Legacy-broken classically; quantum search is not the primary reason to replace.',
      oldBits: 'MD5/SHA-1 collision resistance is practically broken.', newBits: '256-bit output gives about 128-bit generic quantum preimage work under Grover.',
      sizes: '256-bit digest output is 32 bytes.', latency: 'Low in most deployments; compare provider throughput.', effort: 'Low to medium — update algorithm IDs and stored digest migration.',
      before: 'digest = hashlib.md5(data).digest()', after: 'digest = hashlib.sha256(data).digest()  # FIPS 180-4\n# Or use SHA3-256 (FIPS 202); BLAKE3 is not a FIPS standard.'
    },
    'AES-256-GCM': {
      category: 'Authenticated symmetric encryption', standard: 'NIST SP 800-38D (2007, GCM); AES block cipher FIPS 197 (2001, updated 2023)',
      safeStatus: 'Quantum-resilient when used with a full 256-bit key, unique 96-bit nonces, and correct authentication-tag handling.',
      points: ['GCM provides authenticated encryption; verify tags before using decrypted plaintext.', 'Use a unique nonce per key; 96-bit nonces are the standard recommended form in SP 800-38D.', 'Grover halves generic key-search strength, leaving roughly 128-bit work for AES-256.'],
      quantum: 'Grover can quadratically speed up exhaustive key search. AES-256 retains roughly 128-bit generic quantum key-search strength; Shor does not apply to AES.',
      classical: 'AES-ECB leaks repeated-block patterns; DES/3DES are legacy ciphers with inadequate or obsolete security margins.',
      oldClassical: 'ECB leaks structure; DES/3DES are not recommended for new protection.', oldQuantum: 'Grover affects symmetric key search; Shor does not apply.',
      oldBits: 'Depends on cipher; DES has a 56-bit key. ECB mode has no semantic security for repeated blocks.', newBits: 'AES-256: 256-bit key; roughly 128-bit generic quantum key-search work under Grover.',
      sizes: 'Ciphertext length is approximately plaintext length plus nonce/tag framing.', latency: 'Usually low; validate throughput, nonce storage, and tag handling.', effort: 'Low to medium — migrate format, nonce management, and authentication handling.',
      before: 'cipher = AES.new(key, AES.MODE_ECB)', after: `nonce = secrets.token_bytes(12)  # unique per key
      cipher = AES.new(key_32_bytes, AES.MODE_GCM, nonce=nonce)
      ciphertext, tag = cipher.encrypt_and_digest(plaintext)`
    },
    'AES-256-GCM / ChaCha20-Poly1305': {
      category: 'Authenticated symmetric encryption', standard: 'AES-GCM: NIST SP 800-38D (2007); ChaCha20-Poly1305: RFC 8439 (2018)',
      safeStatus: 'Both are modern authenticated-encryption choices with 256-bit keys; follow nonce/nonce-counter requirements.',
      points: ['AES-GCM is specified by NIST SP 800-38D; ChaCha20-Poly1305 by RFC 8439.', 'Both provide confidentiality and integrity when tags are verified.', 'Never reuse a nonce with the same key.'],
      quantum: 'Grover halves generic symmetric key-search strength: 256-bit keys retain approximately 128-bit generic quantum work. Shor does not apply to these symmetric ciphers.',
      classical: 'DES/3DES/RC4 and ECB mode are not appropriate modern authenticated encryption.',
      oldClassical: 'Legacy cipher/mode weakness; some old ciphers are practically brute-forceable or structurally insecure.', oldQuantum: 'Grover applies to symmetric key search; this is not a Shor break.',
      oldBits: 'DES uses a 56-bit key; other legacy cipher strengths vary.', newBits: '256-bit key; approximately 128-bit generic quantum key-search work under Grover.',
      sizes: 'Adds nonce and authentication tag framing; exact size depends on API/protocol.', latency: 'Low in many implementations; hardware support and platform affect results.', effort: 'Low to medium — migrate data formats and nonce handling.',
      before: 'cipher = DES.new(key, DES.MODE_ECB)', after: `nonce = secrets.token_bytes(12)  # unique per key
      cipher = AES.new(key_32_bytes, AES.MODE_GCM, nonce=nonce)
      ciphertext, tag = cipher.encrypt_and_digest(plaintext)`
    },
    'Secrets Manager / KMS / HashiCorp Vault': {
      category: 'Key management', standard: 'Deployment/control choice; use applicable NIST SP 800-57 key-management guidance and organizational policy.',
      safeStatus: 'Reduces embedded-secret exposure; does not make the underlying algorithm quantum-safe by itself.',
      points: ['Keep secret material out of source/configuration and enforce access control/rotation.', 'Select quantum-safe cryptographic primitives independently; KMS is not a PQC algorithm.', 'Audit callers and key lifecycle before removing the exposed value.'],
      quantum: 'A CRQC does not directly solve secret-management errors. If the stored key protects RSA/ECC-encrypted data, that cryptography remains quantum-vulnerable.',
      classical: 'Hardcoded key material is exposed to anyone with access to the code/artifact and should be treated as compromised.',
      oldClassical: 'Secret exposure is a current operational risk.', oldQuantum: 'Not a quantum algorithm issue; fix exposure and separately assess cryptographic primitive.',
      oldBits: 'Not applicable to key custody.', newBits: 'Not applicable; key custody does not define primitive strength.',
      sizes: 'Depends on provider and key export policy.', latency: 'Network/provider round trips may add latency; measure in deployment.', effort: 'Medium to high — access policies, rotation, application integration.',
      before: 'API_KEY = "embedded-secret"', after: 'secret = secret_manager.get_secret("service-key")\n# Rotate the exposed value; never commit the replacement.'
    },
    'AES-256-GCM / AES-256-CBC with HMAC': {
      category: 'Symmetric encryption and integrity', standard: 'AES: FIPS 197 (2001, updated 2023); GCM: NIST SP 800-38D (2007); HMAC: FIPS 198-1 (2008)',
      safeStatus: 'Prefer AEAD AES-GCM; CBC is safe only with correct encrypt-then-MAC composition and constant-time handling.',
      points: ['Prefer AES-GCM for new authenticated encryption.', 'If CBC is required for compatibility, use encrypt-then-MAC with independent keys and verify MAC before decrypting.', 'Use unique IV/nonce and correct tag/MAC verification.'],
      quantum: 'Grover reduces generic search; AES-256 retains approximately 128-bit key-search work. Shor does not apply to AES.',
      classical: 'AES-ECB is not semantically secure; unauthenticated CBC can enable padding-oracle attacks.',
      oldClassical: 'ECB leaks patterns; CBC requires authentication and careful error handling.', oldQuantum: 'No Shor break; Grover applies to key search.',
      oldBits: 'Mode weakness is structural and not captured by key bits alone.', newBits: 'AES-256 gives approximately 128-bit generic quantum key-search work.',
      sizes: 'GCM adds nonce/tag; CBC adds IV and MAC framing.', latency: 'Low to medium; CBC/HMAC can require additional passes.', effort: 'Medium — update data envelope and validate authentication order.',
      before: 'cipher = AES.new(key, AES.MODE_ECB)', after: 'nonce = secrets.token_bytes(12)  # unique per key\ncipher = AES.new(key_32_bytes, AES.MODE_GCM, nonce=nonce)\nciphertext, tag = cipher.encrypt_and_digest(plaintext)'
    },
    'None specified': {
      category: 'No replacement indicated by existing Migration Plan rules', standard: 'No migration standard selected',
      safeStatus: 'No replacement is recommended by the current migration rules. Review the observed usage before making changes.',
      points: ['This item is included only because it is present in the current Migration Plan candidate data.', 'No alternative is invented here.', 'Use the finding context and shared QuantumRules classification to confirm whether action is needed.'],
      quantum: 'Depends on the observed primitive and use; consult the current classification and algorithm-specific standards.',
      classical: 'Use the finding severity/classification; no claim of break is inferred from a missing replacement.',
      oldClassical: 'Not classified as classically broken by the current shared rule.', oldQuantum: 'Not classified as quantum-broken by the current shared rule.',
      oldBits: 'Not established from this finding.', newBits: 'Not applicable.',
      sizes: 'No replacement sizing data.', latency: 'No replacement latency data.', effort: 'Review required.',
      before: '// Review the observed algorithm and usage.', after: '// No replacement specified by Migration Plan.'
    }
  };

  const FALLBACK = {
    category: 'Cryptographic algorithm', standard: 'No matching standard entry; review the applicable NIST FIPS or RFC before migration.',
    safeStatus: 'No algorithm-specific assurance entry exists yet. Treat the replacement as unverified until reviewed.',
    points: ['No algorithm-specific claims are made by this fallback.', 'Confirm the replacement matches the observed operation and protocol.', 'Add a reviewed entry to ENTRIES in this file to provide standards, threat, and migration details.'],
    quantum: 'Quantum impact depends on the primitive family; no specific claim is inferred by the fallback.',
    classical: 'Classical strength is not asserted by this fallback.',
    oldClassical: 'Review required.', oldQuantum: 'Review required.', oldBits: 'Not established.', newBits: 'Not established.',
    sizes: 'Not established.', latency: 'Measure using the deployed provider and protocol.', effort: 'Review required.',
    before: '// Review current implementation before changing it.', after: '// Add a reviewed, provider-correct migration snippet.'
  };

  function normalize(value) {
    return String(value || '').toLowerCase().replace(/\s+/g, ' ').trim();
  }

  function resolveAssuranceEntry(replacement, algorithm, purpose) {
    const normalizedReplacement = normalize(replacement);
    const entry = Object.keys(ENTRIES).find(key => normalize(key) === normalizedReplacement)
      || (/ml-kem/.test(normalizedReplacement) ? 'ML-KEM (Kyber-768/1024) or Hybrid X25519+ML-KEM' : '')
      || (/ml-dsa|slh-dsa|fn-dsa/.test(normalizedReplacement) ? 'ML-DSA (Dilithium-3/5) or SLH-DSA (SPHINCS+)' : '')
      || (/sha-?256|sha3-?256/.test(normalizedReplacement) ? 'SHA-256 / SHA-3-256' : '')
      || (/blake3/.test(normalizedReplacement) ? 'SHA-256 / SHA-3-256 / BLAKE3' : '')
      || (/aes-256-gcm/.test(normalizedReplacement) && /chacha20/.test(normalizedReplacement) ? 'AES-256-GCM / ChaCha20-Poly1305' : '')
      || (/aes-256-gcm/.test(normalizedReplacement) ? 'AES-256-GCM' : '')
      || (/secrets manager|kms|vault|environment/.test(normalizedReplacement) ? 'Secrets Manager / KMS / HashiCorp Vault' : '')
      || null;
    const current = String(algorithm || '').toUpperCase();
    let old = null;
    if (/MD5|MD4|MD2/.test(current)) old = { classical: 'Broken: practical collision attacks make MD5 unsuitable for collision resistance.', quantum: 'Already broken classically; Grover is not the reason to replace it.' };
    else if (/SHA.?1/.test(current)) old = { classical: 'Broken for collision resistance; practical collision attacks are known.', quantum: 'Grover weakens generic search, but SHA-1 collision weakness is already classical.' };
    else if (/\bDES\b|3DES|TRIPLE.?DES|TDES/.test(current)) old = { classical: 'Legacy cipher: DES has a 56-bit key and is brute-forceable; 3DES has a 64-bit block and is restricted/disallowed for new encryption by NIST SP 800-131A.', quantum: 'Grover gives a quadratic search speedup; the legacy key/block-size limitations already matter classically.' };
    else if (/RSA|ECDSA|ECDH|ED25519|ED448|\bDSA\b|\bDH\b/.test(current)) old = { classical: 'Generally strong at recommended parameters; undersized keys or deprecated schemes may be weak today.', quantum: 'Shor’s algorithm breaks the public-key problem, enabling decryption or signature forgery as applicable.' };
    else if (/AES.?ECB|\bECB\b/.test(current)) old = { classical: 'ECB reveals repeated-block patterns; this is a mode weakness even with a large AES key.', quantum: 'Grover affects key search only; it does not repair ECB pattern leakage.' };
    else if (/HARDCODED|PLAINTEXT.?KEY|SECRET/.test(current)) old = { classical: 'Embedded secret exposure is a present-day operational weakness.', quantum: 'Not a quantum primitive break; rotate exposed material and assess the algorithm separately.' };
    else if (/AES|CHACHA/.test(current)) old = { classical: 'Strong when correctly parameterized and used with authenticated encryption.', quantum: 'Grover quadratically speeds generic key search; effective security depends on key size.' };
    else if (/SHA-?256|SHA-?384|SHA-?512|SHA3/.test(current)) old = { classical: 'No practical break is known for the observed SHA-2/SHA-3 variant.', quantum: 'Grover gives a quadratic speedup for preimage search; SHA-256 preimage work is roughly 128-bit against a generic quantum search.' };

    let oldBits = ((entry && ENTRIES[entry]) || FALLBACK).oldBits;
    let classicallyBroken = false;
    const rsaBits = current.match(/\bRSA[- ]?(\d{3,5})\b/);
    if (rsaBits) {
      const size = Number(rsaBits[1]);
      const rsaEquivalent = { 2048: 'about 112-bit classical strength', 3072: 'about 128-bit classical strength', 7680: 'about 192-bit classical strength', 15360: 'about 256-bit classical strength' };
      oldBits = `RSA-${size}: ${rsaEquivalent[size] || 'modulus size is not assigned a strength here'}; Shor breaks RSA in the CRQC model.`;
      if (size < 2048) { old.classical = `RSA-${size} is below the NIST 2048-bit minimum for RSA and is classically weak.`; classicallyBroken = true; }
    } else if (/AES.?ECB|\bECB\b/.test(current)) { oldBits = 'Key length is not enough to describe ECB safety; ECB leaks repeated-block patterns regardless of key size.'; classicallyBroken = true; }
    else if (/AES-?128/.test(current)) oldBits = 'AES-128: 128-bit key; approximately 64-bit generic quantum key-search work under Grover.';
    else if (/AES-?256/.test(current)) oldBits = 'AES-256: 256-bit key; approximately 128-bit generic quantum key-search work under Grover.';
    else if (/3DES|TRIPLE.?DES|TDES/.test(current)) { oldBits = '3DES/TDEA uses a 64-bit block; effective strength depends on the keying option. NIST SP 800-131A restricts/disallows its use for new encryption.'; classicallyBroken = true; }
    else if (/\bDES\b/.test(current)) { oldBits = 'DES has a 56-bit key.'; classicallyBroken = true; }
    else if (/MD5|MD4|MD2|SHA.?1/.test(current)) classicallyBroken = true;
    else if (/HARDCODED|PLAINTEXT.?KEY|SECRET/.test(current)) classicallyBroken = true;

    const usage = String(purpose || '').toLowerCase();
    const signatureUse = /sign|auth|jwt|certificate/.test(usage);
    let before = ((entry && ENTRIES[entry]) || FALLBACK).before;
    let after = ((entry && ENTRIES[entry]) || FALLBACK).after;
    let contextNote = '';
    if (/MD5|MD4|MD2/.test(current)) before = 'digest = hashlib.md5(data).digest()';
    else if (/SHA.?1/.test(current)) before = 'digest = hashlib.sha1(data).digest()';
    else if (/3DES|TRIPLE.?DES|TDES/.test(current)) before = 'cipher = DES3.new(key, DES3.MODE_ECB)';
    else if (/\bDES\b/.test(current)) before = 'cipher = DES.new(key, DES.MODE_ECB)';
    else if (/AES.?ECB|\bECB\b/.test(current)) before = 'cipher = AES.new(key, AES.MODE_ECB)';
    else if (/HARDCODED|PLAINTEXT.?KEY|SECRET/.test(current)) before = 'API_KEY = "embedded-secret"';
    else if (/ECDSA|ED25519|ED448|\bDSA\b/.test(current)) before = 'signature = classical_private_key.sign(message, ... )';
    else if (/(RSA|ECDH|\bDH\b)/.test(current)) before = signatureUse
      ? 'signature = rsa_private_key.sign(message, padding, hashes.SHA256())'
      : 'shared_key = classical_private_key.exchange(peer_public_key)';
    if (signatureUse && /ML-KEM/i.test(replacement) && !/ML-DSA|SLH-DSA/i.test(replacement)) {
      contextNote = 'The existing Migration Plan replacement is key-establishment-oriented, while this finding is a signature/authentication use. ML-KEM is not a signature scheme; select an approved signature replacement such as FIPS 204/205 for this use with a cryptography review.';
      after = '# Do not use ML-KEM for signatures. Select a FIPS 204/205 signer\n# and update every verifier; API is provider-specific.';
    }

    const transition = /ML-KEM|ML-DSA|SLH-DSA/i.test(replacement)
      ? 'NIST IR 8547 draft transition planning proposes deprecation of quantum-vulnerable public-key algorithms by 2030 and disallowance by 2035; these are proposed policy milestones, not universal law. CNSA 2.0 has separate scope-specific requirements; consult the linked NSA guidance and applicable policy.'
      : 'No universal NIST IR 8547 public-key transition date is asserted for this replacement; follow the applicable algorithm standard and organizational policy.';
    const normalized = normalize(replacement);
    const isKem = /ml-kem/.test(normalized);
    const isSignature = /ml-dsa|slh-dsa|fn-dsa/.test(normalized);
    const isHash = /sha-?256|sha3/.test(normalized);
    const isSymmetric = /aes-256|chacha20/.test(normalized);
    const isSecret = /secrets manager|kms|vault|environment/.test(normalized);
    const parameterSet = String(replacement || '');
    const nistStatus = /fips 206|fn-dsa/i.test(parameterSet) ? 'Draft' :
      /fips 20[345]|ml-kem|ml-dsa|slh-dsa/i.test(parameterSet) ? 'Final' : 'Not applicable / not established';
    const securityCategory = /ml-kem-768|ml-dsa-65/i.test(parameterSet) ? 'NIST security category 3' :
      /ml-kem-1024|ml-dsa-87/i.test(parameterSet) ? 'NIST security category 5' :
      /ml-kem-512|ml-dsa-44|slh-dsa-sha2-128|slh-dsa-shake-128/i.test(parameterSet) ? 'NIST security category 1' :
      isKem || isSignature ? 'Parameter-set dependent (NIST categories 1/3/5)' : 'Not applicable / not established';
    const purposeName = isKem ? 'KEM / key establishment' : isSignature ? 'Digital signature' :
      isHash ? 'Hash' : isSymmetric ? 'Symmetric encryption' : isSecret ? 'Secret management' : 'Not established';
    const hardProblem = isKem ? 'Module-LWE (Module Learning With Errors).' :
      /slh-dsa/.test(normalized) ? 'Hash-based security assumptions; see FIPS 205 parameter-set rationale.' :
      /fn-dsa/.test(normalized) ? 'NTRU lattices; FIPS 206 remains draft until finalized.' :
      /ml-dsa/.test(normalized) ? 'Module-lattice assumptions; see FIPS 204 parameter-set rationale.' :
      isHash ? 'Collision / preimage resistance of the selected hash construction.' :
      isSymmetric ? 'Generic key-search resistance; Grover gives a quadratic speedup.' :
      isSecret ? 'Not an algorithmic hardness assumption; this is key custody and exposure control.' :
      'Not established for this replacement.';
    const bestAttack = isKem || isSignature
      ? `No known practical attack as of ${new Date().toISOString().slice(0, 10)}, per ${isKem ? 'NIST FIPS 203' : /slh-dsa/.test(normalized) ? 'NIST FIPS 205' : 'NIST FIPS 204'}; this is not a guarantee.`
      : 'No attack-cost or security-margin claim is asserted for this finding.';
    const caveat = isKem || isSignature
      ? 'These standards are newer than RSA/ECC deployments. Side-channel, fault, key-management, parameter-selection, and implementation risks remain; use reviewed provider implementations.'
      : isSecret
        ? 'A secret manager does not make an underlying cryptographic algorithm quantum-safe. Rotate the exposed key and review its cryptographic use separately.'
        : 'Implementation and protocol compatibility risks remain; verify the actual use and provider behavior.';
    const migrationPath = isKem
      ? ['Deploy a protocol-supported hybrid exchange first (for example X25519 + ML-KEM-768) using a reviewed combiner.', 'Move to PQC-only only after peer support and downgrade behavior are verified.', 'Keep algorithm and key-format agility so parameter sets can be replaced without redesign.']
      : isSignature
        ? ['Use dual signatures (PQC plus the existing signature) where the protocol supports a reviewed transition.', 'Migrate signers, verifiers, certificates, and stored signature formats together.', 'Retain crypto-agility and assess SLH-DSA as a conservative hash-based alternative when appropriate.']
        : ['Use the replacement compatible with the actual operation and persisted data format.', 'Add compatibility tests and preserve an explicit crypto-agility path.'];
    const futureResilience = isKem
      ? 'HQC was selected by NIST in March 2025 as a backup KEM based on a different code-based assumption; it is selected for standardization, not yet a final standard. Track standardization and retain a replaceable KEM interface.'
      : isSignature
        ? 'SLH-DSA (FIPS 205) is a standardized hash-based signature alternative to lattice signatures; parameter size and performance trade-offs differ. Retain a replaceable signature interface.'
        : 'Maintain crypto-agility and periodically review new cryptanalysis and applicable standards.';
    return {
      replacement: entry || 'FALLBACK', algorithm: algorithm || 'Unknown algorithm', current: old || FALLBACK,
      ...((entry && ENTRIES[entry]) || FALLBACK), oldBits, classicallyBroken, transition, before, after, contextNote, isFallback: !entry,
      nistStatus, securityCategory, purposeName, hardProblem, bestAttack, caveat, migrationPath, futureResilience,
      publicKeySize: /ml-kem-768/.test(normalized) ? '1,184 bytes (spec value)' : /ml-dsa-65/.test(normalized) ? '1,952 bytes (spec value)' : 'Not established for the selected parameter set',
      outputSize: /ml-kem-768/.test(normalized) ? 'Ciphertext: 1,088 bytes (spec value)' : /ml-dsa-65/.test(normalized) ? 'Signature: 3,309 bytes (spec value)' : (isHash ? 'Digest: 32 bytes for SHA-256/SHA3-256 (spec value)' : 'Not established for the selected parameter set'),
      impact: isKem ? 'Public key and ciphertext framing grow; update protocol negotiation, peer support, and message limits.' :
        isSignature ? 'Public keys/signatures and certificate or JWT payloads can grow; update all verifiers and storage/transport limits.' :
        isSecret ? 'App fails at startup if env var missing' :
        'Key, nonce/IV, digest, or ciphertext framing may change; verify the actual data format and compatibility.',
      sources: SOURCES
    };
  }

  return { ENTRIES, FALLBACK, SOURCES, resolveAssuranceEntry };
}));
