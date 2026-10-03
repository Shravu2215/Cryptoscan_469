/**
 * CryptoScan PQC Data Table & Impact Calculation Engine
 * Contains sizes (in bytes) from FIPS 203/204/205 and Falcon specification,
 * default protocol limits, calculation logic, and risk labeling.
 */

window.PQCSizes = (function() {
  'use strict';

  // Master database of sizes (all in bytes)
  const ALGO_DATABASE = {
    // Classical Signatures & Asymmetric Key Exchange
    'RSA-2048': { name: 'RSA-2048', family: 'RSA', category: 'signature_kem', pk: 256, sig: 256, ct: 256, derPk: 294, derSig: 256 },
    'RSA-3072': { name: 'RSA-3072', family: 'RSA', category: 'signature_kem', pk: 384, sig: 384, ct: 384, derPk: 422, derSig: 384 },
    'RSA-4096': { name: 'RSA-4096', family: 'RSA', category: 'signature_kem', pk: 512, sig: 512, ct: 512, derPk: 550, derSig: 512 },
    'ECDSA P-256': { name: 'ECDSA P-256', family: 'ECDSA', category: 'signature', pk: 64, sig: 64, uncompressedPk: 65, derSig: 72 },
    'ECDSA P-384': { name: 'ECDSA P-384', family: 'ECDSA', category: 'signature', pk: 96, sig: 96, uncompressedPk: 97, derSig: 104 },
    'Ed25519': { name: 'Ed25519', family: 'Ed25519', category: 'signature', pk: 32, sig: 64 },
    'ECDH P-256': { name: 'ECDH P-256', family: 'ECDH', category: 'kem', pk: 65, ct: 65 },
    'X25519': { name: 'X25519', family: 'X25519', category: 'kem', pk: 32, ct: 32 },

    // Post-Quantum Signatures (FIPS 204 ML-DSA, Falcon, FIPS 205 SLH-DSA)
    'ML-DSA-44': { name: 'ML-DSA-44', family: 'ML-DSA', category: 'signature', pk: 1312, sig: 2420, standard: 'FIPS 204' },
    'ML-DSA-65': { name: 'ML-DSA-65', family: 'ML-DSA', category: 'signature', pk: 1952, sig: 3309, standard: 'FIPS 204' },
    'ML-DSA-87': { name: 'ML-DSA-87', family: 'ML-DSA', category: 'signature', pk: 2592, sig: 4627, standard: 'FIPS 204' },
    'Falcon-512': { name: 'Falcon-512', family: 'Falcon', category: 'signature', pk: 897, sig: 666, standard: 'NIST Round 4' },
    'Falcon-1024': { name: 'Falcon-1024', family: 'Falcon', category: 'signature', pk: 1793, sig: 1280, standard: 'NIST Round 4' },
    'SLH-DSA-SHA2-128s': { name: 'SLH-DSA-SHA2-128s', family: 'SLH-DSA', category: 'signature', pk: 32, sig: 7856, standard: 'FIPS 205' },
    'SLH-DSA-SHA2-128f': { name: 'SLH-DSA-SHA2-128f', family: 'SLH-DSA', category: 'signature', pk: 32, sig: 17088, standard: 'FIPS 205' },
    'SLH-DSA-SHA2-192s': { name: 'SLH-DSA-SHA2-192s', family: 'SLH-DSA', category: 'signature', pk: 48, sig: 16224, standard: 'FIPS 205' },
    'SLH-DSA-SHA2-256s': { name: 'SLH-DSA-SHA2-256s', family: 'SLH-DSA', category: 'signature', pk: 64, sig: 29792, standard: 'FIPS 205' },
    'SLH-DSA-SHA2-256f': { name: 'SLH-DSA-SHA2-256f', family: 'SLH-DSA', category: 'signature', pk: 64, sig: 49856, standard: 'FIPS 205' },

    // Post-Quantum Key Exchange (FIPS 203 ML-KEM & Hybrids)
    'ML-KEM-512': { name: 'ML-KEM-512', family: 'ML-KEM', category: 'kem', pk: 800, ct: 768, sharedSecret: 32, standard: 'FIPS 203' },
    'ML-KEM-768': { name: 'ML-KEM-768', family: 'ML-KEM', category: 'kem', pk: 1184, ct: 1088, sharedSecret: 32, standard: 'FIPS 203' },
    'ML-KEM-1024': { name: 'ML-KEM-1024', family: 'ML-KEM', category: 'kem', pk: 1568, ct: 1568, sharedSecret: 32, standard: 'FIPS 203' },
    'X25519MLKEM768': { name: 'X25519MLKEM768', family: 'Hybrid', category: 'kem', pk: 1216, ct: 1120, sharedSecret: 64, isHybrid: true },

    // Symmetric Ciphers & Hash Functions
    'AES-ECB': { name: 'AES-ECB', family: 'AES-ECB', category: 'symmetric', key: 16, tag: 0, noPayloadImpact: true },
    'AES-128': { name: 'AES-128', family: 'AES', category: 'symmetric', key: 16, tag: 0, noPayloadImpact: true },
    'AES-256-GCM': { name: 'AES-256-GCM', family: 'AES', category: 'symmetric', key: 32, tag: 16, noPayloadImpact: true },
    'DES': { name: 'DES', family: 'DES', category: 'symmetric', key: 8, noPayloadImpact: true },
    '3DES': { name: '3DES', family: 'DES', category: 'symmetric', key: 24, noPayloadImpact: true },
    'RC4': { name: 'RC4', family: 'RC4', category: 'symmetric', key: 16, noPayloadImpact: true },
    'MD5': { name: 'MD5', family: 'MD5', category: 'hash', digest: 16, noPayloadImpact: true },
    'SHA-1': { name: 'SHA-1', family: 'SHA', category: 'hash', digest: 20, noPayloadImpact: true },
    'SHA-256': { name: 'SHA-256', family: 'SHA', category: 'hash', digest: 32, noPayloadImpact: true },
    'SHA-384': { name: 'SHA-384', family: 'SHA', category: 'hash', digest: 48, noPayloadImpact: true },
    'SHA3-256': { name: 'SHA3-256', family: 'SHA3', category: 'hash', digest: 32, noPayloadImpact: true }
  };

  // Default Protocol and Environmental Limits (User editable in UI)
  const DEFAULT_LIMITS = {
    cookieLimit: 4096,              // Browser cookie size limit (4096 bytes)
    headerLineLimit: 8192,          // HTTP header line limit (nginx/Apache default 8192 bytes)
    headerTotalLimit: 16384,        // Node.js default total HTTP headers limit
    tlsInitCwnd: 14600,             // TCP initial congestion window (~14600 bytes = 10 x 1460 MSS)
    qrEccLevel: 'L',                // QR Code ECC level (L: 2953, M: 2331, Q: 1663, H: 1273)
    qrLimits: { L: 2953, M: 2331, Q: 1663, H: 1273 },
    iotProfile: 'BLE_ATT',          // IoT profile limit
    iotLimits: {
      BLE_ATT: 20,                  // BLE ATT default MTU payload (20 bytes)
      BLE_ATT_MAX: 512,             // Max BLE ATT payload
      LoRaWAN_SF12: 51,             // LoRaWAN SF12 payload
      LoRaWAN_SF7: 222,             // LoRaWAN SF7 payload
      IEEE_802_15_4: 127,           // IEEE 802.15.4 frame
      CoAP_UDP: 1152,               // CoAP without blockwise transfer
      DTLS_UDP: 1280                // DTLS MTU
    },
    certChainCount: 3,              // Leaf, Intermediate, Root (Root not sent)
    certOverhead: 300,              // Static ASN.1/x509 fields per cert
    jwtClaimsPayload: 200           // Default JSON claims payload size in bytes
  };

  /**
   * Normalizes arbitrary algorithm strings from scan findings into database keys.
   */
  function normalizeAlgo(algoStr) {
    if (!algoStr) return null;
    const s = algoStr.trim().toUpperCase();

    if (s.includes('ML-DSA-65') || s.includes('DILITHIUM3')) return 'ML-DSA-65';
    if (s.includes('ML-DSA-44') || s.includes('DILITHIUM2')) return 'ML-DSA-44';
    if (s.includes('ML-DSA-87') || s.includes('DILITHIUM5')) return 'ML-DSA-87';
    if (s.includes('FALCON-512') || s.includes('FALCON512')) return 'Falcon-512';
    if (s.includes('FALCON-1024') || s.includes('FALCON1024')) return 'Falcon-1024';

    if (s.includes('SLH-DSA-SHA2-128S')) return 'SLH-DSA-SHA2-128s';
    if (s.includes('SLH-DSA-SHA2-128F')) return 'SLH-DSA-SHA2-128f';
    if (s.includes('SLH-DSA-SHA2-192S')) return 'SLH-DSA-SHA2-192s';
    if (s.includes('SLH-DSA-SHA2-256S')) return 'SLH-DSA-SHA2-256s';
    if (s.includes('SLH-DSA-SHA2-256F')) return 'SLH-DSA-SHA2-256f';

    if (s.includes('X25519MLKEM768') || s.includes('HYBRID X25519')) return 'X25519MLKEM768';
    if (s.includes('ML-KEM-768') || s.includes('KYBER768')) return 'ML-KEM-768';
    if (s.includes('ML-KEM-512') || s.includes('KYBER512')) return 'ML-KEM-512';
    if (s.includes('ML-KEM-1024') || s.includes('KYBER1024')) return 'ML-KEM-1024';

    if (s.includes('RSA-4096') || s.includes('RSA 4096') || s.includes('4096')) return 'RSA-4096';
    if (s.includes('RSA-3072') || s.includes('RSA 3072') || s.includes('3072')) return 'RSA-3072';
    if (s.includes('RSA-2048') || s.includes('RSA 2048') || s.includes('RSA')) return 'RSA-2048';

    if (s.includes('ECDSA P-384') || s.includes('P-384') || s.includes('SECP384R1')) return 'ECDSA P-384';
    if (s.includes('ECDSA P-256') || s.includes('P-256') || s.includes('SECP256R1') || s.includes('ECDSA') || s === 'EC' || s.endsWith(' EC') || s.startsWith('EC ') || s.includes(' EC ')) return 'ECDSA P-256';
    if (s.includes('ED25519')) return 'Ed25519';
    if (s.includes('ECDH')) return 'ECDH P-256';
    if (s.includes('X25519')) return 'X25519';

    if (s.includes('AES') && s.includes('ECB')) return 'AES-ECB';
    if (s.includes('AES-256')) return 'AES-256-GCM';
    if (s.includes('AES-128') || s.includes('AES')) return 'AES-128';
    if (s.includes('3DES') || s.includes('TRIPLEDES')) return '3DES';
    if (s.includes('DES')) return 'DES';
    if (s.includes('RC4')) return 'RC4';

    if (s.includes('SHA-384') || s.includes('SHA384')) return 'SHA-384';
    if (s.includes('SHA3-256') || s.includes('SHA3')) return 'SHA3-256';
    if (s.includes('SHA-256') || s.includes('SHA256')) return 'SHA-256';
    if (s.includes('SHA-1') || s.includes('SHA1')) return 'SHA-1';
    if (s.includes('MD5')) return 'MD5';

    return null;
  }

  /**
   * Filter available PQC replacements for a given classical algorithm type.
   */
  function getValidReplacements(classicalAlgoKey, mode = 'pure') {
    const cur = ALGO_DATABASE[classicalAlgoKey] || ALGO_DATABASE['ECDSA P-256'];
    if (cur.category === 'symmetric') {
      return ['AES-256-GCM'];
    }
    if (cur.category === 'hash') {
      return ['SHA-384', 'SHA3-256'];
    }
    if (cur.category === 'kem' || (cur.category === 'signature_kem' && classicalAlgoKey.includes('KEM'))) {
      if (mode === 'hybrid') {
        return ['X25519MLKEM768', 'ML-KEM-768', 'ML-KEM-1024', 'ML-KEM-512'];
      }
      return ['ML-KEM-768', 'ML-KEM-512', 'ML-KEM-1024', 'X25519MLKEM768'];
    }
    // Default signatures
    return [
      'ML-DSA-65',
      'ML-DSA-44',
      'ML-DSA-87',
      'Falcon-512',
      'Falcon-1024',
      'SLH-DSA-SHA2-128s',
      'SLH-DSA-SHA2-128f',
      'SLH-DSA-SHA2-192s',
      'SLH-DSA-SHA2-256s'
    ];
  }

  /**
   * JWT Size calculation: Base64url(header + payload + signature) + 2 dots
   */
  function calculateJwt(sigBytes, payloadBytes = 200, headerBytes = 36) {
    const rawBytes = headerBytes + payloadBytes + sigBytes;
    const base64Bytes = Math.ceil(rawBytes * 4 / 3) + 2;
    return { rawBytes, base64Bytes };
  }

  /**
   * Certificate Chain size calculation: 3 certs by default
   */
  function calculateCertChain(pkBytes, sigBytes, count = 3, overhead = 300) {
    const perCert = pkBytes + sigBytes + overhead;
    const totalChain = perCert * count;
    return { perCert, totalChain };
  }

  /**
   * Run full simulation calculations for before and after algorithms.
   */
  function computeSimulation(classicalKey, pqcKey, mode = 'pure', userLimits = {}, scannedEvidence = {}) {
    const limits = { ...DEFAULT_LIMITS, ...userLimits };
    const cur = ALGO_DATABASE[classicalKey] || ALGO_DATABASE['ECDSA P-256'];
    const pqc = ALGO_DATABASE[pqcKey] || ALGO_DATABASE['ML-DSA-65'];

    // Handle symmetric & hash ("no payload impact")
    if (cur.noPayloadImpact || pqc.noPayloadImpact) {
      return {
        classicalKey,
        pqcKey,
        mode,
        isNoPayloadImpact: true,
        summaryMessage: 'Symmetric key & hash algorithm upgrades change key or digest size only slightly and have zero impact on payload limits or transport frames.',
        kpis: {
          pkBefore: cur.key || cur.digest || 16,
          pkAfter: pqc.key || pqc.digest || 32,
          pkMultiplier: ( (pqc.key || pqc.digest || 32) / (cur.key || cur.digest || 16) ).toFixed(1),
          sigBefore: 0,
          sigAfter: 0,
          sigMultiplier: '1.0',
          affectedScenariosCount: 0,
          verdict: 'Safe'
        },
        matrix: []
      };
    }

    // Bytes extraction
    const curPk = cur.pk || 64;
    const curSig = cur.sig || cur.ct || 64;

    let pqcPk = pqc.pk || 1952;
    let pqcSig = pqc.sig || pqc.ct || 3309;

    // Hybrid adjustments if applicable
    if (mode === 'hybrid' && !pqc.isHybrid && (pqc.category === 'kem' || cur.category === 'kem')) {
      pqcPk = (cur.pk || 32) + pqc.pk;
      pqcSig = (cur.ct || 32) + (pqc.ct || pqc.sig);
    } else if (pqc.isHybrid) {
      pqcPk = pqc.pk; // 1216
      pqcSig = pqc.ct; // 1120
    }

    // 1. JWT & Cookie Storage
    const curJwt = calculateJwt(curSig, limits.jwtClaimsPayload);
    const pqcJwt = calculateJwt(pqcSig, limits.jwtClaimsPayload);
    const cookieLimit = limits.cookieLimit;
    const jwtCookieBreached = pqcJwt.base64Bytes > cookieLimit;

    // 2. HTTP Header
    const headerLineLimit = limits.headerLineLimit;
    const headerBreached = pqcJwt.base64Bytes > headerLineLimit;

    // 3. Certificate Chain
    const curCertChain = calculateCertChain(curPk, curSig, limits.certChainCount, limits.certOverhead);
    const pqcCertChain = calculateCertChain(pqcPk, pqcSig, limits.certChainCount, limits.certOverhead);

    // 4. TLS Handshake Flight
    // Key share is the KEM component only. A signature-only change does NOT
    // change the key share (it stays X25519 = 32 B).  Only a KEM replacement
    // (ML-KEM-*, X25519MLKEM768) changes it.
    const isKemReplacement = (pqc.category === 'kem');
    const curKeyShare = (cur.category === 'kem') ? (cur.ct || cur.pk || 32) : 32; // X25519 default
    const pqcKeyShare = isKemReplacement ? (pqc.ct || pqc.pk || 1184) : curKeyShare;
    const curTlsFlight = curCertChain.totalChain + curKeyShare;
    const pqcTlsFlight = pqcCertChain.totalChain + pqcKeyShare;
    const tlsBreached = pqcTlsFlight > limits.tlsInitCwnd;

    // 5. QR Code Storage
    const qrCap = limits.qrLimits[limits.qrEccLevel] || 2953;
    const curQrPayload = curSig;
    const pqcQrPayload = pqcSig;
    const qrBreached = pqcQrPayload > qrCap;

    // 6. IoT Payload & Fragmentation
    const iotMtu = limits.iotLimits[limits.iotProfile] || limits.iotLimits.BLE_ATT;
    const curIotFrags = Math.ceil(curSig / iotMtu);
    const pqcIotFrags = Math.ceil(pqcSig / iotMtu);
    const iotBreached = pqcSig > iotMtu;

    // helper to determine risk status label & evidence string
    // "Confirmed issue" ONLY if (a) a real limit was parsed from a scanned file
    // (evidence must contain parsedLimit) or (b) the user typed the limit.
    // Map scenario keys to the userLimits property they correspond to.
    const SCENARIO_TO_LIMIT_KEY = {
      jwt: 'cookieLimit', header: 'headerLineLimit',
      tls: 'tlsInitCwnd', qr: 'qrEccLevel', iot: 'iotProfile'
    };

    function classifyScenario(isBreached, beforeVal, afterVal, limitVal, scenarioKey) {
      if (!isBreached) {
        const headroom = limitVal - afterVal;
        return {
          status: 'No issue',
          badgeClass: 'badge-safe',
          evidence: `Fits comfortably (${headroom.toLocaleString()} B remaining headroom)`,
          headroom,
          usedPct: Math.min(100, Math.round((afterVal / limitVal) * 100))
        };
      }

      // (a) Real parsed limit from scanned file (must carry parsedLimit)
      const repoEv = scannedEvidence[scenarioKey];
      if (repoEv && repoEv.parsedLimit) {
        return {
          status: 'Confirmed issue',
          badgeClass: 'badge-crit',
          evidence: `Scanned config: ${repoEv.file} (line ${repoEv.line || 1}) — ${repoEv.parsedLimit.directive || 'limit'} = ${repoEv.parsedLimit.value} B`,
          headroom: 0,
          usedPct: Math.round((afterVal / limitVal) * 100)
        };
      }

      // (b) User explicitly typed a value in the Limits panel
      const limitKey = SCENARIO_TO_LIMIT_KEY[scenarioKey];
      if (limitKey && userLimits[limitKey] !== undefined) {
        return {
          status: 'Confirmed issue',
          badgeClass: 'badge-crit',
          evidence: `User-entered limit: ${limitVal.toLocaleString()} B`,
          headroom: 0,
          usedPct: Math.round((afterVal / limitVal) * 100)
        };
      }

      // Otherwise: estimated risk only
      return {
        status: 'Estimated risk',
        badgeClass: 'badge-amber',
        evidence: `Default protocol limit (${limitVal.toLocaleString()} B); may break unconfigured endpoints`,
        headroom: 0,
        usedPct: Math.round((afterVal / limitVal) * 100)
      };
    }

    const scJwt = classifyScenario(jwtCookieBreached, curJwt.base64Bytes, pqcJwt.base64Bytes, cookieLimit, 'jwt');
    const scHeader = classifyScenario(headerBreached, pqcJwt.base64Bytes, pqcJwt.base64Bytes, headerLineLimit, 'header');
    const scTls = classifyScenario(tlsBreached, curTlsFlight, pqcTlsFlight, limits.tlsInitCwnd, 'tls');
    // Cert chain is informational — no limit to breach unless user enters one
    const userCertLimit = userLimits.certChainLimit;
    const certBreached = userCertLimit ? (pqcCertChain.totalChain > userCertLimit) : false;
    const scCert = userCertLimit
      ? classifyScenario(certBreached, curCertChain.totalChain, pqcCertChain.totalChain, userCertLimit, 'cert')
      : { status: 'Informational', badgeClass: 'badge-amber', evidence: `Chain grew ${(pqcCertChain.totalChain / curCertChain.totalChain).toFixed(1)}x`, headroom: null, usedPct: null };
    const scQr = classifyScenario(qrBreached, curQrPayload, pqcQrPayload, qrCap, 'qr');
    const scIot = classifyScenario(iotBreached, curSig, pqcSig, iotMtu, 'iot');

    // ─── Context-sensitive mitigation builders ──────────────────────────

    function buildQrMitigation(eccLevel) {
      if (eccLevel === 'L') {
        return 'Already at maximum capacity. Split the payload across multiple QR codes (structured append), compress it (CBOR/zlib), or encode only a short URL/ID and keep the signature on a server.';
      }
      return 'Switch to ECC level L (capacity 2953 B) to gain space; if it still doesn\'t fit, use the options above.';
    }

    function buildIotMitigation(profile, mtu, payload, pqcFrags, curFrags) {
      const p = (profile || '').toUpperCase();
      if (p === 'BLE_ATT') {
        const maxMtu = limits.iotLimits.BLE_ATT_MAX || 512;
        const packetsAtMax = Math.ceil(payload / maxMtu);
        return `Negotiate a larger ATT MTU (up to ${maxMtu} B: ${packetsAtMax} packets instead of ${pqcFrags}), or use ATT long writes; or let a gateway verify the signature.`;
      }
      if (p.includes('LORAWAN') || p.includes('LORA')) {
        return 'Use application-layer fragmentation, or send a hash/ID and verify off-device.';
      }
      if (p.includes('802.15.4') || p.includes('6LOWPAN') || p === 'IEEE_802_15_4') {
        return 'Use 6LoWPAN fragmentation.';
      }
      if (p.includes('COAP') || p.includes('DTLS') || p === 'COAP_UDP' || p === 'DTLS_UDP') {
        return 'Use CoAP blockwise transfer (RFC 7959) or DTLS fragmentation (path MTU 1280).';
      }
      // Fallback
      return `Payload requires ${pqcFrags} fragments at ${mtu} B MTU. Consider application-layer fragmentation or a gateway verification model.`;
    }


    const matrix = [
      {
        id: 'jwt',
        name: 'JWT / Cookie Storage',
        desc: 'Base64url encoded JWT inside HTTP Cookie headers',
        beforeSize: curJwt.base64Bytes,
        afterSize: pqcJwt.base64Bytes,
        limit: cookieLimit,
        limitUnit: 'B cookie limit',
        status: scJwt.status,
        badgeClass: scJwt.badgeClass,
        evidence: scJwt.evidence,
        usedPct: scJwt.usedPct,
        mitigation: 'Use reference tokens / session IDs instead of embedding large PQC signatures in cookies, or increase max cookie buffer limits.',
        breakdown: `Raw JSON: Header (36 B) + Claims (${limits.jwtClaimsPayload} B) + Sig (${pqcSig} B) = ${36 + limits.jwtClaimsPayload + pqcSig} B. Base64url expanded: ${pqcJwt.base64Bytes} B vs Cookie limit ${cookieLimit} B.`
      },
      {
        id: 'header',
        name: 'HTTP Authorization Header',
        desc: 'Single HTTP header line size (nginx/Apache default limit)',
        beforeSize: curJwt.base64Bytes,
        afterSize: pqcJwt.base64Bytes,
        limit: headerLineLimit,
        limitUnit: 'B header limit',
        status: scHeader.status,
        badgeClass: scHeader.badgeClass,
        evidence: scHeader.evidence,
        usedPct: scHeader.usedPct,
        mitigation: 'Increase web server header buffer (e.g. nginx `large_client_header_buffers 4 16k`) or pass tokens via HTTP POST body.',
        breakdown: `Authorization header line total: ${pqcJwt.base64Bytes} B vs Server max header line limit ${headerLineLimit} B.`
      },
      {
        id: 'tls',
        name: 'TLS Handshake Initial Flight',
        desc: 'Server handshake flight (cert chain + key share) vs TCP initcwnd',
        beforeSize: curTlsFlight,
        afterSize: pqcTlsFlight,
        limit: limits.tlsInitCwnd,
        limitUnit: 'B TCP initcwnd',
        status: scTls.status,
        badgeClass: scTls.badgeClass,
        evidence: scTls.evidence,
        usedPct: scTls.usedPct,
        mitigation: 'Enable TLS Certificate Compression (RFC 8879) or use compact signatures (Falcon-512) for server certificates to avoid +1 RTT latency penalty.',
        breakdown: `3 Certs (${pqcCertChain.totalChain} B) + Key Share (${pqcKeyShare} B) = ${pqcTlsFlight} B vs TCP initcwnd limit ${limits.tlsInitCwnd} B.`
      },
      {
        id: 'cert',
        name: 'X.509 Certificate Chain',
        desc: 'Full certificate chain total size (Leaf + Intermediate + Root)',
        beforeSize: curCertChain.totalChain,
        afterSize: pqcCertChain.totalChain,
        limit: userCertLimit || null,
        limitDisplay: userCertLimit ? `${userCertLimit.toLocaleString()} B` : 'N/A',
        limitUnit: userCertLimit ? 'B user limit' : 'N/A',
        status: scCert.status,
        badgeClass: scCert.badgeClass,
        evidence: scCert.evidence,
        usedPct: scCert.usedPct,
        isInformational: !userCertLimit,
        mitigation: 'Use Falcon-512 signatures (666 B) instead of ML-DSA-65 (3309 B) to reduce certificate chain overhead.',
        breakdown: `${limits.certChainCount} Certs x [Public Key (${pqcPk} B) + Signature (${pqcSig} B) + Overhead (${limits.certOverhead} B)] = ${pqcCertChain.totalChain} B.`
      },
      {
        id: 'qr',
        name: 'QR Code Capacity',
        desc: `Version 40 QR Code binary capacity at ECC Level ${limits.qrEccLevel}`,
        beforeSize: curQrPayload,
        afterSize: pqcQrPayload,
        limit: qrCap,
        limitUnit: 'B QR capacity',
        status: scQr.status,
        badgeClass: scQr.badgeClass,
        evidence: scQr.evidence,
        usedPct: scQr.usedPct,
        mitigation: buildQrMitigation(limits.qrEccLevel),
        breakdown: `PQC payload ${pqcQrPayload} B vs Version 40 QR Level ${limits.qrEccLevel} max capacity ${qrCap} B.`
      },
      {
        id: 'iot',
        name: 'IoT & Constrained Device Frame',
        desc: `${limits.iotProfile} frame size limit`,
        beforeSize: curSig,
        afterSize: pqcSig,
        limit: iotMtu,
        limitUnit: `B MTU (${pqcIotFrags} frags)`,
        status: scIot.status,
        badgeClass: scIot.badgeClass,
        evidence: scIot.evidence,
        usedPct: scIot.usedPct,
        // IoT-specific display: show packets instead of raw %
        displayLabel: iotBreached ? `${pqcIotFrags} packets needed` : `${scIot.usedPct}% limit`,
        displayPct: iotBreached ? Math.min(100, Math.round(100 * (1 / (pqcSig / iotMtu)))) : scIot.usedPct,
        overLimitText: iotBreached ? `${Math.round(pqcSig / iotMtu)}x over limit` : null,
        pqcIotFrags,
        curIotFrags,
        mitigation: buildIotMitigation(limits.iotProfile, iotMtu, pqcSig, pqcIotFrags, curIotFrags),
        breakdown: `PQC signature ${pqcSig} B divided by ${limits.iotProfile} MTU (${iotMtu} B) requires ${pqcIotFrags} fragment packets.`
      }
    ];

    // Count affected scenarios
    const affectedCount = matrix.filter(m => m.status === 'Confirmed issue' || m.status === 'Estimated risk').length;
    const hasConfirmed = matrix.some(m => m.status === 'Confirmed issue');

    let overallVerdict = 'Safe';
    if (hasConfirmed) overallVerdict = 'Breaking';
    else if (affectedCount > 0) overallVerdict = 'Review';

    return {
      classicalKey,
      pqcKey,
      mode,
      cur,
      pqc,
      curJwt,
      pqcJwt,
      curCertChain,
      pqcCertChain,
      curTlsFlight,
      pqcTlsFlight,
      kpis: {
        pkBefore: curPk,
        pkAfter: pqcPk,
        pkMultiplier: (pqcPk / curPk).toFixed(1),
        sigBefore: curSig,
        sigAfter: pqcSig,
        sigMultiplier: (pqcSig / curSig).toFixed(1),
        affectedScenariosCount: affectedCount,
        verdict: overallVerdict
      },
      matrix
    };
  }

  return {
    ALGO_DATABASE,
    DEFAULT_LIMITS,
    normalizeAlgo,
    getValidReplacements,
    calculateJwt,
    calculateCertChain,
    computeSimulation
  };
})();
