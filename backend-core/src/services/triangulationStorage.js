'use strict';

/**
 * Data Access Object (DAO) for Network Captures and Triangulation Results.
 * Uses Prisma Client.
 */

const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

const memoryTriangulation = new Map(); // scanId -> array of results
const memoryCaptures = []; // array of captures

/**
 * Creates a NetworkCapture record with observations.
 */
async function createNetworkCapture(data) {
  try {
    return await prisma.networkCapture.create({
      data: {
        id: data.id || undefined,
        scanId: data.scanId || null,
        source: data.source || 'json',
        fileName: data.fileName || null,
        observations: {
          create: (data.observations || []).map((o) => ({
            host: o.host || null,
            port: o.port ? parseInt(o.port, 10) : null,
            protocol: o.protocol || 'TLS',
            protocolVersion: o.protocolVersion || o.protocol_version || 'TLSv1.3',
            cipherSuite: o.cipherSuite || o.cipher_suite || null,
            keyExchange: o.keyExchange || o.key_exchange || null,
            signatureAlgorithm: o.signatureAlgorithm || o.signature_algorithm || null,
            certificateKeyType: o.certificateKeyType || o.certificate_key_type || null,
            certificateKeySize: o.certificateKeySize !== undefined ? o.certificateKeySize : (o.certificate_key_size || null),
            normalizedAlgorithms: o.normalizedAlgorithms || o.normalized_algorithms || [],
            quantumVulnerable: Boolean(o.quantumVulnerable || o.quantum_vulnerable),
          })),
        },
      },
      include: {
        observations: true,
      },
    });
  } catch (err) {
    // In-memory fallback
    const capture = {
      id: data.id || 'cap-' + Date.now(),
      scanId: data.scanId || null,
      source: data.source || 'json',
      fileName: data.fileName || null,
      observations: data.observations || [],
      createdAt: new Date(),
    };
    memoryCaptures.push(capture);
    return capture;
  }
}

/**
 * Lists network captures for a scan.
 */
async function listNetworkCaptures(scanId = null, limit = 50) {
  try {
    const where = scanId ? { scanId } : {};
    return await prisma.networkCapture.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      take: limit,
      include: {
        observations: true,
      },
    });
  } catch (err) {
    let filtered = memoryCaptures;
    if (scanId) {
      filtered = filtered.filter((c) => c.scanId === scanId);
    }
    return filtered.slice(0, limit);
  }
}

/**
 * Bulk-saves triangulation results for a scan.
 */
async function saveTriangulationResults(scanId, results, runIds = [], captureIds = []) {
  if (!results || results.length === 0) return [];

  const records = results.map((r) => ({
    scanId,
    runIds,
    captureIds,
    algorithm: r.algorithm || 'UNKNOWN',
    keySize: r.keySize !== undefined ? r.keySize : (r.key_size || null),
    classification: r.classification || 'Static Only',
    confidence: r.confidence || 'medium',
    confidenceReason: r.confidenceReason || r.confidence_reason || '',
    coverageNote: r.coverageNote || r.coverage_note || '',
    possibleStaticFalseNegative: Boolean(r.possibleStaticFalseNegative || r.possible_static_false_negative),
    quantumVulnerable: Boolean(r.quantumVulnerable || r.quantum_vulnerable),
    staticFindingId: r.staticFindingId || r.static_finding_id || null,
    location: r.location || '',
    evidence: r.evidence || [],
  }));

  try {
    await prisma.triangulationResult.deleteMany({
      where: { scanId },
    });

    await prisma.triangulationResult.createMany({
      data: records,
    });

    return await prisma.triangulationResult.findMany({
      where: { scanId },
      orderBy: { createdAt: 'desc' },
    });
  } catch (err) {
    // In-memory fallback
    memoryTriangulation.set(scanId, records);
    console.warn('[TriangulationStorage] PostgreSQL DB unreachable; falling back to in-memory storage:', err.message);
    return records;
  }
}

/**
 * Gets triangulation results for a scan with optional classification filter.
 */
async function getTriangulationResults(scanId, classification = null) {
  try {
    const where = { scanId };
    if (classification) {
      where.classification = classification;
    }
    return await prisma.triangulationResult.findMany({
      where,
      orderBy: { createdAt: 'asc' },
    });
  } catch (err) {
    let list = memoryTriangulation.get(scanId) || [];
    if (classification) {
      list = list.filter((r) => r.classification === classification);
    }
    return list;
  }
}

/**
 * Computes summary card statistics for a scan's triangulation results.
 */
async function getTriangulationSummary(scanId) {
  let results = [];
  try {
    results = await prisma.triangulationResult.findMany({
      where: { scanId },
    });
  } catch (err) {
    results = memoryTriangulation.get(scanId) || [];
  }

  const summary = {
    totalFindings: results.length,
    counts: {
      'Confirmed Active': 0,
      'Static Only': 0,
      'Runtime Only': 0,
      'Network Only': 0,
    },
    quantumVulnerableCount: 0,
    possibleFalseNegatives: 0,
  };

  for (const r of results) {
    if (summary.counts[r.classification] !== undefined) {
      summary.counts[r.classification]++;
    }

    if (r.quantumVulnerable) summary.quantumVulnerableCount++;
    if (r.possibleStaticFalseNegative) summary.possibleFalseNegatives++;
  }

  return summary;
}

module.exports = {
  prisma,
  createNetworkCapture,
  listNetworkCaptures,
  saveTriangulationResults,
  getTriangulationResults,
  getTriangulationSummary,
};
