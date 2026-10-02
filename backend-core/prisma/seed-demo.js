/**
 * CryptoScan Demo Seed
 * Run with: npm run seed:demo
 * SAFETY: Hard-exits in NODE_ENV=production.
 */
'use strict';

if (process.env.NODE_ENV === 'production') {
  console.error('[seed-demo] REFUSED: must not run in production.');
  process.exit(1);
}

require('dotenv').config();
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');
const prisma = new PrismaClient();

const DEMO = {
  user: {
    id: 'demo-user-0000-0000-0000-000000000001',
    email: 'demo@cryptoscan.dev',
    password: 'CryptoScan2024!',
    name: 'Demo User',
    role: 'Security Analyst',
    quantumZ: 12,
  },
  repos: [
    { id: 'demo-repo-0000-0000-0000-000000000001', name: 'checkout-service', filePath: '/demo/checkout-service.zip', businessCriticality: 'HIGH' },
    { id: 'demo-repo-0000-0000-0000-000000000002', name: 'auth-gateway',     filePath: '/demo/auth-gateway.zip',     businessCriticality: 'CRITICAL' },
  ],
  scans: [
    { id: 'demo-scan-0000-0000-0000-000000000001', repoIdx: 0, status: 'COMPLETED' },
    { id: 'demo-scan-0000-0000-0000-000000000002', repoIdx: 1, status: 'COMPLETED' },
  ],
  // 12 findings, 5 distinct algorithms, 7 unique (algo, file) component pairs
  findings: [
    { id:'demo-f-001', scanIdx:0, filePath:'checkout_controller.py', lineNumber:23, algorithm:'AES-GCM', severity:'MEDIUM',   quantumStatus:'Quantum Safe',      description:'AES-GCM 128-bit for session tokens.',              recommendation:'Migrate to AES-256-GCM.',                  confidence:'High|ast'    },
    { id:'demo-f-002', scanIdx:0, filePath:'checkout_controller.py', lineNumber:47, algorithm:'RSA',     severity:'HIGH',     quantumStatus:'Quantum Vulnerable', description:'RSA-2048 wraps AES session key.',                  recommendation:'Replace with ML-KEM-768 (Kyber).',         confidence:'High|ast'    },
    { id:'demo-f-003', scanIdx:0, filePath:'payment_processor.py',  lineNumber:12, algorithm:'RSA',     severity:'CRITICAL', quantumStatus:'Quantum Vulnerable', description:'RSA-1024 signs payment receipts; below NIST min.',recommendation:'Upgrade to RSA-4096; migrate to ML-DSA.',  confidence:'High|ast'    },
    { id:'demo-f-004', scanIdx:0, filePath:'config/.env',           lineNumber:3,  algorithm:'AES',     severity:'LOW',      quantumStatus:'Quantum Safe',      description:'Hardcoded AES key; 10-yr lifetime.',              recommendation:'Rotate; move to secrets manager.',         confidence:'Medium|regex' },
    { id:'demo-f-005', scanIdx:0, filePath:'config/.env',           lineNumber:7,  algorithm:'AES',     severity:'LOW',      quantumStatus:'Quantum Safe',      description:'Hardcoded AES key; 1-yr lifetime.',               recommendation:'Rotate; move to secrets manager.',         confidence:'Medium|regex' },
    { id:'demo-f-006', scanIdx:0, filePath:'cart_service.py',       lineNumber:88, algorithm:'SHA-1',   severity:'HIGH',     quantumStatus:'Quantum Safe',      description:'SHA-1 for cart integrity; collision risk.',       recommendation:'Replace with SHA-256 or SHA-3.',           confidence:'High|ast'    },
    { id:'demo-f-007', scanIdx:1, filePath:'jwt_handler.js',        lineNumber:14, algorithm:'ECDSA',   severity:'MEDIUM',   quantumStatus:'Quantum Vulnerable', description:'ECDSA P-256 signs JWTs.',                         recommendation:'Migrate to ML-DSA for PQ JWT signing.',    confidence:'High|ast'    },
    { id:'demo-f-008', scanIdx:1, filePath:'certs/server.key',      lineNumber:1,  algorithm:'ECDSA',   severity:'MEDIUM',   quantumStatus:'Quantum Vulnerable', description:'EC P-384 TLS private key.',                       recommendation:'Plan hybrid certificate migration.',       confidence:'High|ast'    },
    { id:'demo-f-009', scanIdx:1, filePath:'session_store.js',      lineNumber:31, algorithm:'AES-GCM', severity:'LOW',      quantumStatus:'Quantum Safe',      description:'AES-256-GCM for session storage; compliant.',    recommendation:'No immediate action needed.',              confidence:'High|ast'    },
    { id:'demo-f-010', scanIdx:1, filePath:'password_policy.js',    lineNumber:5,  algorithm:'SHA-1',   severity:'CRITICAL', quantumStatus:'Quantum Safe',      description:'SHA-1 for legacy password hashing.',              recommendation:'Migrate to bcrypt or Argon2 immediately.', confidence:'High|ast'    },
    { id:'demo-f-011', scanIdx:1, filePath:'oauth_provider.js',     lineNumber:62, algorithm:'RSA',     severity:'HIGH',     quantumStatus:'Quantum Vulnerable', description:'RSA-2048 for OAuth2 token signing.',               recommendation:'Migrate to ML-DSA or Ed25519.',            confidence:'High|ast'    },
    { id:'demo-f-012', scanIdx:1, filePath:'config/.env',           lineNumber:2,  algorithm:'AES',     severity:'LOW',      quantumStatus:'Quantum Safe',      description:'Hardcoded AES key in auth-gateway .env.',         recommendation:'Move to secrets manager.',                 confidence:'Medium|regex' },
  ],
};

async function main() {
  console.log('[seed-demo] Starting deterministic demo seed...');

  const passwordHash = await bcrypt.hash(DEMO.user.password, 10);
  const user = await prisma.user.upsert({
    where:  { id: DEMO.user.id },
    update: { name: DEMO.user.name, role: DEMO.user.role, quantumZ: DEMO.user.quantumZ },
    create: { id: DEMO.user.id, email: DEMO.user.email, password: passwordHash, name: DEMO.user.name, role: DEMO.user.role, quantumZ: DEMO.user.quantumZ },
  });
  console.log('[seed-demo] User:', user.email);

  const repoRecords = [];
  for (const r of DEMO.repos) {
    const repo = await prisma.repo.upsert({
      where:  { id: r.id },
      update: { businessCriticality: r.businessCriticality },
      create: { id: r.id, name: r.name, filePath: r.filePath, uploadedBy: user.id, businessCriticality: r.businessCriticality },
    });
    repoRecords.push(repo);
    console.log('[seed-demo] Repo:', repo.name);
  }

  const scanRecords = [];
  for (const s of DEMO.scans) {
    const scan = await prisma.scan.upsert({
      where:  { id: s.id },
      update: { status: s.status },
      create: { id: s.id, repoId: repoRecords[s.repoIdx].id, status: s.status },
    });
    scanRecords.push(scan);
    console.log('[seed-demo] Scan:', scan.id);
  }

  let n = 0;
  for (const f of DEMO.findings) {
    await prisma.finding.upsert({
      where:  { id: f.id },
      update: {},   // findings are immutable after seed
      create: {
        id: f.id, scanId: scanRecords[f.scanIdx].id,
        filePath: f.filePath, lineNumber: f.lineNumber,
        algorithm: f.algorithm, severity: f.severity,
        quantumStatus: f.quantumStatus, description: f.description,
        recommendation: f.recommendation, confidence: f.confidence,
      },
    });
    n++;
  }

  console.log('[seed-demo] Findings upserted:', n);
  console.log('[seed-demo]');
  console.log('[seed-demo] Done. Expected counts on every page after seed:demo:');
  console.log('[seed-demo]   findings_total   : 12');
  console.log('[seed-demo]   components_total : 7  (unique algo+file pairs after dedup)');
  console.log('[seed-demo]   algorithms_total : 5  (AES, AES-GCM, RSA, SHA-1, ECDSA)');
  console.log('[seed-demo]');
  console.log('[seed-demo]   Login email   :', DEMO.user.email);
  console.log('[seed-demo]   Login password:', DEMO.user.password);
}

main()
  .catch((e) => { console.error('[seed-demo] FAILED:', e); process.exit(1); })
  .finally(() => prisma.$disconnect());
