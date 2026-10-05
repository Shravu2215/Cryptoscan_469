'use strict';

/**
 * CryptoShield Store & Demo Data Seeder
 * Manages Crypto Asset Identities, Access Policies, Security Events, Recovery Plans,
 * and Audit Trails using Prisma ORM with devStore fallback.
 * NEVER stores raw private keys/secrets — uses SHA-256 fingerprints only.
 */

const crypto = require('crypto');
const prisma = require('../utils/prismaClient');
const devStore = require('../utils/devStore');

/**
 * Helper to generate a safe one-way SHA-256 fingerprint preview (e.g. 8f3a...9bd)
 */
function generateSafeFingerprint(assetId) {
  const hash = crypto.createHash('sha256').update(`cryptoshield-salt-${assetId}`).digest('hex');
  return `${hash.substring(0, 8)}...${hash.substring(hash.length - 4)}`;
}

/**
 * Seed initial DEMO data if store is empty
 */
async function seedDemoDataIfEmpty() {
  const existingAssets = devStore.getShieldAssets();
  if (existingAssets && existingAssets.length > 0) {
    return;
  }

  const demoAssets = [
    {
      assetId: 'Payment-Key-01',
      assetType: 'PRIVATE_KEY',
      fingerprint: generateSafeFingerprint('Payment-Key-01'),
      algorithm: 'RSA-2048',
      application: 'Payment Service',
      environment: 'production',
      owner: 'Payments SecOps',
      sourceFile: 'src/services/paymentCrypto.js',
      sourceLine: 42,
      criticality: 'CRITICAL',
      allowedServices: ['Payment Service', 'Payment API Gateway'],
      status: 'PROTECTED',
      createdAt: new Date(Date.now() - 7 * 24 * 3600 * 1000).toISOString()
    },
    {
      assetId: 'Authentication-Key-01',
      assetType: 'TOKEN_SIGNER',
      fingerprint: generateSafeFingerprint('Authentication-Key-01'),
      algorithm: 'ECDSA-P256',
      application: 'Authentication Service',
      environment: 'production',
      owner: 'Identity Team',
      sourceFile: 'src/auth/jwtSigner.js',
      sourceLine: 18,
      criticality: 'CRITICAL',
      allowedServices: ['Authentication Service'],
      status: 'PROTECTED',
      createdAt: new Date(Date.now() - 5 * 24 * 3600 * 1000).toISOString()
    },
    {
      assetId: 'TLS-Certificate-01',
      assetType: 'CERTIFICATE',
      fingerprint: generateSafeFingerprint('TLS-Certificate-01'),
      algorithm: 'ECDH-P256 / TLS-1.3',
      application: 'Notification Service',
      environment: 'production',
      owner: 'Infra Ops',
      sourceFile: 'config/tls/cert.pem',
      sourceLine: 1,
      criticality: 'HIGH',
      allowedServices: ['Notification Service', 'Authentication Service'],
      status: 'PROTECTED',
      createdAt: new Date(Date.now() - 3 * 24 * 3600 * 1000).toISOString()
    },
    {
      assetId: 'API-Credential-01',
      assetType: 'API_CREDENTIAL',
      fingerprint: generateSafeFingerprint('API-Credential-01'),
      algorithm: 'AES-256-GCM',
      application: 'Developer Tool',
      environment: 'staging',
      owner: 'DevOps',
      sourceFile: 'src/config/apiCreds.js',
      sourceLine: 88,
      criticality: 'MEDIUM',
      allowedServices: ['Developer Tool', 'Notification Service'],
      status: 'PROTECTED',
      createdAt: new Date(Date.now() - 1 * 24 * 3600 * 1000).toISOString()
    }
  ];

  demoAssets.forEach(asset => devStore.saveShieldAsset(asset));

  // Seed Policies
  const demoPolicies = [
    {
      id: 'pol-1',
      assetId: 'Payment-Key-01',
      allowedService: 'Payment Service',
      allowedOperations: ['SIGN', 'DECRYPT'],
      environment: 'production',
      status: 'ACTIVE',
      createdAt: new Date().toISOString()
    },
    {
      id: 'pol-2',
      assetId: 'Authentication-Key-01',
      allowedService: 'Authentication Service',
      allowedOperations: ['SIGN', 'VERIFY'],
      environment: 'production',
      status: 'ACTIVE',
      createdAt: new Date().toISOString()
    },
    {
      id: 'pol-3',
      assetId: 'TLS-Certificate-01',
      allowedService: 'Notification Service',
      allowedOperations: ['ENCRYPT', 'DECRYPT'],
      environment: 'production',
      status: 'ACTIVE',
      createdAt: new Date().toISOString()
    }
  ];

  demoPolicies.forEach(policy => devStore.saveShieldPolicy(policy));

  // Seed Initial Security Event (Simulated Attempt)
  const demoEvents = [
    {
      eventId: 'evt-demo-101',
      timestamp: new Date(Date.now() - 3600 * 1000).toISOString(),
      assetId: 'Payment-Key-01',
      requestingApplication: 'Unknown Service',
      requestedOperation: 'DECRYPT',
      environment: 'production',
      decision: 'BLOCKED',
      reason: 'Unauthorized requesting application "Unknown Service" is not in allowed services policy.',
      severity: 'CRITICAL'
    },
    {
      eventId: 'evt-demo-102',
      timestamp: new Date(Date.now() - 1800 * 1000).toISOString(),
      assetId: 'Authentication-Key-01',
      requestingApplication: 'Authentication Service',
      requestedOperation: 'SIGN',
      environment: 'production',
      decision: 'ALLOWED',
      reason: 'Access policy verified for Authentication Service (SIGN operation).',
      severity: 'LOW'
    }
  ];

  demoEvents.forEach(evt => devStore.saveShieldEvent(evt));

  // Initial Audit Trail
  devStore.addShieldAudit({
    action: 'INITIALIZE_CRYPTOSHIELD_DEMO',
    user: 'System Admin',
    assetId: 'Payment-Key-01',
    result: 'SUCCESS',
    details: 'Seeded initial Crypto Asset Identities and Access Policies.'
  });
}

// Ensure seed data is initialized
seedDemoDataIfEmpty().catch(err => console.warn('Demo data seed warning:', err.message));

module.exports = {
  seedDemoDataIfEmpty,
  generateSafeFingerprint
};
