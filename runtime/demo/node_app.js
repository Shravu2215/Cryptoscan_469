/**
 * CryptoScan Runtime Demo Application (Node.js)
 * Demonstrates active runtime cryptographic execution paths alongside unexecuted static paths.
 */

const crypto = require('crypto');

function runExecutedCryptoPaths() {
  console.log('[Node Demo] Executing SHA-256...');
  const hash = crypto.createHash('sha256').update('sample_data').digest('hex');

  console.log('[Node Demo] Executing AES-256-GCM...');
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.update('secret_payload', 'utf8');
  cipher.final();

  console.log('[Node Demo] Executing RSA-2048 KeyGen & Sign...');
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
  });
  const signer = crypto.createSign('SHA256');
  signer.update('data_to_sign');
  signer.end();
  const signature = signer.sign(privateKey);

  console.log('[Node Demo] Executing ECDSA P-256 KeyGen...');
  crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
  });

  console.log('[Node Demo] All executed paths completed successfully.');
}

function unexecutedStaticOnlyPath() {
  /**
   * This function contains a vulnerable legacy MD5 call
   * that is NEVER executed at runtime.
   */
  if (false) {
    const md5Hash = crypto.createHash('md5').update('weak_password').digest('hex');
    return md5Hash;
  }
}

runExecutedCryptoPaths();
