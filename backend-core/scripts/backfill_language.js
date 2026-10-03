'use strict';
/**
 * backfill_language.js
 * Run once after deploying the language-detection fix:
 *   node backend-core/scripts/backfill_language.js
 * Safe: only overwrites language where it is null, '', or 'Unknown'.
 */

require('dotenv').config({ path: require('path').join(__dirname, '../.env') });
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

const EXACT_FILENAMES = {
  '.env': 'Dotenv', '.envrc': 'Dotenv', 'dockerfile': 'Dockerfile',
  'makefile': 'Makefile', 'gnumakefile': 'Makefile', 'cmakelists.txt': 'CMake',
  'nginx.conf': 'Nginx config', 'httpd.conf': 'Apache config',
  'apache2.conf': 'Apache config', 'openssl.cnf': 'OpenSSL config',
  'openssl.conf': 'OpenSSL config', 'docker-compose.yml': 'Docker Compose',
  'docker-compose.yaml': 'Docker Compose', 'compose.yml': 'Docker Compose',
  'compose.yaml': 'Docker Compose', 'pipfile': 'Pipfile',
  'pyproject.toml': 'pyproject.toml', 'requirements.txt': 'pip requirements',
  'setup.py': 'Python', 'go.mod': 'Go module', 'go.sum': 'Go module',
  'cargo.toml': 'Cargo.toml', 'cargo.lock': 'Cargo.toml',
  'gemfile': 'Gemfile', 'gemfile.lock': 'Gemfile',
  'composer.json': 'composer.json', 'composer.lock': 'composer.json',
  'package.json': 'Node (package.json)', 'package-lock.json': 'Node (package.json)',
  'yarn.lock': 'Node (package.json)', 'pom.xml': 'Maven POM',
  'build.gradle': 'Gradle', 'build.gradle.kts': 'Gradle',
  'jenkinsfile': 'Jenkinsfile', 'procfile': 'Procfile', 'vagrantfile': 'Vagrantfile',
  '.htaccess': 'Apache config', 'known_hosts': 'SSH config',
  'authorized_keys': 'SSH key', '.npmrc': 'npm config',
  'sshd_config': 'SSH config', 'ssh_config': 'SSH config',
  'ipsec.conf': 'IPsec config', 'ipsec.secrets': 'IPsec config',
};

const PREFIX_PATTERNS = [
  { prefix: 'dockerfile.', lang: 'Dockerfile' },
  { prefix: 'requirements', lang: 'pip requirements' },
  { prefix: '.env.', lang: 'Dotenv' },
];

const EXTENSIONS = {
  '.py': 'Python', '.pyw': 'Python', '.pyi': 'Python',
  '.js': 'JavaScript', '.mjs': 'JavaScript', '.cjs': 'JavaScript', '.jsx': 'JSX',
  '.ts': 'TypeScript', '.tsx': 'TSX',
  '.java': 'Java', '.kt': 'Kotlin', '.kts': 'Kotlin', '.scala': 'Scala',
  '.go': 'Go', '.rs': 'Rust',
  '.c': 'C', '.h': 'C', '.cc': 'C++', '.cpp': 'C++', '.cxx': 'C++',
  '.hh': 'C++', '.hpp': 'C++',
  '.cs': 'C#', '.swift': 'Swift', '.dart': 'Dart', '.php': 'PHP',
  '.rb': 'Ruby', '.rake': 'Ruby', '.pl': 'Perl', '.pm': 'Perl',
  '.sh': 'Bash/Shell', '.bash': 'Bash/Shell', '.zsh': 'Zsh',
  '.ps1': 'PowerShell', '.psm1': 'PowerShell', '.psd1': 'PowerShell',
  '.tf': 'Terraform/HCL', '.tfvars': 'Terraform/HCL', '.hcl': 'Terraform/HCL',
  '.yaml': 'YAML', '.yml': 'YAML', '.xml': 'XML', '.json': 'JSON',
  '.toml': 'TOML', '.ini': 'INI', '.cfg': 'INI', '.conf': 'Config file',
  '.env': 'Dotenv', '.properties': 'Properties',
  '.crt': 'Certificate', '.cer': 'Certificate', '.pem': 'Certificate',
  '.der': 'Certificate', '.key': 'Private key', '.p12': 'PKCS#12',
  '.pfx': 'PKCS#12', '.jks': 'Java Keystore', '.csr': 'CSR', '.pub': 'SSH key',
  '.sql': 'SQL', '.html': 'HTML', '.htm': 'HTML', '.css': 'CSS',
  '.scss': 'SCSS', '.vue': 'Vue', '.svelte': 'Svelte',
  '.proto': 'Protobuf', '.graphql': 'GraphQL', '.gql': 'GraphQL',
  '.sol': 'Solidity', '.gradle': 'Gradle', '.bat': 'Batch', '.cmd': 'Batch',
};

function detectLanguageFromPath(filePath) {
  if (!filePath) return null;
  const normalized = filePath.replace(/\\/g, '/');
  const bn = normalized.split('/').pop();
  const bnLower = bn.toLowerCase();
  const lastDot = bn.lastIndexOf('.');
  const extSimple = lastDot === -1 ? '' : bn.slice(lastDot).toLowerCase();

  if (EXACT_FILENAMES[bn]) return EXACT_FILENAMES[bn];
  if (EXACT_FILENAMES[bnLower]) return EXACT_FILENAMES[bnLower];

  for (const { prefix, lang } of PREFIX_PATTERNS) {
    if (bnLower.startsWith(prefix)) return lang;
  }

  if (extSimple && EXTENSIONS[extSimple]) return EXTENSIONS[extSimple];
  return null;
}

async function main() {
  const BATCH = 200;
  let updated = 0;
  let skip = 0;
  console.log('backfill_language.js — starting...');
  while (true) {
    const rows = await prisma.finding.findMany({
      where: { OR: [{ language: null }, { language: '' }, { language: 'Unknown' }] },
      select: { id: true, filePath: true },
      skip,
      take: BATCH,
      orderBy: { createdAt: 'asc' },
    });
    if (rows.length === 0) break;
    for (const row of rows) {
      const lang = detectLanguageFromPath(row.filePath);
      if (lang) {
        await prisma.finding.update({ where: { id: row.id }, data: { language: lang } });
        updated++;
      }
    }
    skip += rows.length;
    process.stdout.write(`\r  processed ${skip} rows, updated ${updated} so far...`);
  }
  console.log(`\nbackfill_language.js — done. Updated ${updated} findings.`);
  await prisma.$disconnect();
}

main().catch(async (e) => {
  console.error(e);
  await prisma.$disconnect();
  process.exit(1);
});
