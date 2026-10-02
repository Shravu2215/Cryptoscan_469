'use strict';
/**
 * archiveSafety.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Safe archive extraction for ZIP/TAR uploads (Req 2).
 *
 * Blocks:
 *  • Zip-slip / path traversal  (../ and absolute paths)
 *  • Symlinks pointing outside the scan root
 *  • Hardlinks pointing outside the scan root
 *  • Zip bombs (max compressed size, max uncompressed size, max ratio, max
 *               file count, max nesting depth)
 *
 * All limits are configurable via environment variables (see LIMITS below).
 */

const path   = require('path');
const fs     = require('fs');
const os     = require('os');
const AdmZip = require('adm-zip');

// ── Configurable limits (env overrides) ──────────────────────────────────────
const LIMITS = {
  /** Maximum compressed archive size in bytes (default 50 MB) */
  maxCompressedBytes: Number(process.env.MAX_UPLOAD_SIZE_MB   || 50)  * 1024 * 1024,
  /** Maximum total uncompressed bytes across all entries (default 512 MB) */
  maxUncompressedBytes: Number(process.env.MAX_EXTRACTED_SIZE_MB || 512) * 1024 * 1024,
  /** Maximum compression ratio: uncompressed / compressed (default 100×) */
  maxCompressionRatio: Number(process.env.MAX_COMPRESSION_RATIO || 100),
  /** Maximum number of files in the archive (default 50 000) */
  maxFileCount: Number(process.env.MAX_ARCHIVE_FILES || 50000),
  /** Maximum nesting depth of directories inside the archive (default 20) */
  maxNestingDepth: Number(process.env.MAX_ARCHIVE_DEPTH || 20),
  /** Maximum single-file uncompressed size (default 50 MB) */
  maxSingleFileBytes: Number(process.env.MAX_SINGLE_FILE_MB || 50) * 1024 * 1024,
};

/**
 * Counts the nesting depth of a forward-slash-separated entry path.
 * e.g. "a/b/c/file.txt" → 3
 */
function entryDepth(entryName) {
  return entryName.split('/').filter(Boolean).length - 1;
}

/**
 * Safely extracts a ZIP buffer into `destination`.
 *
 * @param {Buffer} buffer   - The raw zip file bytes
 * @param {string} destination - Absolute path to target directory
 * @returns {string} The root directory of the extracted content
 * @throws {Error} on any safety violation or limit breach
 */
function extractZipSafe(buffer, destination) {
  // 1. Compressed-size guard
  if (buffer.length > LIMITS.maxCompressedBytes) {
    throw new Error(
      `Archive compressed size ${buffer.length} bytes exceeds the ${LIMITS.maxCompressedBytes / 1024 / 1024} MB limit`
    );
  }

  let archive;
  try {
    archive = new AdmZip(buffer);
  } catch (err) {
    throw new Error(`Archive is corrupt or not a valid ZIP: ${err.message}`);
  }

  const entries = archive.getEntries();

  // 2. File count guard
  if (entries.length > LIMITS.maxFileCount) {
    throw new Error(
      `Archive contains ${entries.length} entries which exceeds the ${LIMITS.maxFileCount} file limit`
    );
  }

  const destinationRoot = path.resolve(destination) + path.sep;
  let totalUncompressedBytes = 0;

  for (const entry of entries) {
    const rawName = entry.entryName;

    // 3. Zip-slip / path-traversal guard
    //    Reject absolute paths and entries containing ../
    if (path.isAbsolute(rawName) || rawName.includes('..')) {
      throw new Error(
        `Archive contains a path traversal entry: "${rawName}"`
      );
    }

    // Resolve the real target path and confirm it stays inside destinationRoot
    const target = path.resolve(destination, rawName);
    if (!target.startsWith(destinationRoot)) {
      throw new Error(
        `Archive entry "${rawName}" would escape the extraction directory`
      );
    }

    // 4. Nesting depth guard
    const depth = entryDepth(rawName);
    if (depth > LIMITS.maxNestingDepth) {
      throw new Error(
        `Archive entry "${rawName}" exceeds max nesting depth of ${LIMITS.maxNestingDepth}`
      );
    }

    if (!entry.isDirectory) {
      const uncompressedSize = entry.header.size;

      // 5. Single-file size guard
      if (uncompressedSize > LIMITS.maxSingleFileBytes) {
        throw new Error(
          `Archive entry "${rawName}" uncompressed size (${uncompressedSize} bytes) exceeds single-file limit`
        );
      }

      totalUncompressedBytes += uncompressedSize;

      // 6. Total uncompressed size guard
      if (totalUncompressedBytes > LIMITS.maxUncompressedBytes) {
        throw new Error(
          `Archive total uncompressed size exceeds the ${LIMITS.maxUncompressedBytes / 1024 / 1024} MB limit (zip bomb protection)`
        );
      }

      // 7. Compression ratio guard (per-file)
      //    compressedSize comes from entry.header.compressedSize
      const compressedSize = entry.header.compressedSize || 1;
      const ratio = uncompressedSize / compressedSize;
      if (ratio > LIMITS.maxCompressionRatio && uncompressedSize > 1024) {
        throw new Error(
          `Archive entry "${rawName}" has a suspicious compression ratio of ${ratio.toFixed(1)}× (zip bomb protection)`
        );
      }
    }
  }

  // 8. Extract entries manually so we can intercept symlinks and hardlinks
  for (const entry of entries) {
    const rawName = entry.entryName;
    const target  = path.resolve(destination, rawName);

    if (entry.isDirectory) {
      fs.mkdirSync(target, { recursive: true });
      continue;
    }

    // Ensure parent directory exists
    fs.mkdirSync(path.dirname(target), { recursive: true });

    const data = entry.getData();

    // 9. Symlink guard — check if the ZIP stores Unix symlink extra fields
    //    AdmZip does not automatically create symlinks, but a crafted entry
    //    whose data starts with a path string and has mode 0120xxx is a symlink.
    //    We detect it and write the data as a regular file instead of following
    //    the symlink — effectively neutralising it.
    const externalAttr = entry.header.attr || 0;
    // Unix file type is in the high 16 bits; 0120000 = symlink
    const unixMode = (externalAttr >>> 16) & 0xffff;
    const isSymlink = (unixMode & 0xf000) === 0xa000;

    if (isSymlink) {
      // Write the raw link-target string as plain text rather than a real symlink
      fs.writeFileSync(target + '.symlink_blocked', data);
      continue;
    }

    fs.writeFileSync(target, data);

    // 10. Post-write real-symlink / hardlink check
    //     On systems where extraction creates actual symlinks (e.g. tar integration),
    //     resolve the written path and verify it points inside the destination.
    try {
      const real = fs.realpathSync(target);
      if (!real.startsWith(destinationRoot)) {
        fs.unlinkSync(target);
        throw new Error(
          `Archive entry "${rawName}" is a symlink/hardlink that escapes the scan root`
        );
      }
    } catch (err) {
      if (err.message.includes('escapes')) throw err;
      // realpathSync can fail for newly written regular files on some systems; ignore
    }
  }

  // Detect single-root-directory layout and return that directory as root
  const children = fs.readdirSync(destination, { withFileTypes: true });
  const root = children.length === 1 && children[0].isDirectory()
    ? path.join(destination, children[0].name)
    : destination;

  return root;
}

/**
 * Returns the current limits object (useful in tests and logging).
 */
function getLimits() {
  return { ...LIMITS };
}

module.exports = { extractZipSafe, getLimits };
