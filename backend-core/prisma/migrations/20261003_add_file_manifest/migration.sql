-- CreateTable: FileManifestEntry
-- Stores per-file SHA-256 hashes captured at scan time for forensic comparison during verification.
CREATE TABLE IF NOT EXISTS "FileManifestEntry" (
    "id"        TEXT NOT NULL,
    "scanId"    TEXT NOT NULL,
    "filePath"  TEXT NOT NULL,
    "status"    TEXT NOT NULL,
    "sha256"    TEXT,
    "size"      INTEGER,
    "reason"    TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "FileManifestEntry_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX IF NOT EXISTS "FileManifestEntry_scanId_idx" ON "FileManifestEntry"("scanId");
CREATE INDEX IF NOT EXISTS "FileManifestEntry_scanId_filePath_idx" ON "FileManifestEntry"("scanId", "filePath");

-- AddForeignKey
ALTER TABLE "FileManifestEntry" ADD CONSTRAINT "FileManifestEntry_scanId_fkey"
    FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;
