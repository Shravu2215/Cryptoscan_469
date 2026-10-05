-- CryptoTwin DB Migration
-- Non-destructive: adds new tables only; never modifies existing ones.

CREATE TABLE IF NOT EXISTS "CryptoTwinRun" (
  "id"           TEXT NOT NULL PRIMARY KEY,
  "scanId"       TEXT,
  "userId"       TEXT NOT NULL,
  "repoName"     TEXT NOT NULL DEFAULT '',
  "source"       TEXT NOT NULL DEFAULT 'direct',   -- 'direct' | 'uploaded'
  "status"       TEXT NOT NULL DEFAULT 'PENDING',   -- PENDING | RUNNING | DONE | FAILED
  "inputJson"    TEXT NOT NULL DEFAULT '{}',        -- serialized CryptoTwinInput
  "stagesJson"   TEXT NOT NULL DEFAULT '[]',        -- array of stage status objects
  "attackPaths"  TEXT NOT NULL DEFAULT '[]',        -- array of attack path objects
  "testsJson"    TEXT NOT NULL DEFAULT '[]',        -- array of test result objects
  "patchLog"     TEXT NOT NULL DEFAULT '[]',        -- array of {file,before,after} patch entries
  "aiIterations" TEXT NOT NULL DEFAULT '[]',        -- array of AI fix attempts
  "verdict"      TEXT,                              -- PRODUCTION_READY | PRODUCTION_NOT_READY | INCONCLUSIVE
  "confidence"   FLOAT,                             -- 0-100 confidence score
  "blockers"     TEXT NOT NULL DEFAULT '[]',        -- list of blocker strings
  "approval"     TEXT,                              -- APPROVED | APPROVED_WITH_OVERRIDE | REJECTED | PENDING_REVIEW
  "approvalBy"   TEXT,
  "approvalAt"   TIMESTAMP(3),
  "approvalNote" TEXT,
  "overrideReason" TEXT,
  "reportJson"   TEXT,
  "errorMessage" TEXT,
  "createdAt"    TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt"    TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS "CryptoTwinRun_scanId_idx" ON "CryptoTwinRun"("scanId");
CREATE INDEX IF NOT EXISTS "CryptoTwinRun_userId_idx" ON "CryptoTwinRun"("userId");
