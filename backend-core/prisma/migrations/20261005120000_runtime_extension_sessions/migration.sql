ALTER TABLE "RuntimeRun"
  ADD COLUMN "userId" TEXT NOT NULL DEFAULT '',
  ADD COLUMN "ingestTokenHash" TEXT NOT NULL DEFAULT '',
  ADD COLUMN "targetOrigin" TEXT NOT NULL DEFAULT '',
  ADD COLUMN "cryptoscanOrigin" TEXT NOT NULL DEFAULT '',
  ADD COLUMN "status" TEXT NOT NULL DEFAULT 'ready',
  ADD COLUMN "lastEventAt" TIMESTAMP(3),
  ADD COLUMN "stoppedAt" TIMESTAMP(3);

ALTER TABLE "RuntimeEvent"
  ADD COLUMN "source" TEXT NOT NULL DEFAULT 'crypto',
  ADD COLUMN "keyInfo" TEXT NOT NULL DEFAULT '{}',
  ADD COLUMN "callerScript" TEXT NOT NULL DEFAULT 'unknown:0',
  ADD COLUMN "hostOrigin" TEXT NOT NULL DEFAULT '',
  ADD COLUMN "scheme" TEXT NOT NULL DEFAULT '',
  ADD COLUMN "port" INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN "crossOrigin" BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN "count" INTEGER NOT NULL DEFAULT 1;

ALTER TABLE "Finding"
  ADD COLUMN "source" TEXT NOT NULL DEFAULT 'static',
  ADD COLUMN "sessionId" TEXT,
  ADD COLUMN "operation" TEXT,
  ADD COLUMN "callSite" TEXT,
  ADD COLUMN "mode" TEXT,
  ADD COLUMN "curve" TEXT,
  ADD COLUMN "hash" TEXT,
  ADD COLUMN "observedAt" TIMESTAMP(3),
  ADD COLUMN "count" INTEGER NOT NULL DEFAULT 1;

ALTER TABLE "Finding" ADD CONSTRAINT "Finding_sessionId_fkey"
  FOREIGN KEY ("sessionId") REFERENCES "RuntimeRun"("id") ON DELETE SET NULL ON UPDATE CASCADE;

CREATE INDEX "Finding_sessionId_idx" ON "Finding"("sessionId");
CREATE INDEX "RuntimeRun_userId_status_idx" ON "RuntimeRun"("userId", "status");
CREATE INDEX "RuntimeEvent_runId_source_algorithm_idx" ON "RuntimeEvent"("runId", "source", "algorithm");
