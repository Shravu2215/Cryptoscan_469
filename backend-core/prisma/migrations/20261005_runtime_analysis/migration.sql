CREATE TABLE "RuntimeSession" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "ingestTokenHash" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'recording',
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "stoppedAt" TIMESTAMP(3),
    "eventCount" INTEGER NOT NULL DEFAULT 0,
    CONSTRAINT "RuntimeSession_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "RuntimeObservedEvent" (
    "id" TEXT NOT NULL,
    "sessionId" TEXT NOT NULL,
    "algorithm" TEXT NOT NULL,
    "operation" TEXT NOT NULL,
    "keyInfo" TEXT NOT NULL,
    "callSite" TEXT NOT NULL,
    "language" TEXT NOT NULL DEFAULT 'JavaScript',
    "count" INTEGER NOT NULL DEFAULT 1,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "RuntimeObservedEvent_pkey" PRIMARY KEY ("id")
);

ALTER TABLE "RuntimeSession" ADD CONSTRAINT "RuntimeSession_scanId_key" UNIQUE ("scanId");
ALTER TABLE "RuntimeSession" ADD CONSTRAINT "RuntimeSession_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "RuntimeObservedEvent" ADD CONSTRAINT "RuntimeObservedEvent_sessionId_fkey" FOREIGN KEY ("sessionId") REFERENCES "RuntimeSession"("id") ON DELETE CASCADE ON UPDATE CASCADE;
CREATE UNIQUE INDEX "RuntimeObservedEvent_sessionId_algorithm_operation_keyInfo_callSite_key" ON "RuntimeObservedEvent"("sessionId", "algorithm", "operation", "keyInfo", "callSite");
CREATE INDEX "RuntimeObservedEvent_sessionId_algorithm_idx" ON "RuntimeObservedEvent"("sessionId", "algorithm");

ALTER TABLE "Finding" ADD COLUMN "source" TEXT NOT NULL DEFAULT 'static';
ALTER TABLE "Finding" ADD COLUMN "operation" TEXT;
ALTER TABLE "Finding" ADD COLUMN "callSite" TEXT;
ALTER TABLE "Finding" ADD COLUMN "mode" TEXT;
ALTER TABLE "Finding" ADD COLUMN "curve" TEXT;
ALTER TABLE "Finding" ADD COLUMN "hash" TEXT;
ALTER TABLE "Finding" ADD COLUMN "observedAt" TIMESTAMP(3);
ALTER TABLE "Finding" ADD COLUMN "count" INTEGER NOT NULL DEFAULT 1;
