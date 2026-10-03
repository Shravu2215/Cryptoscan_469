-- CreateTable
CREATE TABLE "RuntimeRun" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "scanId" TEXT,
    "language" TEXT NOT NULL,
    "command" TEXT,
    "environment" TEXT NOT NULL DEFAULT 'test',
    "startedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "finishedAt" DATETIME,
    "eventCount" INTEGER NOT NULL DEFAULT 0,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "RuntimeRun_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan" ("id") ON DELETE SET NULL ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "RuntimeEvent" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "eventId" TEXT NOT NULL,
    "runId" TEXT NOT NULL,
    "timestamp" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "language" TEXT NOT NULL,
    "library" TEXT NOT NULL,
    "operation" TEXT NOT NULL,
    "algorithm" TEXT NOT NULL,
    "keySize" INTEGER,
    "mode" TEXT,
    "padding" TEXT,
    "curve" TEXT,
    "callFile" TEXT NOT NULL,
    "callLine" INTEGER NOT NULL,
    "callFunction" TEXT NOT NULL,
    "matchedFindingId" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "RuntimeEvent_runId_fkey" FOREIGN KEY ("runId") REFERENCES "RuntimeRun" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateIndex
CREATE UNIQUE INDEX "RuntimeEvent_eventId_key" ON "RuntimeEvent"("eventId");

-- CreateIndex
CREATE INDEX "RuntimeEvent_runId_algorithm_idx" ON "RuntimeEvent"("runId", "algorithm");
