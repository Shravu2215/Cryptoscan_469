-- CreateTable (PostgreSQL syntax — converted from SQLite draft)
CREATE TABLE "RuntimeRun" (
    "id" TEXT NOT NULL,
    "scanId" TEXT,
    "language" TEXT NOT NULL,
    "command" TEXT,
    "environment" TEXT NOT NULL DEFAULT 'test',
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "finishedAt" TIMESTAMP(3),
    "eventCount" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "RuntimeRun_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RuntimeEvent" (
    "id" TEXT NOT NULL,
    "eventId" TEXT NOT NULL,
    "runId" TEXT NOT NULL,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
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
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "RuntimeEvent_pkey" PRIMARY KEY ("id")
);

-- AddForeignKey
ALTER TABLE "RuntimeRun" ADD CONSTRAINT "RuntimeRun_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "RuntimeEvent" ADD CONSTRAINT "RuntimeEvent_runId_fkey" FOREIGN KEY ("runId") REFERENCES "RuntimeRun"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- CreateIndex
CREATE UNIQUE INDEX "RuntimeEvent_eventId_key" ON "RuntimeEvent"("eventId");

-- CreateIndex
CREATE INDEX "RuntimeEvent_runId_algorithm_idx" ON "RuntimeEvent"("runId", "algorithm");
