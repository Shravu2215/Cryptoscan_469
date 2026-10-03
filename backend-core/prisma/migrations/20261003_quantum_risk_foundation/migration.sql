CREATE TABLE "ThreatScenario" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "familyTimelines" JSONB NOT NULL,
    "source" TEXT NOT NULL,
    "citationNote" TEXT NOT NULL,
    "editable" BOOLEAN NOT NULL DEFAULT true,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "ThreatScenario_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "ThreatAssessment" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "assetId" TEXT NOT NULL,
    "scenarioId" TEXT NOT NULL,
    "dataLifetimeYears" DOUBLE PRECISION NOT NULL,
    "migrationTimeYears" DOUBLE PRECISION NOT NULL,
    "pBreakBeforeMigration" DOUBLE PRECISION NOT NULL,
    "pMoscaViolated" DOUBLE PRECISION NOT NULL,
    "p10" DOUBLE PRECISION NOT NULL,
    "p50" DOUBLE PRECISION NOT NULL,
    "p90" DOUBLE PRECISION NOT NULL,
    "riskBand" TEXT NOT NULL,
    "iterations" INTEGER NOT NULL,
    "seed" INTEGER NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "ThreatAssessment_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "SensitiveDataField" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "fieldId" TEXT NOT NULL,
    "dataClass" TEXT NOT NULL,
    "location" JSONB NOT NULL,
    "retentionYears" DOUBLE PRECISION NOT NULL,
    "retentionSource" TEXT NOT NULL,
    "protectedBy" TEXT[] NOT NULL,
    "detectionConfidence" DOUBLE PRECISION NOT NULL,
    "lineageConfidence" DOUBLE PRECISION NOT NULL,
    "evidence" TEXT[] NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "SensitiveDataField_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "DataExposure" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "fieldId" TEXT NOT NULL,
    "assetId" TEXT NOT NULL,
    "scenarioId" TEXT NOT NULL,
    "exposureProbability" DOUBLE PRECISION NOT NULL,
    "sensitivityWeight" DOUBLE PRECISION NOT NULL,
    "retentionYears" DOUBLE PRECISION NOT NULL,
    "explanation" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "DataExposure_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "MigrationSchedule" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "input" JSONB NOT NULL,
    "result" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "MigrationSchedule_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "ThreatScenario_scanId_idx" ON "ThreatScenario"("scanId");
CREATE INDEX "ThreatAssessment_scanId_idx" ON "ThreatAssessment"("scanId");
CREATE INDEX "ThreatAssessment_scanId_scenarioId_idx" ON "ThreatAssessment"("scanId", "scenarioId");
CREATE INDEX "SensitiveDataField_scanId_idx" ON "SensitiveDataField"("scanId");
CREATE INDEX "DataExposure_scanId_idx" ON "DataExposure"("scanId");
CREATE INDEX "DataExposure_scanId_scenarioId_idx" ON "DataExposure"("scanId", "scenarioId");
CREATE INDEX "MigrationSchedule_scanId_idx" ON "MigrationSchedule"("scanId");