# Quantum Risk & Migration Intelligence Contracts

Foundation only: these contracts define payload shapes and validation. Threat calculations, field detection, exposure scoring, and scheduling are not implemented.

## CryptoAsset

```js
{
  assetId: string,       // stable, derived from findingId
  findingId: string,
  algorithm: string,
  family: 'RSA' | 'ECC' | 'DH' | 'AES' | 'HASH' | 'OTHER' | 'PQC',
  keySize: number | null,
  usage: string,
  filePath: string,
  lineNumber: number | null,
  service: string | null,
  confidence: number,    // 0..1
  sources: Array<'static' | 'runtime' | 'network'> // defaults to ['static']
}
```

The adapter uses `finding:<findingId>` for `assetId`. `Confirmed`, `Likely`, and `Possible` map to 1.0, 0.7, and 0.4; recognized numeric confidence and percent strings are clamped to 0..1. Unknown labels map to 0.5. `DSA` currently maps to family `DH` because the agreed family enum has no separate DSA value. `service` uses a top-level `apps/`, `packages/`, or `services/` path segment, otherwise a non-generic top-level directory or finding package/library metadata; it is null when unavailable.

## ThreatScenario And ThreatAssessment

```js
ThreatScenario = {
  id: string,
  name: 'optimistic' | 'median' | 'pessimistic' | 'custom',
  familyTimelines: {
    [family: string]: {
      distribution: 'triangular' | 'normal' | 'lognormal',
      params: { min: number, mode: number, max: number } | { mean: number, sd: number }
    }
  },
  source: string,
  citationNote: string,
  editable: boolean,
  createdBy: string
}

ThreatAssessment = {
  assetId: string, scenarioId: string,
  dataLifetimeYears: number, migrationTimeYears: number,
  pBreakBeforeMigration: number, pMoscaViolated: number,
  p10: number, p50: number, p90: number,
  riskBand: string, iterations: number, seed: number
}
```

Probabilities are validated in [0,1]; percentile values must be ordered. Default scenario parameters are placeholders only; every scenario is marked `ASSUMPTION - editable, cite before final demo`. No external source is claimed.

## SensitiveDataField And DataExposure

```js
SensitiveDataField = {
  fieldId: string,
  dataClass: 'AADHAAR' | 'PAN' | 'PAYMENT_CARD' | 'HEALTH' | 'PII_OTHER',
  location: { filePath: string, line: number } | { schemaTable: string, column: string },
  retentionYears: number,
  retentionSource: 'stated' | 'default' | 'inferred',
  protectedBy: string[], detectionConfidence: number, lineageConfidence: number,
  evidence: string[]
}

DataExposure = {
  fieldId: string, assetId: string, scenarioId: string,
  exposureProbability: number, sensitivityWeight: number,
  retentionYears: number, explanation: string
}
```

Confidence and probability values are validated in [0,1]. Locations must identify a source file and line or a schema table and column.

## MigrationTask And Schedule Contracts

```js
MigrationTask = {
  taskId: string, assetIds: string[], service: string | null,
  effortPersonDays: number, dependsOn: string[], deadline: string | null,
  exposureWeightPerMonth: number
}

ScheduleInput = {
  tasks: MigrationTask[], teamCapacityPerMonth: number,
  horizonMonths: number, scenarioId: string, objective: 'min_exposure'
}

ScheduleResult = {
  waves: Array<{ wave: number, startMonth: number, endMonth: number, taskIds: string[] }>,
  ganttRows: Array<{ taskId: string, startMonth: number, endMonth: number }>,
  totalExposure: number, baselineTotalExposure: number, improvementPct: number,
  solverStatus: string, sensitivity: object[]
}
```

## Persistence And API Boundary

Quantum-risk persistence models carry `scanId` as a string and do not add relations or foreign keys to existing scan/finding models. The adapter is a pure mapper over caller-provided findings; it does not query, mutate, or write findings or CBOMs. New API paths are authenticated and verify scan-repository ownership before returning the temporary 501 response.