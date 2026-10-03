# Living Threat Model

This document describes the pure engine in `backend-core/src/services/quantumRisk/threatModel/`. It performs no database access and does not mutate assets or scenarios.

## Variables And Events

- `Z` is years until the modeled algorithm family is breakable by a cryptographically relevant quantum computer. It is sampled from a scenario's family distribution and clamped to `Z >= 0`.
- `X` is the number of years protected data must remain secret. `Y` is years to complete migration.
- Mosca is violated when `X + Y > Z`.
- `pMoscaViolated = P(X + Y > Z)` models harvest-now-decrypt-later exposure.
- `pBreakBeforeMigration = P(Z < Y)` models an algorithm becoming breakable before migration finishes.
- For signature/auth/JWT/certificate usage, the engine forces `X = 0` and sets `pMoscaViolated` to the same event as `pBreakBeforeMigration`.

For continuous `Z`, `P(Z < T)` is the distribution CDF `F_Z(T)`; point equality has probability zero. Sampling uses the strict comparison `Z < T`, matching the strict Mosca inequality. The deterministic helper returns `marginYears = Z - (X + Y)`, so positive is remaining runway and negative is an exceeded horizon.

## Sampling And Reproducibility

The engine uses Mulberry32, seeded with `options.seed` (default `42`), and Box-Muller for normal variates. Triangular parameters are `min`, `mode`, `max`. Normal parameters are arithmetic `mean` and `sd`. Lognormal parameters are arithmetic mean and standard deviation, converted to the corresponding log-space parameters before sampling. Normal and shifted triangular samples may be negative before the final `Z >= 0` clamp.

One `Float64Array` of samples is generated per family per scenario and reused across all assets of that family (common random numbers). Asset thresholds and key-size multipliers are applied in O(iterations), without allocating objects inside the sampling loop. The 95% confidence interval is the clamped Wald/binomial normal approximation `p ± 1.96 * sqrt(p * (1-p) / n)`. For deterministic pure-function output, `meta.generatedAt` is `null` unless the caller supplies `options.generatedAt`.

Each assessment includes `pBreakBeforeMigrationCI95` and `pMoscaViolatedCI95`, each shaped as `{ lower, upper }`. It also includes `lowConfidenceFamily: true` when OTHER or a family missing from that scenario uses the conservative fallback timeline.

## Family And Key-Size Handling

PQC returns exact zero probabilities, confidence bounds, and `Z` percentiles without sampling. RSA, ECC, and DH use Shor-class scenario timelines. AES and HASH use Grover-class timelines with finite, larger default horizons; key-size multipliers make shorter AES keys earlier/less secure. OTHER uses the conservative `triangular(1, 4, 12)` fallback and sets `lowConfidenceFamily: true`.

All multipliers below are editable **ASSUMPTIONs**, not measured quantum resource estimates. RSA/DH use a modest delay for larger classical keys; key-size multipliers scale the sampled Z and its reported percentiles.

| Family/key size | Z multiplier | Rationale |
|---|---:|---|
| RSA/DH below 2048 | 0.98 | Slight earlier-break nudge |
| RSA/DH 2048-3071 | 1.00 | Baseline |
| RSA/DH 3072-4095 | 1.03 | Small later-break nudge |
| RSA/DH 4096+ | 1.05 | Conservative small later-break nudge |
| AES below 128 | 0.45 | Weak Grover margin |
| AES 128-191 | 0.60 | AES-128 weaker than AES-256 |
| AES 192-255 | 0.80 | Intermediate margin |
| AES 256+ | 1.00 | Large finite scenario horizon |
| HASH below 256 | 0.70 | Short-output conservative margin |
| HASH 256+ | 1.00 | Large finite scenario horizon |
| Unknown AES/HASH key size | 0.55 / 0.70 | Conservative fallback |

Missing family scenario entries use the same OTHER fallback timeline. DH also accepts the scenario key `DH/DSA`; the asset family enum has no standalone DSA value.

## Default X And Y Assumptions

Every default is tagged `source: 'ASSUMPTION'` with a rationale in `mosca.js`. Asset-level `options.overrides[assetId]` may replace either value. Signature/auth/JWT/certificate usage always forces X to zero, even if an X override is supplied.

| Usage | Default X, years |
|---|---:|
| key_exchange, key_wrap, encryption, data_encryption | 20 |
| digital_signature, signature, auth, jwt, certificate, mac | 0 |
| integrity_hashing | 10 |
| unknown | 10 |

| Usage group | RSA | ECC | DH | AES | HASH | OTHER | PQC |
|---|---:|---:|---:|---:|---:|---:|---:|
| key_exchange / key_wrap | 2.5 | 2 | 2.5 | 1.5 | 1 | 4 | 0.5 |
| encryption / data_encryption | 2 | 2 | 2 | 1.5 | 1 | 4 | 0.5 |
| digital_signature / signature / auth / jwt / certificate | 3 | 3 | 2.5 | 1.5 | 1.5 | 4 | 0.5 |
| integrity_hashing | 2 | 2 | 2 | 1.5 | 1 | 4 | 0.5 |
| mac | 2 | 2 | 2 | 1.5 | 1.5 | 4 | 0.5 |
| unknown | 3 | 3 | 3 | 2 | 2 | 4 | 0.5 |

These durations are planning defaults only. Replace them with organization-specific inventory, staffing, dependency, and migration evidence before presenting results as forecasts.

## Risk Bands

`riskBandFromProbability` uses editable thresholds in `mosca.js`: `p < 0.01` MINIMAL; `< 0.05` LOW; `< 0.20` MODERATE; `< 0.50` HIGH; otherwise CRITICAL. Exact boundaries move into the next band.

## Aggregation And Sensitivity

`assessThreat` returns per-scenario per-asset assessments. `expectedAssetsViolated` is the sum of asset `pMoscaViolated` values (expected count, not probability of at least one asset); `meanP` is the unweighted mean and `maxP` is the maximum. Heatmap service/family rows use the arithmetic mean of the selected probability for assets in that group; asset rows retain their own probability. Arrival sweeps shift only distribution location parameters; standard deviations stay fixed. Lognormal arithmetic means are clamped to a positive epsilon if a negative arrival shift crosses zero, and sampled Z remains clamped at zero.

## Scientific Limitations

The default scenario timelines, key-size multipliers, X/Y durations, risk bands, and Grover family horizons are explicitly provisional assumptions. They are not sourced CRQC forecasts. A family-wide Z ignores implementation, circuit, error-correction, and attacker-resource variation; common random numbers create within-family consistency, not evidence of real-world correlation. A normal-approximation interval is unreliable for very small sample sizes or probabilities near 0/1. The current model does not include algorithm-specific quantum resource estimates, migration dependencies, or calibrated likelihood data. Keep all demo claims labeled as assumptions until those inputs are sourced and reviewed.