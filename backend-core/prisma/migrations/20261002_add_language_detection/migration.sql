-- Migration: Add language, detection, detection_method columns to Finding
-- Safe to run on existing databases: all columns are nullable with defaults.
-- Old scans will show "Unknown" for language and "AST" for detection.

ALTER TABLE "Finding"
  ADD COLUMN IF NOT EXISTS "detection"         TEXT DEFAULT 'AST',
  ADD COLUMN IF NOT EXISTS "detection_method"  TEXT DEFAULT 'ast',
  ADD COLUMN IF NOT EXISTS "language"          TEXT DEFAULT 'Unknown';
