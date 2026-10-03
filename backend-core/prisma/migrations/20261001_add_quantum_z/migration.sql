-- AlterTable: add businessCriticality column to Repo (missing from 0_init migration)
ALTER TABLE "Repo" ADD COLUMN IF NOT EXISTS "businessCriticality" TEXT NOT NULL DEFAULT 'Not tagged';

-- AlterTable
-- Temporary store for user's Mosca threat horizon Z; moves to organisation model later
ALTER TABLE "User" ADD COLUMN IF NOT EXISTS "quantumZ" INTEGER NOT NULL DEFAULT 12;
