-- AlterTable
-- Temporary store for user's Mosca threat horizon Z; moves to organisation model later
ALTER TABLE "User" ADD COLUMN IF NOT EXISTS "quantumZ" INTEGER NOT NULL DEFAULT 12;
