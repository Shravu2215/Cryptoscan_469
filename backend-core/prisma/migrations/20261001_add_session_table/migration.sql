-- Migration: add Session table for refresh-token rotation and server-side revocation
-- Safe to run multiple times (all statements are idempotent).

CREATE TABLE IF NOT EXISTS "Session" (
    "id"               TEXT      NOT NULL,
    "jti"              TEXT      NOT NULL,
    "userId"           TEXT      NOT NULL,
    "refreshTokenHash" TEXT      NOT NULL,
    "expiresAt"        TIMESTAMP(3) NOT NULL,
    "revokedAt"        TIMESTAMP(3),
    "createdAt"        TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Session_pkey" PRIMARY KEY ("id")
);

-- Unique index on jti (used for O(1) lookup on every refresh call)
CREATE UNIQUE INDEX IF NOT EXISTS "Session_jti_key" ON "Session"("jti");

-- Index for fetching all sessions by user (e.g. logout-all-devices)
CREATE INDEX IF NOT EXISTS "Session_userId_idx" ON "Session"("userId");

-- Foreign key to User
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'Session_userId_fkey'
  ) THEN
    ALTER TABLE "Session" ADD CONSTRAINT "Session_userId_fkey"
      FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
  END IF;
END $$;
