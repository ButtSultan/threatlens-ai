-- ThreatLens AI - Database Initialization
-- This runs once when the PostgreSQL container is first created.

-- Ensure the database exists (already created by POSTGRES_DB env var)
-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";  -- For full-text search optimization

-- The tables are created by Alembic migrations at app startup.
-- This file just ensures extensions are available.

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE threatlens_db TO threatlens;
