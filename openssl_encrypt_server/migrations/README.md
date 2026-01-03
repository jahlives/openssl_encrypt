# Database Migrations

This directory contains database migration scripts for the OpenSSL Encrypt Server.

## Migration List

| ID | Date | Description | Status |
|----|------|-------------|--------|
| 001 | 2026-01-03 | Increase fingerprint column size from 64 to 100 | Ready |

## Running Migrations

### Option 1: SQL Migration (PostgreSQL psql)

```bash
# Connect to database and run SQL file
psql -U postgres -d openssl_encrypt_db -f 001_increase_fingerprint_size.sql
```

### Option 2: Python Migration Script

```bash
# Run migration programmatically
python3 001_increase_fingerprint_size.py --database-url "postgresql+asyncpg://user:pass@host/db"
```

### Option 3: Docker Exec (for containerized databases)

```bash
# Copy migration to container and execute
docker cp 001_increase_fingerprint_size.sql openssl-encrypt-db:/tmp/
docker exec -it openssl-encrypt-db psql -U postgres -d openssl_encrypt_db -f /tmp/001_increase_fingerprint_size.sql
```

## Migration Details

### 001: Increase Fingerprint Column Size

**Problem:**
- SHA-256 fingerprints with colon separators are 95 characters long
- Example: `d5:28:7d:a5:ea:dc:be:39:38:7c:02:9c:d5:dd:c1:78:86:8a:51:f3:8f:3e:3c:11:5a:0d:6a:74:78:f4:a4:8f`
- Previous `VARCHAR(64)` size was insufficient
- Caused upload failures with: `value too long for type character varying(64)`

**Solution:**
- Increase `ks_keys.fingerprint` from `VARCHAR(64)` to `VARCHAR(100)`
- Increase `ks_access_log.key_fingerprint` from `VARCHAR(64)` to `VARCHAR(100)`
- Add column comments documenting the size

**Impact:**
- No data loss (only increasing column size)
- Backward compatible
- Minimal downtime (ALTER TABLE is fast on small tables)

## Creating New Migrations

1. Create sequential migration files: `002_migration_name.sql` and `002_migration_name.py`
2. Document the migration in this README
3. Test on a staging database first
4. Run on production during a maintenance window if necessary

## Best Practices

- Always backup the database before running migrations
- Test migrations on a staging environment first
- Document all schema changes in this README
- Keep SQL and Python versions in sync
- Use transaction blocks for complex migrations
- Add rollback instructions if needed
