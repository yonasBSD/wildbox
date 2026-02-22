#!/usr/bin/env bash
#
# PostgreSQL Backup Script for Wildbox Security Suite
#
# Creates timestamped, compressed, encrypted backups of all PostgreSQL databases.
# Supports retention rotation and optional upload to S3.
#
# Usage:
#   ./backup_postgres.sh                  # Backup with defaults
#   ./backup_postgres.sh --upload-s3      # Backup and upload to S3
#   ./backup_postgres.sh --databases identity,data  # Specific databases
#
# Environment variables:
#   POSTGRES_HOST       (default: wildbox-postgres)
#   POSTGRES_PORT       (default: 5432)
#   POSTGRES_USER       (default: postgres)
#   POSTGRES_PASSWORD   (required)
#   BACKUP_DIR          (default: /backups/postgres)
#   BACKUP_RETENTION    (default: 30 days)
#   GPG_RECIPIENT       (optional, for encryption)
#   S3_BUCKET           (optional, for remote upload)

set -euo pipefail

# Configuration
POSTGRES_HOST="${POSTGRES_HOST:-wildbox-postgres}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
POSTGRES_USER="${POSTGRES_USER:-postgres}"
BACKUP_DIR="${BACKUP_DIR:-/backups/postgres}"
BACKUP_RETENTION="${BACKUP_RETENTION:-30}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DATABASES="${DATABASES:-identity,data}"
UPLOAD_S3=false

# Parse arguments
for arg in "$@"; do
  case $arg in
    --upload-s3) UPLOAD_S3=true ;;
    --databases=*) DATABASES="${arg#*=}" ;;
  esac
done

# Verify password is set
if [ -z "${POSTGRES_PASSWORD:-}" ]; then
  echo "ERROR: POSTGRES_PASSWORD environment variable is required"
  exit 1
fi

export PGPASSWORD="$POSTGRES_PASSWORD"

# Create backup directory
mkdir -p "$BACKUP_DIR"

echo "=== Wildbox PostgreSQL Backup ==="
echo "Timestamp: $TIMESTAMP"
echo "Host: $POSTGRES_HOST:$POSTGRES_PORT"
echo "Databases: $DATABASES"
echo "Backup dir: $BACKUP_DIR"
echo ""

# Backup each database
IFS=',' read -ra DB_ARRAY <<< "$DATABASES"
for db in "${DB_ARRAY[@]}"; do
  db=$(echo "$db" | xargs)  # trim whitespace
  BACKUP_FILE="${BACKUP_DIR}/${db}_${TIMESTAMP}.sql.gz"

  echo "Backing up database: $db"

  pg_dump \
    -h "$POSTGRES_HOST" \
    -p "$POSTGRES_PORT" \
    -U "$POSTGRES_USER" \
    -d "$db" \
    --format=custom \
    --compress=9 \
    --no-owner \
    --no-privileges \
    -f "${BACKUP_FILE%.gz}"

  # Compress with gzip
  gzip -f "${BACKUP_FILE%.gz}"

  # Encrypt if GPG recipient is set
  if [ -n "${GPG_RECIPIENT:-}" ]; then
    gpg --batch --yes --encrypt --recipient "$GPG_RECIPIENT" "$BACKUP_FILE"
    rm -f "$BACKUP_FILE"
    BACKUP_FILE="${BACKUP_FILE}.gpg"
    echo "  Encrypted: $BACKUP_FILE"
  fi

  # Show file size
  FILE_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
  echo "  Created: $BACKUP_FILE ($FILE_SIZE)"

  # Upload to S3 if requested
  if [ "$UPLOAD_S3" = true ] && [ -n "${S3_BUCKET:-}" ]; then
    S3_KEY="postgres-backups/${db}/${db}_${TIMESTAMP}.sql.gz"
    if [ -n "${GPG_RECIPIENT:-}" ]; then
      S3_KEY="${S3_KEY}.gpg"
    fi
    aws s3 cp "$BACKUP_FILE" "s3://${S3_BUCKET}/${S3_KEY}" --quiet
    echo "  Uploaded to: s3://${S3_BUCKET}/${S3_KEY}"
  fi
done

# Retention: remove backups older than BACKUP_RETENTION days
echo ""
echo "Cleaning up backups older than ${BACKUP_RETENTION} days..."
DELETED=$(find "$BACKUP_DIR" -name "*.sql.gz*" -mtime +"$BACKUP_RETENTION" -delete -print | wc -l)
echo "  Removed $DELETED old backup(s)"

# Verify backup integrity (test decompression of latest)
echo ""
echo "Verifying backup integrity..."
for db in "${DB_ARRAY[@]}"; do
  db=$(echo "$db" | xargs)
  LATEST=$(ls -t "${BACKUP_DIR}/${db}_"*.sql.gz 2>/dev/null | head -1 || true)
  if [ -n "$LATEST" ]; then
    if gzip -t "$LATEST" 2>/dev/null; then
      echo "  $db: OK"
    else
      echo "  $db: FAILED (corrupt backup)"
      exit 1
    fi
  fi
done

echo ""
echo "=== Backup complete ==="
