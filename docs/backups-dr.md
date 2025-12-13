# Backup & Disaster Recovery (DR)

## Database Backup Script (SQLite)

Create a backup of the hospital database:

```bash
# Backup hospital.db to build/backups/hospital-backup-$(date +%Y%m%d).db
mkdir -p build/backups
cp backend/hospital.db build/backups/hospital-backup-$(date +%Y%m%d).db
```

## Restore Script

Restore the database from a backup:

```bash
# Restore backup to backend/hospital.db
cp build/backups/hospital-backup-YYYYMMDD.db backend/hospital.db
```

## Recommendations
- Schedule regular backups (daily/weekly) using cron or Task Scheduler.
- Store backups in a secure, offsite location (cloud, encrypted external drive).
- Test restore procedures periodically.
- Document backup/restore steps for staff.

## Next Steps
- Automate backup/restore in CI/CD or server startup scripts.
- Add backup integrity checks and retention policies.
