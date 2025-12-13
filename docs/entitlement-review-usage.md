# Entitlement Review Script Usage

## Location
Script: `backend/scripts/review-entitlements.js`

## Purpose
- Lists all users, roles, and entitlements
- Flags orphaned roles and unused entitlements for admin review

## How to Run
1. Open a terminal in the backend directory:
   ```sh
   cd backend/scripts
   node review-entitlements.js
   ```
2. The script will output a report to the console, showing:
   - All users, their roles, and status
   - Assignments to appointments (doctor, nurse, patient)
   - Orphaned roles (active users with no assignments)
   - Unassigned users

## Output Example
```
Entitlement Review Report
========================
DOCTOR | Alice <alice@healthcure.com> | Status: active | Assignments: Doctor for appointment 1, Doctor for appointment 2
NURSE | Bob <bob@healthcure.com> | Status: active [ORPHANED]
PATIENT | Carol <carol@healthcure.com> | Status: active | Assignments: Patient for appointment 1
```

## Next Steps
- Review flagged orphaned roles and unassigned users
- Remove or reassign as needed
- Extend script for more detailed entitlement checks if required
