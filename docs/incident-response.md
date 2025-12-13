# Incident Response Plan

## Overview
- Define roles and responsibilities for incident response.
- Establish communication channels and escalation procedures.
- Document steps for detection, containment, eradication, and recovery.

## Example Steps
1. **Detection**: Monitor logs and alerts for suspicious activity.
2. **Analysis**: Investigate alerts, identify affected systems/data.
3. **Containment**: Isolate compromised accounts/systems.
4. **Eradication**: Remove malware, revoke access, patch vulnerabilities.
5. **Recovery**: Restore from backups, validate system integrity.
6. **Post-Incident**: Document findings, update policies, notify stakeholders.

## Simulation Script
```bash
# Simulate incident: lock user account and log event
sqlite3 backend/hospital.db "UPDATE users SET status='locked' WHERE email='victim@example.com';"
echo "Incident simulated: user account locked."
```

## Next Steps
- Schedule regular incident response drills.
- Review and update plan after each incident or drill.
- Store IR plan in a secure, accessible location.
