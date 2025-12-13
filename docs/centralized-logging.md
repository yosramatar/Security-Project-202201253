# Centralized Logging & SIEM Forwarding

## Local Logging
- All security/audit events are logged to `backend/security.log` as JSON lines.
- See `backend/logger.js` for implementation details.

## SIEM Forwarding
- If the environment variable `HCA_LOG_WEBHOOK` or `HCA_SIEM_WEBHOOK` is set, logs are forwarded to the specified SIEM endpoint via HTTP POST.
- Forwarding is handled in `logger.js` using the `forwardToSiem()` function.

## Log Immutability
- Local logs are append-only. For production, use a WORM (Write Once Read Many) storage or cloud log service to ensure immutability.

## How to Enable SIEM Forwarding
1. Set `HCA_LOG_WEBHOOK` to your SIEM endpoint URL in the environment.
2. Restart the backend server.
3. Confirm logs are received by your SIEM.

## Next Steps
- Integrate log monitoring and alerting in your SIEM for suspicious events.
- Periodically review logs for compliance and incident response.