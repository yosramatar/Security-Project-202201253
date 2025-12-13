// ABAC Policy Engine for HealthCureAlpha
// Supports context-based access control (department, consent, assignment)

const db = require('./db');

/**
 * Evaluate access for a user based on context and policy rules.
 * @param {Object} session - Current session object
 * @param {Object} context - Contextual info (resource, department, patientId, etc)
 * @param {String} action - Action being requested (e.g., 'view', 'edit', 'assign')
 * @returns {Boolean} - true if access is allowed, false otherwise
 */
function evaluateAccess(session, context, _action) {
  // Example rules:
  // 1. Admins always allowed
  if (session.role === 'admin') return true;

  // 2. Doctors can view/edit patients assigned to them
  if (session.role === 'doctor' && context.patientId) {
    const assignment = db.prepare('SELECT doctor_id FROM appointments WHERE patient_id = ? AND doctor_id = ?')
      .get(context.patientId, session.userId);
    if (assignment) return true;
  }

  // 3. Nurses can view/edit patients assigned to their doctor
  if (session.role === 'nurse' && context.patientId) {
    const nurseAssignment = db.prepare(`SELECT a.nurse_id FROM appointments a WHERE a.patient_id = ? AND a.nurse_id = ?`)
      .get(context.patientId, session.userId);
    if (nurseAssignment) return true;
  }

  // 4. Patient can view/edit own records
  if (session.role === 'patient' && context.patientId && session.userId === context.patientId) {
    return true;
  }

  // 5. Department-based access (example)
  if (context.department && session.department && session.department === context.department) {
    return true;
  }

  // 6. Consent-based access (example)
  if (context.consentGiven === true) {
    return true;
  }

  // Default deny
  return false;
}

module.exports = { evaluateAccess };
