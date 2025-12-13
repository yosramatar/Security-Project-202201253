// Automated Entitlement Review Script
// Lists all users, roles, and entitlements; flags orphaned roles and unused entitlements

const db = require('../db');


function getAllUsers() {
  // Add last_login and explicit_entitlements columns if available
  return db.prepare('SELECT id, email, name, role, status, last_login, explicit_entitlements FROM users').all();
}

function getAllAppointments() {
  return db.prepare('SELECT id, patient_id, doctor_id, nurse_id FROM appointments').all();
}


function getRoleAssignments(users, appointments) {
  const assignments = {};
  users.forEach(u => {
    assignments[u.id] = {
      user: u,
      assigned: false,
      orphaned: false,
      details: [],
      last_login: u.last_login,
      explicit_entitlements: u.explicit_entitlements || '',
    };
  });
  appointments.forEach(a => {
    if (assignments[a.doctor_id]) {
      assignments[a.doctor_id].assigned = true;
      assignments[a.doctor_id].details.push(`Doctor for appointment ${a.id}`);
    }
    if (assignments[a.nurse_id]) {
      assignments[a.nurse_id].assigned = true;
      assignments[a.nurse_id].details.push(`Nurse for appointment ${a.id}`);
    }
    if (assignments[a.patient_id]) {
      assignments[a.patient_id].assigned = true;
      assignments[a.patient_id].details.push(`Patient for appointment ${a.id}`);
    }
  });
  return assignments;
}


function detectOrphanedRoles(assignments) {
  Object.values(assignments).forEach(a => {
    // Orphaned: active, not assigned, not admin, and no explicit entitlements
    const isOrphaned = !a.assigned && a.user.status === 'active' && a.user.role !== 'admin' && !a.explicit_entitlements;
    if (isOrphaned) {
      a.orphaned = true;
    }
  });
}


function printReport(assignments) {
  console.log('Entitlement Review Report');
  console.log('========================');
  Object.values(assignments).forEach(a => {
    const { user, assigned, orphaned, details, last_login, explicit_entitlements } = a;
    let line = `${user.role.toUpperCase()} | ${user.name} <${user.email}> | Status: ${user.status}`;
    if (last_login) line += ` | Last login: ${last_login}`;
    if (explicit_entitlements) line += ` | Explicit entitlements: ${explicit_entitlements}`;
    if (orphaned) line += ' [ORPHANED]';
    if (!assigned && !orphaned && user.role !== 'admin') line += ' [UNASSIGNED]';
    if (details.length) line += ` | Assignments: ${details.join(', ')}`;
    console.log(line);
  });
}

function main() {
  const users = getAllUsers();
  const appointments = getAllAppointments();
  const assignments = getRoleAssignments(users, appointments);
  detectOrphanedRoles(assignments);
  printReport(assignments);
}

main();
