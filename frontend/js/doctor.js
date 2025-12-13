// frontend/js/doctor.js
document.addEventListener("DOMContentLoaded", () => {
  const info = window.requireRole(["doctor"]);
  if (!info) return;

  const tableBody = document.querySelector("#doctorAppointmentsTable tbody");
  const assignForm = document.getElementById("assignNurseForm");
  const assignMsg = document.getElementById("assignNurseMessage");
  const nurseSelect = document.getElementById("assignNurseId");
  const diagForm = document.getElementById("diagnosisForm");
  const diagMsg = document.getElementById("diagnosisMessage");
  const diagSelect = document.getElementById("diagAppointmentId");

  let appointmentsCache = [];

  function renderAppointmentsSelect(list) {
    if (!diagSelect) return;

    diagSelect.innerHTML = "";

    if (!list.length) {
      const opt = document.createElement("option");
      opt.value = "";
      opt.textContent = "No appointments available";
      diagSelect.appendChild(opt);
      diagSelect.disabled = true;
      return;
    }

    const placeholder = document.createElement("option");
    placeholder.value = "";
    placeholder.textContent = "Select appointment";
    diagSelect.appendChild(placeholder);

    list.forEach((a) => {
      const opt = document.createElement("option");
      opt.value = a.id;
      opt.textContent = `#${a.id} – ${a.patient_name} (${a.datetime})`;
      diagSelect.appendChild(opt);
    });

    diagSelect.disabled = false;
  }

  async function loadAppointments() {
    tableBody.innerHTML = "<tr><td colspan='5'>Loading…</td></tr>";
    try {
      const data = await window.apiFetch("/api/doctor/appointments");
      tableBody.innerHTML = "";
      appointmentsCache = data.appointments || [];

      if (appointmentsCache.length === 0) {
        tableBody.innerHTML =
          "<tr><td colspan='5' class='muted'>No appointments yet.</td></tr>";
      }

      appointmentsCache.forEach((a) => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${a.id}</td>
          <td>${a.datetime}</td>
          <td>${a.patient_name} (${a.patient_email})</td>
          <td>${a.status}</td>
          <td>
            <button class="btn-small" data-fill-appointment="${a.id}">
              Use in form
            </button>
          </td>
        `;
        tableBody.appendChild(tr);
      });

      renderAppointmentsSelect(appointmentsCache);
    } catch (err) {
      tableBody.innerHTML =
        "<tr><td colspan='5' class='error'>Failed to load appointments</td></tr>";
      renderAppointmentsSelect([]);
    }
  }

  if (assignForm && nurseSelect) {
    assignForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      assignMsg.textContent = "";
      assignMsg.className = "form-message";

      const nurseId = Number(nurseSelect.value);
      if (!nurseId) {
        assignMsg.textContent = "Please select a nurse.";
        assignMsg.classList.add("error");
        return;
      }

      try {
        const data = await window.apiFetch("/api/doctor/assign-nurse", {
          method: "POST",
          body: JSON.stringify({ nurseId }),
        });
        assignMsg.textContent = data.message || "Nurse assigned.";
        assignMsg.classList.add("success");
      } catch (err) {
        const msg =
          err.data && err.data.error
            ? err.data.error
            : "Failed to assign nurse.";
        assignMsg.textContent = msg;
        assignMsg.classList.add("error");
      }
    });
  }

  if (diagForm && diagSelect) {
    diagForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      diagMsg.textContent = "";
      diagMsg.className = "form-message";

      const appointmentId = Number(diagSelect.value);
      const notes = document.getElementById("diagNotes").value.trim();

      if (!appointmentId) {
        diagMsg.textContent = "Select an appointment first.";
        diagMsg.classList.add("error");
        return;
      }

      try {
        const data = await window.apiFetch("/api/doctor/diagnosis", {
          method: "POST",
          body: JSON.stringify({ appointmentId, notes }),
        });
        diagMsg.textContent = data.message || "Diagnosis saved.";
        diagMsg.classList.add("success");
        await loadAppointments();
        diagSelect.value = "";
        document.getElementById("diagNotes").value = "";
      } catch (err) {
        const msg =
          err.data && err.data.error
            ? err.data.error
            : "Failed to save diagnosis.";
        diagMsg.textContent = msg;
        diagMsg.classList.add("error");
      }
    });
  }

  document.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-fill-appointment]");
    if (!btn) return;
    const id = btn.getAttribute("data-fill-appointment");
    if (diagSelect) {
      diagSelect.value = id;
    }
  });

  async function loadNurses() {
    if (!nurseSelect) return;

    nurseSelect.innerHTML = "<option value=''>Loading nurses…</option>";
    nurseSelect.disabled = true;

    try {
      const data = await window.apiFetch("/api/doctor/nurses");
      const nurses = data.nurses || [];

      nurseSelect.innerHTML = "";

      if (!nurses.length) {
        const opt = document.createElement("option");
        opt.value = "";
        opt.textContent = "No nurses available";
        nurseSelect.appendChild(opt);
        nurseSelect.disabled = true;
        return;
      }

      const placeholder = document.createElement("option");
      placeholder.value = "";
      placeholder.textContent = "Select nurse";
      nurseSelect.appendChild(placeholder);

      nurses.forEach((n) => {
        const opt = document.createElement("option");
        opt.value = n.id;
        opt.textContent = `${n.name} (ID ${n.id})`;
        nurseSelect.appendChild(opt);
      });

      nurseSelect.disabled = false;
    } catch (err) {
      console.error("Failed to load nurses", err);
      nurseSelect.innerHTML = "<option value=''>Unable to load nurses</option>";
      nurseSelect.disabled = true;
      assignMsg.textContent = err?.data?.error || "Unable to load nurses.";
      assignMsg.className = "form-message error";
    }
  }

  loadNurses();
  loadAppointments();
});
