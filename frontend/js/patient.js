// frontend/js/patient.js
document.addEventListener("DOMContentLoaded", () => {
  const info = window.requireRole(["patient"]);
  if (!info) return;

  const form = document.getElementById("appointmentForm");
  const msg = document.getElementById("appointmentMessage");
  const dataDiv = document.getElementById("patientData");
  const doctorSelect = document.getElementById("appointmentDoctorId");

  async function loadDoctors() {
    if (!doctorSelect) return;

    doctorSelect.innerHTML = "<option value=''>Loading…</option>";
    doctorSelect.disabled = true;

    try {
      const data = await window.apiFetch("/api/patient/doctors");
      const doctors = data.doctors || [];

      if (doctors.length === 0) {
        doctorSelect.innerHTML = "<option value=''>No doctors available</option>";
        return;
      }

      doctorSelect.innerHTML = "<option value=''>Select doctor</option>";
      doctors.forEach(doc => {
        const opt = document.createElement("option");
        opt.value = doc.id;
        opt.textContent = `${doc.name} (ID ${doc.id})`;
        doctorSelect.appendChild(opt);
      });

      doctorSelect.disabled = false;
    } catch (err) {
      console.error("Failed to load doctors", err);
      doctorSelect.innerHTML = "<option value=''>Unable to load doctors</option>";
      doctorSelect.disabled = true;
      if (msg) {
        msg.textContent = err?.data?.error || "Unable to load doctors.";
        msg.className = "form-message error";
      }
    }
  }

  async function loadDiagnosis() {
    dataDiv.innerHTML = "<p class='muted'>Loading…</p>";
    try {
      const data = await window.apiFetch("/api/patient/diagnosis");
      const appts = data.appointments || [];
      const diag = data.diagnosis || [];
      if (appts.length === 0) {
        dataDiv.innerHTML = "<p class='muted'>No appointments yet.</p>";
        return;
      }

      const map = {};
      diag.forEach((d) => {
        map[d.appointment_id] = d;
      });

      const table = document.createElement("table");
      table.className = "data-table";
      table.innerHTML = `
        <thead>
          <tr>
            <th>ID</th>
            <th>Date/time</th>
            <th>Status</th>
            <th>Diagnosis</th>
            <th>Medications</th>
          </tr>
        </thead>
        <tbody></tbody>
      `;
      const tbody = table.querySelector("tbody");

      appts.forEach((a) => {
        const d = map[a.id] || {};
        const meds = (d.medications || []).join(", ");
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${a.id}</td>
          <td>${a.datetime}</td>
          <td>${a.status}</td>
          <td>${d.notes || ""}</td>
          <td>${meds}</td>
        `;
        tbody.appendChild(tr);
      });

      dataDiv.innerHTML = "";
      dataDiv.appendChild(table);
    } catch (err) {
      dataDiv.innerHTML =
        "<p class='error'>Failed to load your appointments.</p>";
    }
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    msg.textContent = "";
    msg.className = "form-message";

    const doctorId = Number(doctorSelect?.value);
    const datetime = document.getElementById("appointmentDatetime").value;

    if (!doctorId) {
      msg.textContent = "Please select a doctor.";
      msg.classList.add("error");
      return;
    }

    try {
      const data = await window.apiFetch("/api/patient/apply-appointment", {
        method: "POST",
        body: JSON.stringify({ doctorId, datetime }),
      });
      msg.textContent = data.message || "Appointment requested.";
      msg.classList.add("success");
      loadDiagnosis();
    } catch (err) {
      const text =
        err.data && err.data.error ? err.data.error : "Failed to request appointment.";
      msg.textContent = text;
      msg.classList.add("error");
    }
  });

  loadDoctors();
  loadDiagnosis();
});
