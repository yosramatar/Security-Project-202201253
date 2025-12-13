// frontend/js/nurse.js
document.addEventListener("DOMContentLoaded", () => {
  const info = window.requireRole(["nurse"]);
  if (!info) return;

  const tableBody = document.querySelector("#nurseAppointmentsTable tbody");
  const medsForm = document.getElementById("medsForm");
  const medsMsg = document.getElementById("medsMessage");
  const medsSelect = document.getElementById("medsAppointmentId");

  let appointmentsCache = [];

  function renderAppointmentsSelect(list) {
    if (!medsSelect) return;

    medsSelect.innerHTML = "";

    if (!list.length) {
      medsSelect.appendChild(
        new Option("No appointments available", "")
      );
      medsSelect.disabled = true;
      return;
    }

    medsSelect.appendChild(new Option("Select appointment", ""));
    list.forEach((a) => {
      const label = `#${a.id} – ${a.patient_name} (${a.datetime})`;
      medsSelect.appendChild(new Option(label, a.id));
    });
    medsSelect.disabled = false;
  }

  async function loadAppointments() {
    tableBody.innerHTML = "<tr><td colspan='5'>Loading…</td></tr>";
    try {
      const data = await window.apiFetch("/api/nurse/appointments");
      tableBody.innerHTML = "";
      appointmentsCache = data.appointments || [];

      if (!appointmentsCache.length) {
        tableBody.innerHTML =
          "<tr><td colspan='5' class='muted'>No appointments yet.</td></tr>";
      }

      appointmentsCache.forEach((a) => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${a.id}</td>
          <td>${a.datetime}</td>
          <td>${a.patient_name}</td>
          <td>${a.doctor_name}</td>
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

  if (medsForm && medsSelect) {
    medsForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      medsMsg.textContent = "";
      medsMsg.className = "form-message";

      const appointmentId = Number(medsSelect.value);
      if (!appointmentId) {
        medsMsg.textContent = "Select an appointment first.";
        medsMsg.classList.add("error");
        return;
      }

      const text = document.getElementById("medsText").value.trim();
      const meds = text
        ? text.split("\n").map((l) => l.trim()).filter((l) => l)
        : [];

      try {
        const data = await window.apiFetch("/api/nurse/medications", {
          method: "POST",
          body: JSON.stringify({ appointmentId, medications: meds }),
        });
        medsMsg.textContent = data.message || "Medications saved.";
        medsMsg.classList.add("success");
      } catch (err) {
        const msg =
          err.data && err.data.error
            ? err.data.error
            : "Failed to save medications.";
        medsMsg.textContent = msg;
        medsMsg.classList.add("error");
      }
    });
  }

  document.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-fill-appointment]");
    if (!btn) return;
    const id = btn.getAttribute("data-fill-appointment");
    if (medsSelect) {
      medsSelect.value = id;
    }
  });

  loadAppointments();
});
