//this is Password-hardener/frontend/src/api.js

const API_BASE = "http://localhost:4000";

/* ===============================
   PASSWORD ANALYZER
   =============================== */
export async function analyzePassword(password) {
  const res = await fetch(`${API_BASE}/api/analyze`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ password }),
  });

  return res.json();
}

/* ===============================
   PASSWORD GENERATOR
   =============================== */
export async function generatePassword(primary, secondary = null) {
  const res = await fetch(`${API_BASE}/api/generate-password`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ primary, secondary }),
  });

  return res.json();
}
