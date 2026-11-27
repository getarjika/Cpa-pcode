// Simulates a trusted install callback for LOCAL TESTING ONLY.
// Requires server running and ENABLE_DEMO_ENDPOINT=true.
require("dotenv").config();
const crypto = require("crypto");

async function main() {
  const base = process.env.BASE_URL || "http://localhost:3000";
  const startRes = await fetch(`${base}/api/start`, { method: "POST" });
  const start = await startRes.json();
  if (!startRes.ok) throw new Error(JSON.stringify(start));

  const demoRes = await fetch(`${base}/api/demo/simulate-install`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: start.session_id,
      demo_key: process.env.POSTBACK_SECRET
    })
  });
  const demo = await demoRes.json();
  if (!demoRes.ok) throw new Error(JSON.stringify(demo));

  const codeRes = await fetch(`${base}/api/code/${start.session_id}`);
  const code = await codeRes.json();
  if (!codeRes.ok) throw new Error(JSON.stringify(code));

  console.log("LOCAL DEMO ONLY — simulated install, not a real app install.");
  console.log("Session:", start.session_id);
  console.log("P-Code:", code.p_code);
}
main().catch(err => { console.error(err); process.exit(1); });
