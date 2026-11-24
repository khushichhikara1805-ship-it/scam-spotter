// script.js - sends the message to Flask (/analyze) and shows the result without reloading.
const msgBox = document.getElementById("message");
const btn = document.getElementById("check");
const errorBox = document.getElementById("error");
const resultBox = document.getElementById("result");

// An emoji and a colour-friendly meaning for each rule
const ICONS = {
  urgent_language: "⏰", contains_link: "🔗", suspicious_link: "⚠️",
  sensitive_request: "🔑", payment_request: "💸", prize_claim: "🎁",
  fake_job: "💼", threat_impersonation: "🚨", combination: "🔥",
};
const COLORS = { "Safe": "#13b981", "Suspicious": "#ff9f1c", "High Risk": "#ef3b5c" };
const VERDICTS = {
  "Safe": "No common scam signs found.",
  "Suspicious": "Some warning signs found. Be careful and verify first.",
  "High Risk": "Many scam signs found. Do not click or reply!",
};

document.getElementById("example").addEventListener("change", (e) => { msgBox.value = e.target.value; });

function fillSimple(id, items) {
  const ul = document.getElementById(id);
  ul.innerHTML = "";
  items.forEach((text) => {
    const li = document.createElement("li");
    li.textContent = text;        // textContent (not innerHTML) keeps it safe from XSS
    ul.appendChild(li);
  });
}

function fillReasons(indicators) {
  const ul = document.getElementById("reasons");
  ul.innerHTML = "";
  if (!indicators.length) {
    const li = document.createElement("li");
    li.textContent = "✅ No common scam indicators found.";
    ul.appendChild(li);
    return;
  }
  indicators.forEach((i) => {
    const li = document.createElement("li");
    const ic = document.createElement("span"); ic.className = "ic"; ic.textContent = ICONS[i.rule] || "•";
    const box = document.createElement("div");
    box.textContent = i.description;
    if (i.evidence) { const s = document.createElement("small"); s.textContent = "Found: " + i.evidence; box.appendChild(s); }
    const pts = document.createElement("span"); pts.className = "pts"; pts.textContent = "+" + i.points;
    li.append(ic, box, pts);
    ul.appendChild(li);
  });
}

btn.addEventListener("click", async () => {
  errorBox.textContent = "";
  btn.disabled = true;
  btn.textContent = "Checking...";
  try {
    const res = await fetch("/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: msgBox.value }),
    });
    const data = await res.json();
    if (!res.ok) { errorBox.textContent = data.error; resultBox.classList.add("hidden"); return; }

    const level = document.getElementById("level");
    level.textContent = data.level;
    level.className = "badge " + data.level.replace(" ", "").toLowerCase();
    document.getElementById("verdict-text").textContent = VERDICTS[data.level];
    document.getElementById("score").textContent = data.score;
    resultBox.style.setProperty("--c", COLORS[data.level]);
    resultBox.style.setProperty("--pct", data.score);

    fillReasons(data.indicators);
    fillSimple("tips", data.tips);
    resultBox.classList.remove("hidden");
    resultBox.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (err) {
    errorBox.textContent = "Could not reach the server. Is the app running?";
  } finally {
    btn.disabled = false;
    btn.textContent = "🔍 Check Message";
  }
});
