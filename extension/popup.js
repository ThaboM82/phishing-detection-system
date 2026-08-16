document.addEventListener("DOMContentLoaded", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs[0]) return;
    const activeTab = tabs[0];
    document.getElementById("current-url").textContent = activeTab.url;

    chrome.storage.local.get([activeTab.id.toString()], (result) => {
      const data = result[activeTab.id];
      if (!data) {
        document.getElementById("verdict-badge").textContent = "PENDING";
        return;
      }

      // Update Verdict Badge
      const badge = document.getElementById("verdict-badge");
      badge.textContent = data.verdict;
      badge.className = `badge ${data.verdict.toLowerCase()}`;

      // Update Metrics
      document.getElementById("ml-prob").textContent = `${(data.ml_probability * 100).toFixed(1)}%`;
      document.getElementById("rule-count").textContent = data.heuristic_flags_count;

      // Update Rules List
      const rulesContainer = document.getElementById("rules-container");
      rulesContainer.innerHTML = "";

      if (data.fired_rules && data.fired_rules.length > 0) {
        data.fired_rules.forEach(rule => {
          const div = document.createElement("div");
          div.className = "rule-item";
          div.innerHTML = `<strong>${rule.rule}</strong>: ${rule.reason}`;
          rulesContainer.appendChild(div);
        });
      } else {
        rulesContainer.innerHTML = `<div class="no-rules">✓ No heuristic risk rules triggered.</div>`;
      }
    });
  });
});
