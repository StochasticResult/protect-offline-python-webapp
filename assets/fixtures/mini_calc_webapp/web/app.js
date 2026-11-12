(function () {
  "use strict";

  const badgeEl = document.getElementById("runtime-badge");
  const samplesEl = document.getElementById("samples-input");
  const rateEl = document.getElementById("rate-input");
  const modeEl = document.getElementById("mode-select");
  const outputEl = document.getElementById("result-output");
  const analyzeBtn = document.getElementById("analyze-btn");
  const exportBtn = document.getElementById("export-btn");

  async function refreshHealth() {
    try {
      const resp = await fetch("/api/health");
      const data = await resp.json();
      badgeEl.textContent = data.is_compiled_binary
        ? "Offline Ready (Compiled Core)"
        : "Offline Ready (Source Mode)";
    } catch (err) {
      badgeEl.textContent = "Service unreachable";
    }
  }

  function parseSamples() {
    return samplesEl.value
      .split(",")
      .map((s) => Number(s.trim()))
      .filter((v) => !Number.isNaN(v));
  }

  analyzeBtn.addEventListener("click", async () => {
    const payload = {
      samples: parseSamples(),
      sample_rate_hz: Number(rateEl.value),
      mode: modeEl.value,
    };
    const resp = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await resp.json();
    outputEl.textContent = JSON.stringify(data, null, 2);
  });

  exportBtn.addEventListener("click", async () => {
    const payload = {
      job_name: "ui_batch_check",
      records: [
        { label: "ch1", samples: parseSamples(), sample_rate_hz: Number(rateEl.value), mode: modeEl.value },
      ],
    };
    const resp = await fetch("/api/jobs/import-export", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await resp.json();
    outputEl.textContent = JSON.stringify(data, null, 2);
  });

  refreshHealth();
})();
