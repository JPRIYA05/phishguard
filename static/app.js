(() => {
  const $ = (id) => document.getElementById(id);
  const form = $("form"), input = $("input"), go = $("go"), err = $("error"), res = $("result");
  const LABELS = { safe: "Looks low-risk", suspicious: "Suspicious: be careful", dangerous: "Dangerous: do not engage" };

  function fill(listId, items) {
    const ul = $(listId);
    ul.replaceChildren(...items.map((t) => { const li = document.createElement("li"); li.textContent = t; return li; }));
  }

  document.querySelectorAll("[data-sample]").forEach((b) =>
    b.addEventListener("click", () => { input.value = b.dataset.sample; input.focus(); }));

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    err.hidden = true;
    const text = input.value.trim();
    if (!text) { err.textContent = "Enter a message or link to check."; err.hidden = false; input.focus(); return; }
    go.disabled = true; go.textContent = "Checking...";
    try {
      const r = await fetch("/api/analyze", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text }) });
      const data = await r.json();
      if (!r.ok) throw new Error(data.error || "Something went wrong.");
      res.className = data.verdict; res.hidden = false;
      $("verdict").textContent = `${LABELS[data.verdict]} (${data.score}/100)`;
      document.querySelector(".meter").setAttribute("aria-valuenow", data.score);
      $("bar").style.width = data.score + "%";
      $("explain").textContent = data.explanation;
      fill("findings", data.findings.length ? data.findings.map((f) => f.message) : ["No common warning signs found."]);
      fill("advice", data.recommendations);
      $("source").textContent = data.explanation_source === "gemini" ? "Explanation by Google Gemini." : "Explanation from built-in rules.";
      $("verdict").setAttribute("tabindex", "-1"); $("verdict").focus();
    } catch (ex) {
      err.textContent = ex.message; err.hidden = false;
    } finally {
      go.disabled = false; go.textContent = "Check it";
    }
  });
})();
