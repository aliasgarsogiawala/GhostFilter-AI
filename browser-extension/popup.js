const apiBaseInput = document.getElementById("apiBase");
const scanButton = document.getElementById("scan");
const copyButton = document.getElementById("copy");
const statusEl = document.getElementById("status");
const resultEl = document.getElementById("result");
const titleEl = document.getElementById("title");
const summaryEl = document.getElementById("summary");
const safeContextEl = document.getElementById("safeContext");
const verdictDotEl = document.getElementById("verdictDot");

chrome.storage.sync.get(["apiBase"], (items) => {
  if (items.apiBase) apiBaseInput.value = items.apiBase;
});

apiBaseInput.addEventListener("change", () => {
  chrome.storage.sync.set({ apiBase: apiBaseInput.value.trim() });
});

async function selectedTextFromActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) throw new Error("No active tab found.");
  const [result] = await chrome.scripting.executeScript({
    target: { tabId: tab.id },
    func: () => window.getSelection()?.toString() ?? "",
  });
  return String(result?.result ?? "").trim();
}

scanButton.addEventListener("click", async () => {
  statusEl.textContent = "Scanning selected text…";
  resultEl.hidden = true;
  try {
    const selectedText = await selectedTextFromActiveTab();
    if (!selectedText) throw new Error("Highlight some webpage text first.");

    const apiBase = apiBaseInput.value.trim().replace(/\/$/, "");
    const res = await fetch(`${apiBase}/api/ghostgpt/firewall`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content: selectedText }),
    });
    const data = await res.json();
    if (!res.ok || !data.firewall) throw new Error(data.error ?? "GhostFilter API error");

    const firewall = data.firewall;
    titleEl.textContent = firewall.title;
    summaryEl.textContent = firewall.summary;
    safeContextEl.value = firewall.sanitizedContext;
    verdictDotEl.style.background =
      firewall.verdict === "block" ? "#ef4060" : firewall.verdict === "isolate" ? "#f7b84b" : "#2de6bd";
    resultEl.hidden = false;
    statusEl.textContent = "";
  } catch (err) {
    statusEl.textContent = err instanceof Error ? err.message : "Scan failed.";
  }
});

copyButton.addEventListener("click", async () => {
  await navigator.clipboard.writeText(safeContextEl.value);
  statusEl.textContent = "Safe context copied.";
});
