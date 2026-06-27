const apiBaseInput = document.getElementById("apiBase");
const apiKeyInput = document.getElementById("apiKey");
const scanSelectionButton = document.getElementById("scanSelection");
const scanPageButton = document.getElementById("scanPage");
const copyButton = document.getElementById("copy");
const openDashboardButton = document.getElementById("openDashboard");
const statusEl = document.getElementById("status");
const resultEl = document.getElementById("result");
const titleEl = document.getElementById("title");
const summaryEl = document.getElementById("summary");
const safeContextEl = document.getElementById("safeContext");
const verdictDotEl = document.getElementById("verdictDot");
const ghostiAdviceEl = document.getElementById("ghostiAdvice");
const scorePillEl = document.getElementById("scorePill");
const actionPillEl = document.getElementById("actionPill");

chrome.storage.local.get(["apiBase", "apiKey"], (items) => {
  if (items.apiBase) apiBaseInput.value = items.apiBase;
  if (items.apiKey) apiKeyInput.value = items.apiKey;
});

apiBaseInput.addEventListener("change", async () => {
  const apiBase = apiBaseInput.value.trim().replace(/\/$/, "");
  try {
    const origin = new URL(apiBase).origin;
    const granted = await chrome.permissions.request({ origins: [`${origin}/*`] });
    if (!granted) throw new Error("Permission was not granted for this API origin.");
    await chrome.storage.local.set({ apiBase });
    statusEl.textContent = "API origin saved.";
  } catch (error) {
    statusEl.textContent = error instanceof Error ? error.message : "Invalid API URL.";
  }
});

apiKeyInput.addEventListener("change", async () => {
  await chrome.storage.local.set({ apiKey: apiKeyInput.value.trim() });
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

async function pageTextFromActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) throw new Error("No active tab found.");
  const [result] = await chrome.scripting.executeScript({
    target: { tabId: tab.id },
    func: () => {
      const title = document.title ? `Page title: ${document.title}\n\n` : "";
      const meta = document.querySelector("meta[name='description']")?.getAttribute("content");
      const body = document.body?.innerText ?? "";
      return `${title}${meta ? `Description: ${meta}\n\n` : ""}${body}`.replace(/\s+\n/g, "\n").slice(0, 12000);
    },
  });
  return String(result?.result ?? "").trim();
}

function verdictCopy(firewall) {
  if (firewall.verdict === "block") {
    return "Ghosti would not pass this raw text to GhostGPT. Copy the safe context or treat the page as hostile.";
  }
  if (firewall.verdict === "isolate") {
    return "Ghosti found risky instructions. Use the safe context wrapper so GhostGPT treats the content as data, not commands.";
  }
  return "Ghosti did not find obvious prompt-injection signals. Still keep external content isolated when using AI agents.";
}

async function runScan(getText, label) {
  statusEl.textContent = `Scanning ${label}…`;
  resultEl.hidden = true;
  scanSelectionButton.disabled = true;
  scanPageButton.disabled = true;
  try {
    const content = await getText();
    if (!content) throw new Error(label === "selection" ? "Highlight some webpage text first." : "This page did not expose readable text.");

    const apiBase = apiBaseInput.value.trim().replace(/\/$/, "");
    const apiKey = apiKeyInput.value.trim();
    const res = await fetch(`${apiBase}/api/ghostgpt/firewall`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(apiKey ? { Authorization: `Bearer ${apiKey}` } : {}),
      },
      body: JSON.stringify({ content }),
    });
    const data = await res.json();
    if (!res.ok || !data.firewall) throw new Error(data.error ?? "GhostFilter API error");

    const firewall = data.firewall;
    titleEl.textContent = firewall.title;
    summaryEl.textContent = firewall.summary;
    safeContextEl.value = firewall.sanitizedContext;
    ghostiAdviceEl.textContent = verdictCopy(firewall);
    scorePillEl.textContent = `Risk ${firewall.score ?? "--"}%`;
    actionPillEl.textContent =
      firewall.verdict === "block" ? "Block" : firewall.verdict === "isolate" ? "Isolate" : "Pass";
    verdictDotEl.style.background =
      firewall.verdict === "block" ? "#ef4060" : firewall.verdict === "isolate" ? "#f7b84b" : "#2de6bd";
    resultEl.hidden = false;
    statusEl.textContent = "";
  } catch (err) {
    statusEl.textContent = err instanceof Error ? err.message : "Scan failed.";
  } finally {
    scanSelectionButton.disabled = false;
    scanPageButton.disabled = false;
  }
}

scanSelectionButton.addEventListener("click", async () => {
  await runScan(selectedTextFromActiveTab, "selection");
});

scanPageButton.addEventListener("click", async () => {
  await runScan(pageTextFromActiveTab, "page");
});

copyButton.addEventListener("click", async () => {
  await navigator.clipboard.writeText(safeContextEl.value);
  statusEl.textContent = "Safe context copied.";
});

openDashboardButton.addEventListener("click", async () => {
  const apiBase = apiBaseInput.value.trim().replace(/\/$/, "");
  await chrome.tabs.create({ url: `${apiBase}/dashboard` });
});
