"use strict";
const $ = (id) => document.getElementById(id);
let token = "",
  identity = null,
  selected = null,
  summary = null,
  busy = false;
const descriptions = {
  PROVEN: "Required evidence supports the frozen contract.",
  DISPROVEN:
    "A required condition failed. Preserve the evidence and coordinate recovery.",
  INDETERMINATE:
    "Admissible evidence is insufficient to establish the outcome.",
  PARTIALLY_PROVEN:
    "Some required outcomes are supported; complete acceptance is unavailable.",
  ACCEPTED: "The owner accepted the independently evaluated outcome.",
  RECOVERED:
    "Recovery was independently verified. The original verdict remains intact.",
};
function node(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}
async function api(path, body) {
  const r = await fetch("/api/v1" + path, {
    method: body === undefined ? "GET" : "POST",
    headers: {
      Authorization: "Bearer " + token,
      ...(body === undefined ? {} : { "Content-Type": "application/json" }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await r.json();
  if (!r.ok) {
    if (r.status === 401) disconnect();
    throw new Error(data.error + (data.detail ? " · " + data.detail : ""));
  }
  return data;
}
function disconnect() {
  token = "";
  identity = null;
  selected = null;
  $("token").value = "";
  $("console").hidden = true;
  $("login").hidden = false;
  $("proposal").close();
}
$("logout").onclick = disconnect;
$("login-form").onsubmit = async (e) => {
  e.preventDefault();
  token = $("token").value.trim();
  $("login-error").textContent = "";
  try {
    identity = await api("/whoami");
    $("token").value = "";
    $("principal").textContent =
      identity.principal + " · " + identity.roles.join(", ");
    $("propose").hidden = !identity.roles.some(
      (r) => r === "actor" || r === "operator",
    );
    $("login").hidden = true;
    $("console").hidden = false;
    await refresh();
  } catch (err) {
    token = "";
    $("login-error").textContent = err.message;
  }
};
async function refresh() {
  try {
    summary = await api("/status");
    const nav = $("transactions");
    nav.replaceChildren();
    for (const [tx, state] of Object.entries(summary.transactions || {})) {
      const b = node(
        "button",
        tx + " · " + state,
        tx === selected ? "active" : "",
      );
      b.onclick = async () => {
        selected = tx;
        await refresh();
      };
      nav.append(b);
    }
    const pos = $("ledger-position");
    pos.replaceChildren(
      node("strong", "EVENTS " + summary.sequence),
      node("span", "HEAD " + summary.verified_head),
    );
    $("empty").hidden = !!selected;
    $("transaction-detail").hidden = !selected;
    if (selected) await renderTransaction();
  } catch (e) {
    $("notice").textContent = e.message;
  }
}
$("refresh").onclick = refresh;
function binding(name, value) {
  const dt = node("dt", name),
    dd = node("dd", value || "Not recorded");
  $("bindings").append(dt, dd);
}
async function renderTransaction() {
  const tx = await api("/transactions/" + selected);
  $("title").textContent = tx.transaction_id;
  $("subtitle").textContent = "Enrolled target · " + tx.target_id;
  $("state").textContent = tx.state;
  $("raw").textContent = JSON.stringify(tx, null, 2);
  $("bindings").replaceChildren();
  for (const [label, key] of [
    ["Contract", "contract_hash"],
    ["Artifact", "artifact_hash"],
    ["Baseline", "baseline_hash"],
    ["Observation start", "window_start"],
    ["Parent transaction", "parent_transaction"],
    ["Recovery transaction", "child_transaction"],
  ])
    binding(label, tx[key]);
  $("packets").replaceChildren(
    ...(tx.packets || []).map((h) => node("div", h, "packet")),
  );
  $("checks").replaceChildren();
  let verdict = tx.verdict || null;
  let body = null;
  if (tx.packets?.length) {
    try {
      const envelope = await api("/transactions/" + selected + "/closure");
      body = envelope.packet.payload.body;
      verdict = body.verdict;
    } catch (err) {
      if (
        !err.message.startsWith("CLOSURE_NOT_AVAILABLE") &&
        !err.message.startsWith("ROUTE_NOT_FOUND")
      )
        $("notice").textContent = err.message;
    }
  }
  $("verdict").textContent = verdict || "Awaiting evidence";
  $("verdict").className = "verdict" + (verdict === "DISPROVEN" ? " fail" : "");
  $("verdict-note").textContent =
    descriptions[verdict] ||
    descriptions[tx.state] ||
    "The authority will evaluate admitted evidence against this frozen contract.";
  if (body) {
    if (body.reason_codes.length)
      $("verdict-note").textContent += "\n" + body.reason_codes.join(" · ");
    for (const [check, status] of Object.entries(body.checks || {})) {
      const row = node(
        "div",
        undefined,
        "check" + (status === "FAIL" ? " fail" : ""),
      );
      row.append(
        node("span", check),
        node(
          "span",
          typeof status === "string" ? status : JSON.stringify(status),
        ),
      );
      $("checks").append(row);
    }
  }
  const routes = {
    PROPOSED: [["Approve contract", "approve", "owner"]],
    DRAFT: [["Approve contract", "approve", "owner"]],
    APPROVED: [["Freeze contract", "freeze", "authority"]],
    FROZEN: [["Record baseline", "baseline", "verifier"]],
    BASELINED: [["Bind run", "bind", "authority"]],
    EXECUTING: [
      ["Deploy artifact", "deploy", "broker"],
      ["Observe deployed state", "observe", "verifier"],
      ["Evaluate closure", "close", "authority"],
    ],
    VERIFYING: [
      ["Observe deployed state", "observe", "verifier"],
      ["Evaluate closure", "close", "authority"],
    ],
    OBSERVING: [
      ["Collect window evidence", "observe", "verifier"],
      ["Evaluate closure", "close", "authority"],
    ],
    PROVEN: [["Accept outcome", "accept", "owner"]],
    DISPROVEN: [["Prepare recovery", "recover", "actor"]],
    INDETERMINATE: [["Prepare recovery", "recover", "actor"]],
    PARTIALLY_PROVEN: [["Prepare recovery", "recover", "actor"]],
    RECOVERY_REQUIRED: [
      ["Verify recovery result", "recover-complete", "authority"],
    ],
  };
  $("actions").replaceChildren();
  for (const [label, path, role] of routes[tx.state] || []) {
    if (!identity.roles.some((r) => r === role || r === "operator")) continue;
    const b = node("button", label, "secondary");
    b.disabled = busy;
    b.onclick = () =>
      act(
        path,
        tx.state === "OBSERVING" && path === "observe"
          ? { phase: "window" }
          : {},
      );
    $("actions").append(b);
  }
  $("bundle").disabled = !tx.window_start;
  $("closure").disabled = !body;
}
async function act(action, body) {
  if (busy) return;
  busy = true;
  $("notice").textContent =
    "Running " +
    action.replaceAll("-", " ") +
    " against the enrolled target. Waiting for the recorded result…";
  for (const b of $("actions").querySelectorAll("button")) b.disabled = true;
  try {
    const result = await api("/transactions/" + selected + "/" + action, body);
    $("notice").textContent =
      "Recorded " +
      (result.state || action) +
      (result.verdict ? " · " + result.verdict : "") +
      ".";
    await refresh();
  } catch (e) {
    $("notice").textContent = e.message;
    await refresh();
  } finally {
    busy = false;
    await renderTransaction();
  }
}
async function download(path, name) {
  try {
    const data = await api(path);
    const a = document.createElement("a");
    a.href = URL.createObjectURL(
      new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }),
    );
    a.download = name;
    a.click();
    URL.revokeObjectURL(a.href);
  } catch (e) {
    $("notice").textContent = e.message;
  }
}
$("bundle").onclick = () =>
  download(
    "/transactions/" + selected + "/bundle",
    selected.replaceAll("/", "-") + "-replay.json",
  );
$("closure").onclick = () =>
  download(
    "/transactions/" + selected + "/closure",
    selected.replaceAll("/", "-") + "-closure.json",
  );
$("propose").onclick = () => {
  $("proposal-error").textContent = "";
  $("proposal").showModal();
};
$("close-proposal").onclick = () => $("proposal").close();
$("proposal-form").onsubmit = async (e) => {
  e.preventDefault();
  const button = e.target.querySelector('button[type="submit"]');
  button.disabled = true;
  try {
    const v = Object.fromEntries(new FormData(e.target));
    const file = $("artifact").files[0];
    if (!file || file.size > 1048576)
      throw new Error("Choose an actual artifact no larger than 1 MiB.");
    const bytes = new Uint8Array(await file.arrayBuffer());
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    const result = await api("/transactions", {
      target_id: v.target_id,
      transaction_id: v.transaction_id,
      intent: v.intent,
      artifact_base64: btoa(binary),
      duration_ms: Number(v.duration) * 1000,
      min_samples: 3,
    });
    selected = result.transaction_id;
    $("proposal").close();
    await refresh();
  } catch (err) {
    $("proposal-error").textContent = err.message;
  } finally {
    button.disabled = false;
  }
};
