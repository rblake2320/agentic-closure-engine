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
    $("approval-mode").textContent =
      identity.approval_mode === "single-operator-administration"
        ? "Single-operator administration; human approval is not independent."
        : identity.approval_mode === "role-scoped"
          ? "Roles restricted. This session is limited to the roles shown."
          : "Approval mode unavailable. Review the operator's role delegation.";
    $("propose").hidden = !identity.roles.includes("actor");
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
    const items =
      summary.items ||
      Object.entries(summary.transactions || {}).map(
        ([transaction_id, state]) => ({ transaction_id, state }),
      );
    for (const { transaction_id: tx, state } of items) {
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
    if (items.length && !selected) selected = items[0].transaction_id;
    const pos = $("ledger-position");
    pos.replaceChildren(
      node("strong", "GLOBAL LEDGER EVENTS " + summary.sequence),
      node("span", "GLOBAL LEDGER HEAD " + summary.verified_head),
    );
    $("empty").hidden = !!selected;
    $("transaction-detail").hidden = !selected;
    if (selected) await renderTransaction();
    if ($("notice").textContent.includes("CHECKPOINT_MISSING"))
      $("notice").textContent = "";
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
  let contractReviewed = false;
  $("criteria").replaceChildren();
  $("contract-intent").textContent = "Loading the acceptance contract…";
  $("contract-scope").textContent = "";
  $("contract-raw").textContent = "";
  try {
    const review = await api("/transactions/" + selected + "/contract");
    const contract = review.contract;
    $("contract-intent").textContent = contract.intent;
    $("contract-scope").textContent = JSON.stringify(
      {
        allowed_actions: contract.allowed_actions,
        allowed_changes: contract.allowed_changes,
        protected_resources: contract.protected_resources,
        window: contract.window,
      },
      null,
      2,
    );
    for (const check of contract.checks) {
      const row = node("div", undefined, "check");
      const criterion = review.evaluator.criteria[check.id];
      row.append(
        node(
          "span",
          check.id +
            " · " +
            check.kind +
            " · " +
            check.phase +
            (check.mandatory ? " · required" : "") +
            (check.allow_not_completed
              ? " · partial allowed if not deployed"
              : ""),
        ),
        node(
          "span",
          criterion
            ? "Required: " +
                JSON.stringify(criterion.equals) +
                " · recovery: " +
                JSON.stringify(criterion.restore_equals)
            : "Protected check",
        ),
      );
      $("criteria").append(row);
    }
    $("contract-raw").textContent = JSON.stringify(review, null, 2);
    contractReviewed = true;
  } catch (error) {
    $("contract-intent").textContent =
      "Contract review unavailable: " + error.message;
  }
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
  if (tx.deployment?.receipt === "NOT_DEPLOYED") {
    $("verdict-note").textContent += "\nDeployment did not occur" +
      (tx.deployment.reason_code ? " · " + tx.deployment.reason_code : "") +
      (tx.deployment.target_http_status ? " · target HTTP " + tx.deployment.target_http_status : "");
  }
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
    BASELINED: [["Execute and verify", "run", "operator"]],
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
      ["Prepare recovery", "recover", "actor"],
      ["Verify recovery result", "recover-complete", "authority"],
    ],
  };
  $("actions").replaceChildren();
  for (const [label, path, role] of routes[tx.state] || []) {
    if (!identity.roles.includes(role) || !tx.allowed_actions?.includes(path)) continue;
    const b = node("button", label, "secondary");
    b.disabled = busy || (path === "approve" && !contractReviewed);
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
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(v.transaction_id) || v.transaction_id.includes(".."))
      throw new Error("Use a transaction ID of at most 128 ASCII letters/digits, dot, underscore or hyphen; no '..' or slash.");
    const file = $("artifact").files[0];
    if (file && v.artifact_text)
      throw new Error("Choose one artifact source: a file or its exact text.");
    const bytes = file
      ? new Uint8Array(await file.arrayBuffer())
      : new TextEncoder().encode(v.artifact_text || "");
    if (!bytes.length || bytes.length > 524288)
      throw new Error("Choose an actual artifact no larger than 512 KiB.");
    const expect = JSON.parse(v.expect_json);
    if (
      !expect ||
      typeof expect !== "object" ||
      Array.isArray(expect) ||
      !Object.keys(expect).length
    )
      throw new Error(
        "Required outcomes must map primary check identifiers to their desired values.",
      );
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    const result = await api("/transactions", {
      target_id: v.target_id,
      transaction_id: v.transaction_id,
      intent: v.intent,
      expect,
      allow_partial: v.allow_partial === "on",
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
