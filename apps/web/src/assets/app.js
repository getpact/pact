const $ = (id) => document.getElementById(id);
let csrfToken = "";
let refreshing = false;
let appConfig = { mode: "production", oauthConfigured: false, defaultWorkspaceId: null };
let driveFiles = [];
let driveRetrievalReady = false;

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const setError = (message = "") => {
  $("error").textContent = message;
};

const messageForError = (path, status, body) => {
  const code = body?.error;
  if (path.includes("/v1/auth/google/start")) {
    if (status === 400 || code === "invalid_workspace") return "Enter a valid workspace UUID.";
    if (status === 403 || code === "origin") return "This page was opened from an unexpected local address. Reload the dashboard and try again.";
    if (status === 503 || code === "misconfigured") return "Dashboard login is not configured for this environment.";
  }
  if (path.includes("/v1/connections/google-drive/start")) {
    if (status === 403 || code === "csrf") return "Refresh the page before connecting Drive.";
    if (status === 401) return "Sign in again before connecting Drive.";
    if (status === 503 || code === "misconfigured") return "Drive connection is not configured for this environment.";
  }
  if (path.includes("/v1/drive/")) {
    if (status === 403 || code === "csrf") return "Refresh the page before using Drive retrieval.";
    if (status === 401) return "Sign in again before using Drive retrieval.";
    if (status === 503 || code === "misconfigured") return "MCP is not configured for Drive retrieval.";
    if (body?.message) return body.message;
  }
  if (status === 401) return "Your session expired. Sign in again.";
  if (status >= 500) return "A Pact service is unavailable. Try again in a moment.";
  return body?.message || code || path + " returned " + status;
};

const requestJson = async (path, init = {}) => {
  const devHeaders = appConfig.mode !== "production" ? { "x-pact-local-dev": "1" } : {};
  const res = await fetch(path, {
    ...init,
    headers: {
      accept: "application/json",
      ...devHeaders,
      ...(init.headers ?? {}),
    },
  });
  if (!res.ok) {
    let body = null;
    try {
      body = await res.json();
    } catch {}
    throw new Error(messageForError(path, res.status, body));
  }
  return res.json();
};

const showView = (name) => {
  for (const id of ["loading", "login", "dashboard"]) {
    $(id).classList.toggle("hidden", id !== name);
  }
  $("logout").classList.toggle("hidden", name !== "dashboard");
};

const refreshSession = async () => {
  if (refreshing || !csrfToken) return false;
  refreshing = true;
  try {
    const res = await fetch("/v1/session/refresh", {
      method: "POST",
      headers: { "x-pact-csrf": csrfToken },
    });
    return res.ok;
  } finally {
    refreshing = false;
  }
};

const loadConfig = async () => {
  try {
    appConfig = await requestJson("/v1/config");
  } catch {}
  const workspaceInput = $("workspace-id");
  const workspaceField = $("workspace-field");
  const workspaceSummary = $("workspace-summary");
  const defaultWorkspaceId = appConfig.defaultWorkspaceId;
  if (defaultWorkspaceId && uuidPattern.test(defaultWorkspaceId)) {
    workspaceInput.value = defaultWorkspaceId;
    workspaceField.classList.add("hidden");
    workspaceSummary.classList.remove("hidden");
    workspaceSummary.textContent = "Demo workspace selected. Continue with Google to sign in.";
  } else {
    const lastWorkspaceId = window.localStorage.getItem("pact:lastWorkspaceId") || "";
    if (!workspaceInput.value && uuidPattern.test(lastWorkspaceId)) {
      workspaceInput.value = lastWorkspaceId;
    }
    workspaceField.classList.remove("hidden");
    workspaceSummary.classList.add("hidden");
  }
  const oauthHelp = $("oauth-help");
  if (!appConfig.oauthConfigured) {
    oauthHelp.classList.remove("hidden");
    oauthHelp.textContent =
      "Google OAuth credentials are not configured for this dashboard environment.";
  } else {
    oauthHelp.classList.add("hidden");
  }
};

const renderSession = (session) => {
  $("metric-workspace").textContent = session.workspaceId ?? "-";
  const details = $("session-details");
  const claims = session.claims ?? {};
  details.innerHTML = "";
  for (const [label, value] of [
    ["Workspace", session.workspaceId],
    ["Email", claims.email],
    ["Roles", Array.isArray(claims.roles) ? claims.roles.join(", ") : ""],
  ]) {
    const dt = document.createElement("dt");
    dt.textContent = label;
    const dd = document.createElement("dd");
    dd.textContent = value || "Unknown";
    details.append(dt, dd);
  }
};

const selectedDriveFile = () => {
  const fileId = $("drive-files").value;
  return driveFiles.find((file) => file.id === fileId) || null;
};

const renderDriveFileOptions = (files) => {
  driveFiles = files;
  const select = $("drive-files");
  select.innerHTML = "";
  if (!files.length) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = driveRetrievalReady ? "No files returned" : "Connect Drive and load files";
    select.append(option);
  } else {
    for (const file of files) {
      const option = document.createElement("option");
      option.value = file.id;
      option.textContent = file.name || file.id;
      select.append(option);
    }
  }
  select.disabled = !driveRetrievalReady || !files.length;
  $("drive-index").disabled = !driveRetrievalReady || !files.length;
};

const renderDriveRetrievalState = (driveStatus, mcp) => {
  driveRetrievalReady = driveStatus === "connected" && !!mcp?.configured && !!mcp?.endpoint;
  $("drive-files-refresh").disabled = !driveRetrievalReady;
  $("drive-search-submit").disabled = !driveRetrievalReady;
  $("drive-search-query").disabled = !driveRetrievalReady;
  if (!driveRetrievalReady) {
    renderDriveFileOptions([]);
    $("drive-index-result").textContent =
      driveStatus === "connected"
        ? "MCP must be configured before indexing Drive files."
        : "Connect Drive before indexing files.";
    $("drive-search-results").textContent = "";
    return;
  }
  if (!driveFiles.length) renderDriveFileOptions([]);
};

const renderSearchResults = (results) => {
  const container = $("drive-search-results");
  container.innerHTML = "";
  if (!results.length) {
    const empty = document.createElement("p");
    empty.className = "help";
    empty.textContent = "No indexed chunks matched this query.";
    container.append(empty);
    return;
  }
  for (const result of results) {
    const item = document.createElement("article");
    item.className = "result-item";
    const title = document.createElement("p");
    title.className = "result-title";
    title.textContent = result.fileName || result.fileId || "Drive file";
    const snippet = document.createElement("p");
    snippet.className = "result-snippet";
    snippet.textContent = result.snippet || "";
    const meta = document.createElement("p");
    meta.className = "result-meta";
    meta.textContent =
      "chunk " +
      (result.chunkIndex ?? "-") +
      (result.indexedAt ? " / indexed " + result.indexedAt : "");
    item.append(title, snippet, meta);
    container.append(item);
  }
};

const renderStatus = (status) => {
  const drive = status.connections?.drive;
  $("metric-users").textContent = String(status.users?.count ?? 0);
  const driveStatus = drive?.status || "unknown";
  $("metric-drive").textContent = driveStatus === "not_configured" ? "not set" : driveStatus;
  $("metric-audit").textContent = status.audit?.head ? "active" : "no head";
  $("drive-status").textContent =
    driveStatus === "not_configured"
      ? "Drive is not connected yet."
      : driveStatus === "connected"
        ? "Drive connected for " + (drive.email || "this user") + "."
        : "Drive connection status: " + driveStatus;
  $("drive-connect").textContent = driveStatus === "connected" ? "Reconnect Drive" : "Connect Drive";
  $("drive-connect").disabled = false;
  const canDisconnect = !["not_configured", "unknown", "disconnected"].includes(driveStatus);
  $("drive-disconnect").classList.toggle("hidden", !canDisconnect);
  $("drive-disconnect").disabled = !canDisconnect;
  renderMcpStatus(status.mcp, driveStatus);
  renderDriveRetrievalState(driveStatus, status.mcp);
  $("audit-status").textContent = status.audit?.head
    ? "Audit log is receiving signed events."
    : "No audit log checkpoint found yet.";
};

const renderMcpStatus = (mcp, driveStatus) => {
  const config = $("mcp-config");
  const test = $("mcp-test");
  $("mcp-test-result").textContent = "";
  if (!mcp?.configured || !mcp.endpoint) {
    $("mcp-status").textContent = "MCP server URL is not configured for this dashboard.";
    config.classList.add("hidden");
    test.disabled = true;
    return;
  }
  $("mcp-status").textContent =
    driveStatus === "connected"
      ? "MCP is ready for this workspace. Test the signed session before using Drive tools."
      : "MCP is configured. Connect Drive before using Drive tools.";
  config.textContent =
    "endpoint: " + mcp.endpoint + "\\n" + "audience: " + (mcp.audience || "pact-mcp");
  config.classList.remove("hidden");
  test.disabled = false;
};

const renderStatusUnavailable = (message) => {
  $("metric-users").textContent = "-";
  $("metric-drive").textContent = "unavailable";
  $("metric-audit").textContent = "unavailable";
  $("drive-status").textContent = "Connection status is unavailable.";
  $("drive-connect").disabled = false;
  $("drive-disconnect").classList.add("hidden");
  $("drive-disconnect").disabled = true;
  $("mcp-status").textContent = "Agent access status is unavailable.";
  $("mcp-config").classList.add("hidden");
  $("mcp-test").disabled = true;
  $("mcp-test-result").textContent = "";
  driveRetrievalReady = false;
  renderDriveFileOptions([]);
  $("drive-files-refresh").disabled = true;
  $("drive-search-submit").disabled = true;
  $("drive-search-query").disabled = true;
  $("drive-index-result").textContent = "Workspace status is unavailable.";
  $("drive-search-results").textContent = "";
  $("audit-status").textContent = message || "Audit log status is unavailable.";
};

const load = async () => {
  setError();
  await loadConfig();
  showView("loading");
  const session = await requestJson("/v1/session");
  if (!session.authenticated) {
    showView("login");
    return;
  }
  showView("dashboard");
  csrfToken = session.csrfToken ?? "";
  renderSession(session);
  try {
    renderStatus(await requestJson("/v1/workspace/status"));
  } catch (error) {
    if (await refreshSession()) {
      renderStatus(await requestJson("/v1/workspace/status"));
      return;
    }
    const message = error instanceof Error ? error.message : "Workspace status failed";
    renderStatusUnavailable(message);
    setError(message);
  }
};

$("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  setError();
  const form = event.currentTarget;
  const workspaceId = String(new FormData(form).get("workspaceId") ?? "").trim();
  if (!uuidPattern.test(workspaceId)) {
    setError("Enter a valid workspace UUID.");
    $("workspace-id").focus();
    return;
  }
  window.localStorage.setItem("pact:lastWorkspaceId", workspaceId);
  const input = $("workspace-id");
  const button = $("login-submit");
  input.disabled = true;
  button.disabled = true;
  button.textContent = "Redirecting to Google...";
  try {
    const body = await requestJson("/v1/auth/google/start", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ workspaceId }),
    });
    window.location.href = body.location;
  } catch (error) {
    input.disabled = false;
    button.disabled = false;
    button.textContent = "Continue with Google";
    setError(error instanceof Error ? error.message : "Login failed");
  }
});

$("logout").addEventListener("click", async () => {
  await fetch("/v1/session", { method: "DELETE", headers: { "x-pact-csrf": csrfToken } });
  await load();
});

$("drive-connect").addEventListener("click", async () => {
  setError();
  const button = $("drive-connect");
  button.disabled = true;
  const previous = button.textContent;
  button.textContent = "Redirecting to Google...";
  try {
    const body = await requestJson("/v1/connections/google-drive/start", {
      method: "POST",
      headers: { "x-pact-csrf": csrfToken },
    });
    window.location.href = body.location;
  } catch (error) {
    button.disabled = false;
    button.textContent = previous || "Connect Drive";
    setError(error instanceof Error ? error.message : "Drive connection failed");
  }
});

$("drive-disconnect").addEventListener("click", async () => {
  setError();
  const button = $("drive-disconnect");
  button.disabled = true;
  try {
    await requestJson("/v1/connections/google-drive", {
      method: "DELETE",
      headers: { "x-pact-csrf": csrfToken },
    });
    await load();
  } catch (error) {
    button.disabled = false;
    setError(error instanceof Error ? error.message : "Drive disconnect failed");
  }
});

$("drive-files-refresh").addEventListener("click", async () => {
  setError();
  const button = $("drive-files-refresh");
  const result = $("drive-index-result");
  button.disabled = true;
  result.textContent = "Loading Drive files...";
  try {
    const body = await requestJson("/v1/drive/files", {
      method: "POST",
      headers: { "content-type": "application/json", "x-pact-csrf": csrfToken },
      body: JSON.stringify({ pageSize: 10 }),
    });
    renderDriveFileOptions(body.files || []);
    result.textContent = body.files?.length
      ? "Select a file and index it for MCP search."
      : "No Drive files were returned for this account.";
  } catch (error) {
    result.textContent = "";
    setError(error instanceof Error ? error.message : "Drive file list failed");
  } finally {
    button.disabled = !driveRetrievalReady;
  }
});

$("drive-index").addEventListener("click", async () => {
  setError();
  const file = selectedDriveFile();
  if (!file) {
    setError("Choose a Drive file to index.");
    return;
  }
  const button = $("drive-index");
  const result = $("drive-index-result");
  button.disabled = true;
  result.textContent = "Indexing " + (file.name || file.id) + "...";
  try {
    const body = await requestJson("/v1/drive/index", {
      method: "POST",
      headers: { "content-type": "application/json", "x-pact-csrf": csrfToken },
      body: JSON.stringify({
        fileId: file.id,
        fileName: file.name,
        modifiedTime: file.modifiedTime,
      }),
    });
    result.textContent =
      "Indexed " +
      (body.fileName || file.name || body.fileId) +
      " into " +
      body.chunks +
      " chunks" +
      (body.truncated ? " (truncated)." : ".");
  } catch (error) {
    result.textContent = "";
    setError(error instanceof Error ? error.message : "Drive indexing failed");
  } finally {
    button.disabled = !driveRetrievalReady || !driveFiles.length;
  }
});

$("drive-search-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  setError();
  const query = String(new FormData(event.currentTarget).get("query") || "").trim();
  if (!query) {
    setError("Enter a Drive search query.");
    $("drive-search-query").focus();
    return;
  }
  const button = $("drive-search-submit");
  button.disabled = true;
  $("drive-search-results").textContent = "Searching indexed Drive context...";
  try {
    const body = await requestJson("/v1/drive/search", {
      method: "POST",
      headers: { "content-type": "application/json", "x-pact-csrf": csrfToken },
      body: JSON.stringify({ query, limit: 5 }),
    });
    renderSearchResults(body.results || []);
  } catch (error) {
    $("drive-search-results").textContent = "";
    setError(error instanceof Error ? error.message : "Drive search failed");
  } finally {
    button.disabled = !driveRetrievalReady;
  }
});

$("mcp-test").addEventListener("click", async () => {
  setError();
  const button = $("mcp-test");
  const result = $("mcp-test-result");
  button.disabled = true;
  result.textContent = "Testing MCP...";
  try {
    const body = await requestJson("/v1/mcp/test", {
      method: "POST",
      headers: { "x-pact-csrf": csrfToken },
    });
    if (body.response?.error) {
      result.textContent =
        "MCP denied the test call: " +
        (body.response.error.message || body.response.error.code || "unknown error");
    } else {
      result.textContent = "MCP test passed with pact.whoami.";
    }
  } catch (error) {
    result.textContent = "";
    setError(error instanceof Error ? error.message : "MCP test failed");
  } finally {
    button.disabled = false;
  }
});

load().catch((error) => {
  showView("login");
  setError(error instanceof Error ? error.message : "Dashboard failed");
});
