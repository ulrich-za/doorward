// The browser side of doorward's JSON endpoints, with no libraries.
"use strict";

const $ = (id) => document.getElementById(id);

function say(text, error = false) {
  const s = $("status");
  s.textContent = text;
  s.className = error ? "error" : "";
}

// Each app writes its own wording for doorward's error codes.
const MESSAGES = {
  invalid_credentials: "Wrong username or password.",
  passkey_not_recognised: "That passkey isn't one this site knows.",
  too_many_attempts: "Too many attempts. Wait a little and try again.",
  needs_recent_sign_in: "Confirm it's you first.",
  ceremony_expired: "That took too long. Try again.",
  busy: "The server is busy. Try again in a moment.",
};

async function api(method, path, body) {
  const resp = await fetch(path, {
    method,
    headers: body === undefined ? {} : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "same-origin",
  });
  const data = resp.status === 204 ? null : await resp.json().catch(() => null);
  if (!resp.ok) {
    const code = data && data.error ? data.error : "internal";
    const err = new Error(MESSAGES[code] || code);
    err.code = code;
    throw err;
  }
  return data;
}

// base64url <-> bytes, for the WebAuthn options and answers.
function fromB64(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0)).buffer;
}
function toB64(buf) {
  let s = "";
  for (const b of new Uint8Array(buf)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function creationOptions(o) {
  const pk = structuredClone(o.publicKey);
  pk.challenge = fromB64(pk.challenge);
  pk.user.id = fromB64(pk.user.id);
  pk.excludeCredentials = (pk.excludeCredentials || []).map((c) => ({ ...c, id: fromB64(c.id) }));
  return { publicKey: pk };
}
function requestOptions(o, modal) {
  const pk = structuredClone(o.publicKey);
  pk.challenge = fromB64(pk.challenge);
  pk.allowCredentials = (pk.allowCredentials || []).map((c) => ({ ...c, id: fromB64(c.id) }));
  // doorward asks for browser autofill ("conditional"); a button wants the
  // ordinary dialog, so leave mediation out.
  return modal ? { publicKey: pk } : { publicKey: pk, mediation: o.mediation };
}
function registrationJSON(c) {
  return {
    id: c.id, rawId: toB64(c.rawId), type: c.type,
    response: { attestationObject: toB64(c.response.attestationObject), clientDataJSON: toB64(c.response.clientDataJSON) },
    extensions: c.getClientExtensionResults(),
  };
}
function assertionJSON(c) {
  return {
    id: c.id, rawId: toB64(c.rawId), type: c.type,
    response: {
      authenticatorData: toB64(c.response.authenticatorData),
      clientDataJSON: toB64(c.response.clientDataJSON),
      signature: toB64(c.response.signature),
      userHandle: c.response.userHandle ? toB64(c.response.userHandle) : null,
    },
    extensions: c.getClientExtensionResults(),
  };
}

async function refresh() {
  const s = await api("GET", "/auth/session");
  $("signed-out").hidden = s.signed_in;
  $("signed-in").hidden = !s.signed_in;
  $("passkey-sign-in").hidden = !s.address.passkeys || !window.PublicKeyCredential;
  if (!s.signed_in) return;
  $("who").textContent = s.user.display_name;
  $("method").textContent = `(with a ${s.method})`;
  const list = (id, items, fmt) => {
    const ul = $(id);
    ul.replaceChildren(...items.map((x) => { const li = document.createElement("li"); li.textContent = fmt(x); return li; }));
  };
  list("passkeys", await api("GET", "/auth/passkeys"), (p) => `${p.label} (${p.rp_id})`);
  list("sessions", await api("GET", "/auth/sessions"), (x) => `${x.method} from ${x.ip}${x.current ? " (this one)" : ""}`);
  list("events", await api("GET", "/auth/events"), (e) => `${new Date(e.at_ms).toLocaleTimeString()} ${e.kind}`);
}

async function confirmIfNeeded(action) {
  try {
    return await action();
  } catch (e) {
    if (e.code !== "needs_recent_sign_in") throw e;
    const pw = prompt("Confirm it's you: your password");
    if (pw === null) throw e;
    await api("POST", "/auth/confirm", { password: pw });
    return action();
  }
}

$("password-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  try {
    await api("POST", "/auth/sign-in", { username: $("username").value, password: $("password").value, remember: $("remember").checked });
    $("password").value = "";
    say("Signed in.");
    await refresh();
  } catch (e) { say(e.message, true); }
});

$("passkey-sign-in").addEventListener("click", async () => {
  try {
    const start = await api("POST", "/auth/passkey/sign-in/start");
    const cred = await navigator.credentials.get(requestOptions(start.options, true));
    await api("POST", "/auth/passkey/sign-in/finish", { ceremony: start.ceremony, credential: assertionJSON(cred), remember: $("remember").checked });
    say("Signed in with a passkey.");
    await refresh();
  } catch (e) { say(e.message, true); }
});

$("add-passkey").addEventListener("click", async () => {
  try {
    await confirmIfNeeded(async () => {
      const start = await api("POST", "/auth/passkeys/register/start", { label: "This browser" });
      const cred = await navigator.credentials.create(creationOptions(start.options));
      await api("POST", "/auth/passkeys/register/finish", { ceremony: start.ceremony, credential: registrationJSON(cred) });
    });
    say("Passkey added.");
    await refresh();
  } catch (e) { say(e.message, true); }
});

$("check-sensitive").addEventListener("click", async () => {
  try {
    const r = await fetch("/api/sensitive", { credentials: "same-origin" });
    say(r.ok ? await r.text() : "Not recent enough: confirm it's you first.", !r.ok);
  } catch (e) { say(e.message, true); }
});

$("sign-out").addEventListener("click", async () => {
  try {
    await api("POST", "/auth/sign-out");
    say("Signed out.");
    await refresh();
  } catch (e) { say(e.message, true); }
});

refresh().catch((e) => say(e.message, true));
