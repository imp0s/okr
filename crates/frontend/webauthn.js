// WebAuthn browser interop (spec §6.1, §3.3 web-sys/wasm-bindgen interop).
// Loaded as an external ES module so it complies with the strict CSP
// (`script-src 'self'`, no inline scripts). Handles the ArrayBuffer<->base64url
// conversions the native API requires; all verification happens server-side.

function b64urlToBuf(s) {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const b64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}

function bufToB64url(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Registration ceremony: returns the fields the server's verify endpoint needs.
export async function register(publicKey) {
  publicKey.challenge = b64urlToBuf(publicKey.challenge);
  publicKey.user.id = b64urlToBuf(publicKey.user.id);
  if (publicKey.excludeCredentials) {
    publicKey.excludeCredentials = publicKey.excludeCredentials.map((c) => ({
      ...c,
      id: b64urlToBuf(c.id),
    }));
  }
  const cred = await navigator.credentials.create({ publicKey });
  return {
    id: cred.id,
    clientDataJSON: bufToB64url(cred.response.clientDataJSON),
    attestationObject: bufToB64url(cred.response.attestationObject),
  };
}

// Assertion ceremony (discoverable / usernameless login).
export async function login(publicKey) {
  publicKey.challenge = b64urlToBuf(publicKey.challenge);
  if (publicKey.allowCredentials) {
    publicKey.allowCredentials = publicKey.allowCredentials.map((c) => ({
      ...c,
      id: b64urlToBuf(c.id),
    }));
  }
  const cred = await navigator.credentials.get({ publicKey });
  return {
    id: cred.id,
    clientDataJSON: bufToB64url(cred.response.clientDataJSON),
    authenticatorData: bufToB64url(cred.response.authenticatorData),
    signature: bufToB64url(cred.response.signature),
    userHandle: cred.response.userHandle ? bufToB64url(cred.response.userHandle) : null,
  };
}

export function supported() {
  return !!(window.PublicKeyCredential && navigator.credentials);
}
